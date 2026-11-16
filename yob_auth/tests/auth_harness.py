# Copyright (c) 2026, YOB and Shayona
"""Request/session scaffolding shared by the endpoint-level auth tests.

WHY THIS EXISTS
---------------
The auth endpoints are exercised AS ENDPOINTS. `login_with_password` calls
`frappe.local.login_manager.authenticate()` and then `post_login()`, and
`post_login()` needs a cookie manager, a request, a client IP and a form dict --
every one of which `frappe.app` installs per request and a unit test does not
have. Testing `LoginManager` in isolation would prove nothing about YOB's
endpoint: the whole point is the stack `whitelist -> yob_api ->
envelope_yob_errors -> get_application -> validate_login_method -> rate limit ->
authenticate -> resolve_access -> post_login -> audit`.

So this installs the same request-local state a real guest POST arrives with,
and restores every value afterwards -- otherwise a successful login would leave
the whole test process logged in as a throwaway Website User with a replaced
`frappe.local.session`, and every module after it would run as that user.

TRANSACTION NOTES, which drive the fixture style in these modules
-----------------------------------------------------------------
Two framework behaviours make in-transaction fixtures unusable here:

* `frappe.sessions.Session.start()` **commits** for any non-Guest user, so a
  SUCCESSFUL login commits the transaction mid-test;
* `LoginManager.fail()` also commits (it writes an Activity Log row), and
  `envelope_yob_errors` **rolls back** before answering a refusal.

A fixture created in `setUp` would therefore be either committed or destroyed by
the endpoint under test, depending on the branch taken. The fixtures are
consequently created once per class with an explicit commit and deleted in
`tearDownClass`, which is the convention `test_domain_enforcement` already uses.
"""

import hashlib
import time

import frappe

#: Every request-local the login path reads or replaces.
_LOCAL_KEYS = (
    "request", "request_ip", "form_dict", "cookie_manager", "login_manager",
    "session", "session_obj", "response",
)


def snapshot_locals() -> dict:
    """Capture the request-locals the endpoints are about to overwrite."""

    snap = {key: getattr(frappe.local, key, None) for key in _LOCAL_KEYS}
    # The response is mutated in place by `set_status`, so the object reference
    # alone would not restore anything.
    response = snap.get("response")
    snap["response"] = frappe._dict(response) if response is not None else None
    return snap


def restore_locals(snap: dict) -> None:
    """Put every captured request-local back and return to Administrator."""

    for key, value in snap.items():
        setattr(frappe.local, key, value)
    frappe.set_user("Administrator")


#: Any YOB endpoint path. It must NOT be `/api/method/login`: `LoginManager`
#: checks for exactly that path (and for `cmd=login`) and would perform a
#: FRAMEWORK login from `form_dict` instead of resuming as Guest.
_ENDPOINT_PATH = "/api/method/yob_auth.api.auth.login_with_password"


def install_guest_request(headers: dict | None = None, *, path=_ENDPOINT_PATH,
                          method="POST", client_ip="127.0.0.1") -> None:
    """Install the request-locals a guest POST to a YOB auth endpoint carries.

    `form_dict` deliberately carries `sid: "Guest"` and NO `cmd`, so
    `LoginManager.__init__` takes its resume branch and resolves to Guest
    instead of performing a login of its own. The endpoint under test is what
    authenticates.
    """

    from frappe.auth import CookieManager, LoginManager
    from werkzeug.test import EnvironBuilder
    from werkzeug.wrappers import Request

    frappe.local.request = Request(
        EnvironBuilder(path=path, method=method, headers=headers or {}).get_environ())
    frappe.local.request_ip = client_ip
    frappe.local.form_dict = frappe._dict({"sid": "Guest"})
    frappe.local.response = frappe._dict({"docs": []})
    frappe.local.cookie_manager = CookieManager()
    frappe.local.login_manager = LoginManager()


def status() -> int | None:
    """The HTTP status the endpoint assigned to the current response."""

    return (getattr(frappe.local, "response", None) or {}).get("http_status_code")


def session_user() -> str:
    return frappe.session.user


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _forget_counter(key: str) -> None:
    """Delete a counter written by `rate_limit._increment_window`.

    `make_keys=False` is REQUIRED and is the whole reason this helper exists.
    `frappe.cache.incrby` is inherited straight from `redis.Redis` and is the
    one cache call Frappe does NOT route through `RedisWrapper.make_key`, so the
    limiter's windows live at the RAW key while `delete_value(key)` would delete
    the site-prefixed `<db_name>|<key>` that nothing ever wrote. Verified
    directly against this bench's Redis.

    Those raw keys carry the site themselves -- see `rate_limit._site_segment`,
    and `test_rate_limit_isolation` for the regression that pins it.
    """

    frappe.cache.delete_value(key, make_keys=False)


def clear_password_limits(*usernames: str) -> None:
    """Drop every password attempt counter that could refuse these identities.

    The limiter is real and stays armed -- one test proves it refuses at the
    endpoint. What this removes is cross-TEST pollution: a module that makes a
    dozen deliberate failed logins in one 300-second window would otherwise
    start answering `rate_limit_exceeded` to its own later tests, and to the
    next run of itself.

    All THREE key families have to go: the per-identity window, and -- when the
    client IP is trusted on this site -- the per-IP and per-pair windows, whose
    limit is the same small number as the identity one. Both the current and the
    previous window are cleared, because a window can roll over mid-run.
    """

    from yob_auth.security.rate_limit import rate_limit_key
    from yob_auth.security.request import get_trusted_client_ip

    window = int(time.time() // 300)
    # Whatever the live request reports, plus the two values the limiter sees
    # when there is no request at all and when no trusted header is configured.
    ips = {get_trusted_client_ip() or "unknown", "unknown", "127.0.0.1"}

    for offset in (0, -1):
        slot = window + offset
        for username in usernames:
            user_key = _digest((username or "").strip().lower())
            _forget_counter(rate_limit_key("password", "user", user_key, slot))
            for ip in ips:
                ip_key = _digest(ip)
                _forget_counter(rate_limit_key("password", "ip", ip_key, slot))
                _forget_counter(
                    rate_limit_key("password", "pair", ip_key, user_key, slot))


def clear_otp_limits(method: str, identifier: str) -> None:
    """Drop the OTP cooldown and the hourly counters for one (method, identifier).

    The cooldown is written with `set_value`, so it is site-prefixed and deleted
    normally. The hourly windows come from `incrby` and need the raw key -- see
    `_forget_counter`.
    """

    from yob_auth.security.rate_limit import rate_limit_key

    key = _digest(f"{method}:{(identifier or '').strip().lower()}")
    frappe.cache.delete_value(rate_limit_key("otp", "cooldown", key))

    window = int(time.time() // 3600)
    for offset in (0, -1):
        _forget_counter(rate_limit_key("otp", "hour", "id", key, window + offset))


def forget_challenge(challenge_id: str) -> None:
    """Remove an OTP challenge from the cache, where challenges actually live.

    They are NOT database rows, so a transaction rollback does not reach them.
    """

    if challenge_id:
        frappe.cache.delete_value(f"yob_auth:otp:{challenge_id}")


def challenge(challenge_id: str) -> dict | None:
    """The stored challenge payload, read the way `verify_otp` reads it."""

    return frappe.cache.get_value(f"yob_auth:otp:{challenge_id}")


def purge_auth_traces(*users: str) -> None:
    """Delete the rows a login leaves behind for a throwaway test identity.

    A successful login commits, so its audit, Activity Log and Sessions rows
    outlive the test transaction and have to be removed explicitly.
    """

    for user in users:
        for doctype in ("YOB Auth Log", "Activity Log"):
            for name in frappe.get_all(doctype, filters={"user": user}, pluck="name"):
                frappe.delete_doc(doctype, name, force=True, ignore_permissions=True)
        frappe.db.sql("delete from tabSessions where user = %s", user)
