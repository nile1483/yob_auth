import hashlib
import time
from urllib.parse import quote

import frappe
from frappe.utils import cint

from yob_auth.security.exceptions import YOBRateLimitError
from yob_auth.security.request import get_trusted_client_ip, is_client_ip_trusted

#: Namespace every YOB auth rate-limit key begins with.
KEY_PREFIX = "yob_auth"

#: Used when no site is bound to this execution context at all. Such a context
#: cannot be attributed to a site, so it gets its own bucket rather than
#: borrowing one -- never a real site's.
UNKNOWN_SITE = "unknown-site"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _site_segment() -> str:
    """The current site as one unambiguous, collision-free key segment.

    WHY THIS EXISTS
    ---------------
    Every counter below is incremented with ``frappe.cache.incrby``, which is
    inherited straight from ``redis.Redis`` and is the one cache call Frappe
    does NOT route through ``RedisWrapper.make_key``. So these counters live at
    RAW Redis keys, outside the ``<db_name>|`` namespace every other cache value
    gets -- and two sites sharing one Redis instance were therefore sharing one
    password window and one OTP window. Activity on site A consumed site B's
    budget.

    That failed SAFE for authentication (a counter can only ever read high, so
    nobody gained attempts), but it is an availability problem: one site's
    traffic, or one attacker against it, could throttle logins on every other
    site on the bench.

    WHY NOT ``make_key``
    --------------------
    Routing the counters through Frappe's namespace would fix the isolation and
    introduce a worse problem: ``frappe.clear_cache()`` deletes EVERY key in the
    site namespace (``cache_manager.clear_cache`` -> ``get_keys("")``), so a
    ``bench clear-cache``, a migrate, or any code path that clears the cache
    would reset all rate limiting. The counters deliberately stay outside that
    namespace, and carry the site themselves.

    UNAMBIGUOUS BY CONSTRUCTION
    ---------------------------
    Percent-encoding rather than character replacement, because replacement is
    not injective: mapping ``:`` to ``-`` would make a site named ``a:b`` share
    a bucket with one named ``a-b``. ``quote`` is reversible, so two different
    sites can never produce the same segment, and it cannot emit the ``:``
    separator used between segments. Ordinary site names such as
    ``shop.example.com`` pass through unchanged and stay readable in Redis.
    """

    site = str(getattr(frappe.local, "site", None) or "").strip()
    if not site:
        # No site bound (a bare CLI or worker context). `db_name` is the same
        # per-site identity Frappe uses for its own cache namespace.
        site = str(frappe.conf.get("db_name") or "").strip()

    return quote(site, safe=".-_") or UNKNOWN_SITE


def rate_limit_key(*parts) -> str:
    """Build one site-scoped rate-limit key.

    The single place any YOB auth rate-limit key is composed, so password,
    email-OTP and mobile-OTP limiting all inherit site isolation from one
    change rather than three copies of it.

    Only the site segment is free text, and it is percent-encoded above. Every
    other segment is a SHA-256 digest or an integer window number, so the
    composition is unambiguous. No identifier, password or OTP is ever placed in
    a key in the clear -- callers pass digests, exactly as before.
    """

    return ":".join((KEY_PREFIX, _site_segment(), *(str(part) for part in parts)))


def _increment_window(key: str, ttl: int) -> int:
    count = frappe.cache.incrby(key, 1)
    frappe.cache.expire(key, ttl)
    return int(count or 0)


def enforce_otp_request_limits(identifier: str, method: str, settings) -> None:
    identifier_key = _digest(f"{method}:{(identifier or '').strip().lower()}")
    ip = get_trusted_client_ip() or "unknown"
    ip_key = _digest(ip)
    cooldown = cint(settings.otp_resend_seconds) or 60
    maximum = cint(settings.max_otp_requests_per_hour) or 8

    cooldown_key = rate_limit_key("otp", "cooldown", identifier_key)
    if frappe.cache.get_value(cooldown_key):
        raise YOBRateLimitError("Please wait before requesting another OTP")

    window = int(time.time() // 3600)
    checks = [(rate_limit_key("otp", "hour", "id", identifier_key, window), maximum)]
    # IP-keyed limits are only meaningful when the IP actually identifies the
    # caller. Behind an unconfigured proxy every request shares one address, so
    # these would throttle the whole platform on one caller's behaviour.
    if is_client_ip_trusted():
        checks.append((rate_limit_key("otp", "hour", "ip", ip_key, window), maximum * 5))
        checks.append((rate_limit_key("otp", "hour", "pair", ip_key, identifier_key, window), maximum))
    for key, limit in checks:
        if _increment_window(key, 3700) > limit:
            raise YOBRateLimitError("Too many OTP requests. Please try later")

    frappe.cache.set_value(cooldown_key, 1, expires_in_sec=cooldown)


def enforce_password_attempt_limits(username: str, settings) -> None:
    ip = get_trusted_client_ip() or "unknown"
    user_key = _digest((username or "").strip().lower())
    ip_key = _digest(ip)
    window_seconds = cint(getattr(settings, "password_rate_window_seconds", 0)) or 300
    per_identity = cint(getattr(settings, "max_password_attempts_per_window", 0)) or 10
    per_ip = cint(getattr(settings, "max_password_attempts_per_ip_window", 0)) or 50
    window = int(time.time() // window_seconds)

    # The per-user window always applies. The IP-keyed windows only apply when
    # the IP is trustworthy -- otherwise they are one shared bucket that lets a
    # single attacker lock every user out (see is_client_ip_trusted).
    checks = [(rate_limit_key("password", "user", user_key, window), per_identity)]
    if is_client_ip_trusted():
        checks.append((rate_limit_key("password", "ip", ip_key, window), per_ip))
        checks.append((rate_limit_key("password", "pair", ip_key, user_key, window), per_identity))
    for key, limit in checks:
        if _increment_window(key, window_seconds + 60) > limit:
            raise YOBRateLimitError("Too many login attempts. Please try later")
