# Copyright (c) 2026, YOB and Shayona
"""`yob_auth.api.auth.login_with_password`, exercised as the endpoint.

THE GAP THIS CLOSES
-------------------
Everything *after* authentication was well covered -- origin matching, domain
enforcement, `resolve_access`, the envelope, the storefront's whole buyer path.
The three login endpoints themselves had no automated test at all, which the
Phase 33 documentation audit recorded as the single largest coverage gap: a
regression in the one function every buyer calls first would have been caught
only by somebody logging in with a browser.

These tests call the real whitelisted function. Nothing is unwrapped, so the
full stack runs:

    frappe.whitelist(allow_guest=True, methods=["POST"])
      -> yob_api                    (unexpected faults -> generic 500)
        -> envelope_yob_errors      (YOB refusals -> errors[] + status)
          -> settings check -> get_application (domain/origin guard)
            -> validate_login_method -> password rate limit
              -> LoginManager.authenticate -> resolve_access
                -> LoginManager.post_login -> audit

`LoginManager` is deliberately NOT tested in isolation: Frappe owns it, and what
matters here is YOB's ordering around it -- in particular that NO session is
created when the credentials are right but the application access is not.

See `auth_harness` for the request scaffolding and for why the fixtures are
committed rather than transaction-scoped.
"""

import json
import unittest
from unittest.mock import patch

import frappe
from frappe.utils import add_days, now_datetime

from yob_auth.api import auth
from yob_auth.tests import auth_harness as harness

APP = "_TESTLOGIN"
APP_ALT = "_TESTLOGINALT"
APP_DOMAIN = "_TESTLOGINDOM"
APP_NO_PASSWORD = "_TESTLOGINOFF"
APP_DISABLED = "_TESTLOGINDEAD"

TRUSTED_HOST = "login.test"

PASSWORD = "Yob-Test-Login-9!x"

USER = "_test-login-ok@yob.invalid"
DISABLED_USER = "_test-login-disabled@yob.invalid"
NO_GRANT_USER = "_test-login-nogrant@yob.invalid"
EXPIRED_USER = "_test-login-expired@yob.invalid"
PENDING_USER = "_test-login-pending@yob.invalid"
OFF_GRANT_USER = "_test-login-offgrant@yob.invalid"

#: Never created. Used to prove an unknown username is indistinguishable from a
#: wrong password; Frappe's own login tracker writes an Activity Log row for it
#: with `ignore_links`, and `fail()` commits, so it is purged like the rest.
UNKNOWN_USER = "_test-login-nobody@yob.invalid"

ALL_USERS = (USER, DISABLED_USER, NO_GRANT_USER, EXPIRED_USER, PENDING_USER,
             OFF_GRANT_USER)
ALL_APPS = (APP, APP_ALT, APP_DOMAIN, APP_NO_PASSWORD, APP_DISABLED)

ACCESS = "YOB User Application Access"


def _application(code, **overrides):
    if frappe.db.exists("YOB Application", code):
        return
    values = {
        "doctype": "YOB Application",
        "application_code": code,
        "application_name": f"Login Test {code}",
        "enabled": 1,
        "domains": "",
        "allow_password_login": 1,
        "allow_email_otp": 0,
        "allow_mobile_otp": 0,
    }
    values.update(overrides)
    frappe.get_doc(values).insert(ignore_permissions=True)


def _user(email, *, password=PASSWORD, enabled=1):
    if frappe.db.exists("User", email):
        return
    doc = frappe.get_doc({
        "doctype": "User", "email": email, "first_name": "Login",
        "last_name": email.split("@")[0], "send_welcome_email": 0,
        "new_password": password,
    })
    doc.flags.ignore_permissions = True
    doc.insert(ignore_permissions=True)
    if not enabled:
        # Disabled AFTER the password is set: `User` will not accept a new
        # password for an account it already knows to be disabled.
        frappe.db.set_value("User", email, "enabled", 0)


def _grant(user, application, **overrides):
    if frappe.db.exists(ACCESS, {"user": user, "application": application}):
        return
    values = {"doctype": ACCESS, "user": user, "application": application,
              "enabled": 1}
    values.update(overrides)
    frappe.get_doc(values).insert(ignore_permissions=True)



#: WHY THE FIXTURE IS BUILT PER TEST AND NEVER COMMITTED
#: -----------------------------------------------------
#: The first version of these modules built the fixture once per class and
#: committed it, following `test_domain_enforcement`. Its sibling in
#: `yob_storefront` then failed in a full-app run: the commit was not durable
#: there, the first test's rollback took the fixture with it, and four later
#: tests went on passing for the WRONG REASON (a refusal that needs a missing
#: GRANT reads identically to one caused by a missing APPLICATION, and
#: `frappe.get_roles` of a user who does not exist answers Guest's roles).
#:
#: So the fixture is created idempotently in `setUp`, nothing depends on a
#: commit surviving, and `setUp` ASSERTS the fixture is present -- which is
#: what turns a vanished fixture into a loud failure instead of a silent lie.


def _ensure_fixtures():
    """Create whatever part of the fixture is missing. See the note above."""

    _application(APP)
    _application(APP_ALT)
    _application(APP_DOMAIN, domains=TRUSTED_HOST)
    _application(APP_NO_PASSWORD, allow_password_login=0)
    _application(APP_DISABLED, enabled=0)

    for email in ALL_USERS:
        _user(email, enabled=0 if email == DISABLED_USER else 1)

    _grant(USER, APP)
    _grant(USER, APP_DOMAIN)
    _grant(DISABLED_USER, APP)
    _grant(OFF_GRANT_USER, APP, enabled=0)
    _grant(EXPIRED_USER, APP,
           valid_from=add_days(now_datetime(), -10),
           valid_until=add_days(now_datetime(), -1))
    _grant(PENDING_USER, APP, valid_from=add_days(now_datetime(), 7))


def _destroy_fixtures():
    frappe.set_user("Administrator")
    harness.purge_auth_traces(*ALL_USERS, UNKNOWN_USER)
    for email in ALL_USERS:
        for name in frappe.get_all(ACCESS, filters={"user": email}, pluck="name"):
            frappe.delete_doc(ACCESS, name, force=True, ignore_permissions=True)
        if frappe.db.exists("User", email):
            frappe.delete_doc("User", email, force=True, ignore_permissions=True)
    for code in ALL_APPS:
        if frappe.db.exists("YOB Application", code):
            frappe.delete_doc("YOB Application", code, force=True,
                              ignore_permissions=True)


class PasswordLoginCase(unittest.TestCase):
    """One throwaway application, one real password, every documented outcome."""

    @classmethod
    def setUpClass(cls):
        frappe.set_user("Administrator")
        # A previous interrupted run can leave these behind, and a successful
        # login commits, so start from a known-clean state.
        _destroy_fixtures()

    @classmethod
    def tearDownClass(cls):
        _destroy_fixtures()
        frappe.db.commit()
        frappe.clear_cache()

    def setUp(self):
        frappe.set_user("Administrator")
        frappe.clear_cache()
        _ensure_fixtures()
        self.assertTrue(
            frappe.db.exists("User", USER),
            "the fixture user is missing, so this module's assertions would "
            "pass vacuously")
        self.assertTrue(frappe.db.exists("YOB Application", APP))
        self.assertTrue(frappe.db.exists(ACCESS, {"user": USER,
                                                  "application": APP}))

        self.locals = harness.snapshot_locals()
        self.addCleanup(harness.restore_locals, self.locals)
        self.addCleanup(frappe.clear_cache)
        self.addCleanup(frappe.db.rollback)
        harness.install_guest_request()
        # After the request exists, so the limiter's IP-keyed buckets are
        # cleared for the IP the endpoint will actually be called with.
        harness.clear_password_limits(*ALL_USERS, UNKNOWN_USER)
        self.assertEqual(frappe.session.user, "Guest",
                         "the harness did not start the request as Guest")

    # ------------------------------------------------------------------ helpers

    def login(self, application=APP, username=USER, password=PASSWORD):
        return auth.login_with_password(
            application=application, username=username, password=password)

    def assertRefused(self, response, code, http_status):
        self.assertIn("errors", response, f"expected a refusal, got {response}")
        self.assertNotIn("data", response)
        self.assertEqual(response["errors"][0]["code"], code)
        self.assertEqual(harness.status(), http_status)

    def assertNoSession(self):
        """A refusal must never have created a Frappe session.

        This is the assertion that makes the ordering in the endpoint matter:
        `resolve_access` runs BEFORE `post_login()`, so a user with a correct
        password but no application access stays Guest.
        """

        self.assertEqual(frappe.session.user, "Guest",
                         "a refused login left the caller authenticated")

    # ------------------------------------------------------------------ success

    def test_a_valid_password_authenticates_and_answers_the_envelope(self):
        response = self.login()

        self.assertNotIn("errors", response, f"login failed: {response}")
        self.assertEqual(set(response), {"data", "notice"})
        self.assertEqual(response["notice"], "Login successful.")

        data = response["data"]
        self.assertEqual(
            set(data),
            {"authenticated", "authentication_method", "user", "context", "csrf_token"})
        self.assertTrue(data["authenticated"])
        self.assertEqual(data["authentication_method"], "password")
        self.assertEqual(data["user"]["name"], USER)
        self.assertTrue(data["csrf_token"], "no CSRF token was issued")

    def test_the_context_names_the_application_that_was_asked_for(self):
        data = self.login()["data"]

        self.assertEqual(data["context"]["application"], APP)

    def test_the_context_publishes_only_the_three_documented_fields(self):
        """`roles` and `company` are withheld on purpose; see `_auth_payload`."""

        context = self.login()["data"]["context"]

        self.assertEqual(set(context),
                         {"application", "profile_doctype", "profile_name"})

    def test_a_successful_login_makes_the_caller_that_user(self):
        self.login()

        self.assertEqual(frappe.session.user, USER)
        self.assertEqual(frappe.local.login_manager.user, USER)

    def test_the_session_is_a_real_frappe_session(self):
        """Not a YOB token: `post_login()` must have produced a Sessions row."""

        self.login()

        self.assertEqual(frappe.local.session.user, USER)
        self.assertTrue(
            frappe.db.sql("select 1 from tabSessions where user = %s", USER),
            "no Frappe session record was created")

    def test_the_response_never_echoes_the_credential(self):
        """`authentication_method: "password"` is the only occurrence allowed."""

        body = json.dumps(self.login(), default=str)

        self.assertNotIn(PASSWORD, body)
        self.assertNotIn("pwd", body)
        self.assertNotIn('"password"', body.replace('"authentication_method": "password"', ""))

    def test_a_success_is_audited_with_a_masked_identifier(self):
        self.login()

        row = frappe.get_all(
            "YOB Auth Log",
            filters={"user": USER, "event": "Login", "status": "Success"},
            fields=["method", "identifier_masked", "application"],
            order_by="creation desc", limit=1)

        self.assertTrue(row, "a successful login wrote no audit row")
        self.assertEqual(row[0].method, "password")
        self.assertEqual(row[0].application, APP)
        self.assertNotEqual(row[0].identifier_masked, USER,
                            "the audit row stored the raw identifier")
        self.assertIn("***", row[0].identifier_masked)

    # ------------------------------------------------------- wrong credentials

    def test_a_wrong_password_is_refused_as_invalid_credentials(self):
        response = self.login(password="not-the-password")

        self.assertRefused(response, "invalid_credentials", 401)
        self.assertNoSession()

    def test_an_unknown_username_answers_exactly_what_a_wrong_password_does(self):
        """Non-enumeration: the two refusals must be indistinguishable."""

        unknown = self.login(username=UNKNOWN_USER)
        unknown_status = harness.status()

        harness.clear_password_limits(USER)
        wrong = self.login(password="not-the-password")

        self.assertEqual(unknown, wrong)
        self.assertEqual(unknown_status, harness.status())

    def test_a_blank_password_is_a_client_error_not_an_attempt(self):
        response = self.login(password="")

        self.assertRefused(response, "validation_failed", 422)
        self.assertEqual(response["errors"][0]["field"], "password")
        self.assertNoSession()

    def test_a_missing_application_is_a_client_error(self):
        response = auth.login_with_password(username=USER, password=PASSWORD)

        self.assertRefused(response, "validation_failed", 422)
        self.assertEqual(response["errors"][0]["field"], "application")

    def test_a_failed_login_is_audited_as_failed(self):
        self.login(password="not-the-password")

        self.assertTrue(
            frappe.get_all("YOB Auth Log",
                           filters={"event": "Login", "status": "Failed",
                                    "application": APP}, limit=1),
            "a failed login wrote no audit row")

    # ------------------------------------------------------------ disabled user

    def test_a_disabled_user_cannot_log_in(self):
        response = self.login(username=DISABLED_USER)

        self.assertRefused(response, "invalid_credentials", 401)
        self.assertNoSession()

    # --------------------------------------------------------- application access

    def test_a_user_with_no_grant_is_refused_after_authenticating(self):
        """The password is right; the authorization is not. No session.

        This is the ordering the endpoint exists to get right -- and the reason
        `resolve_access` is called between `authenticate()` and `post_login()`.
        """

        response = self.login(username=NO_GRANT_USER)

        self.assertRefused(response, "application_access_denied", 403)
        self.assertNoSession()

    def test_a_disabled_grant_is_refused(self):
        response = self.login(username=OFF_GRANT_USER)

        self.assertRefused(response, "application_access_denied", 403)
        self.assertNoSession()

    def test_an_expired_grant_is_refused(self):
        response = self.login(username=EXPIRED_USER)

        self.assertRefused(response, "application_access_denied", 403)
        self.assertIn("expired", response["errors"][0]["detail"].lower())
        self.assertNoSession()

    def test_a_grant_that_is_not_active_yet_is_refused(self):
        response = self.login(username=PENDING_USER)

        self.assertRefused(response, "application_access_denied", 403)
        self.assertNoSession()

    def test_logging_in_to_the_wrong_application_is_refused(self):
        """The user is real and enabled; the grant is for another application."""

        response = self.login(application=APP_ALT)

        self.assertRefused(response, "application_access_denied", 403)
        self.assertNoSession()

    def test_a_disabled_application_and_an_unknown_one_answer_alike(self):
        """Non-enumeration again, this time of application codes."""

        disabled = self.login(application=APP_DISABLED)
        disabled_status = harness.status()
        unknown = self.login(application="_TESTLOGINNOSUCHAPP")

        self.assertRefused(disabled, "application_access_denied", 403)
        self.assertEqual(disabled["errors"][0]["detail"],
                         unknown["errors"][0]["detail"])
        self.assertEqual(disabled_status, harness.status())
        self.assertNoSession()

    # ---------------------------------------------------------- login method off

    def test_an_application_with_password_login_off_refuses(self):
        response = self.login(application=APP_NO_PASSWORD)

        self.assertRefused(response, "application_access_denied", 403)
        self.assertNoSession()

    def test_the_site_wide_password_switch_refuses_before_authenticating(self):
        """`YOB Auth Settings.password_login_enabled = 0`, patched not stored.

        Writing the Single would be a site-wide configuration change, and a
        successful login elsewhere in the run commits -- so the switch is
        applied to the settings object the endpoint reads instead.
        """

        settings = frappe._dict(frappe.get_single("YOB Auth Settings").as_dict())
        settings.password_login_enabled = 0

        with patch.object(auth, "_settings", return_value=settings):
            response = self.login()

        self.assertRefused(response, "login_method_disabled", 422)
        self.assertNoSession()

    # ----------------------------------------------------------- the rate limit

    def test_the_password_rate_limit_applies_to_the_endpoint(self):
        settings = frappe._dict(frappe.get_single("YOB Auth Settings").as_dict())
        settings.max_password_attempts_per_window = 1

        with patch.object(auth, "_settings", return_value=settings):
            first = self.login(password="not-the-password")
            first_status = harness.status()
            second = self.login(password="not-the-password")

        # The status is read as each call returns: there is one shared response
        # object, so asserting on `first` afterwards would see the second status.
        self.assertEqual(first["errors"][0]["code"], "invalid_credentials")
        self.assertEqual(first_status, 401)
        self.assertRefused(second, "rate_limit_exceeded", 429)
        self.assertNoSession()

    # ------------------------------------------------------- the domain guard

    def test_login_does_not_bypass_the_domain_guard(self):
        """THE endpoint-level proof for §1: the guard is armed inside login.

        `test_domain_enforcement` calls `_validate_request_domain` directly, so
        it could not have noticed a login path that skipped it --
        `login_with_password` reaches it through `get_application()`, whose
        `validate_domain` defaults to True.
        """

        harness.install_guest_request()  # no X-YOB-Original-Host at all

        response = self.login(application=APP_DOMAIN)

        self.assertRefused(response, "application_access_denied", 403)
        self.assertIn("domain", response["errors"][0]["detail"].lower())
        self.assertNoSession()

    def test_an_unapproved_host_cannot_log_in(self):
        harness.install_guest_request({"X-YOB-Original-Host": "attacker.test"})

        response = self.login(application=APP_DOMAIN)

        self.assertRefused(response, "application_access_denied", 403)
        self.assertNoSession()

    def test_the_trusted_host_still_logs_in(self):
        """The guard must refuse the wrong host without breaking the right one."""

        harness.install_guest_request({"X-YOB-Original-Host": TRUSTED_HOST})

        response = self.login(application=APP_DOMAIN)

        self.assertNotIn("errors", response, f"login failed: {response}")
        self.assertEqual(response["data"]["context"]["application"], APP_DOMAIN)
        self.assertEqual(frappe.session.user, USER)

    def test_a_third_party_origin_cannot_log_in(self):
        """Origin is browser-set, so it is what stops a cross-site login POST."""

        harness.install_guest_request({
            "X-YOB-Original-Host": TRUSTED_HOST,
            "Origin": "https://evil.example.com",
        })

        response = self.login(application=APP_DOMAIN)

        self.assertRefused(response, "application_access_denied", 403)
        self.assertIn("origin", response["errors"][0]["detail"].lower())
        self.assertNoSession()


if __name__ == "__main__":
    unittest.main()
