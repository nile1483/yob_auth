# Copyright (c) 2026, YOB and Shayona
"""`request_otp` and `login_with_otp`, exercised as the endpoints.

THE GAP THIS CLOSES
-------------------
Like `login_with_password`, neither OTP endpoint had any automated test. The OTP
mechanism is also the part of auth with the most invariants to get wrong --
expiry measured from issuance, single-use consumption, attempt budgets, a
response that cannot be used to enumerate accounts, and a stored challenge that
must contain no credential.

CONFIGURATION IS NEVER WRITTEN
------------------------------
OTP is deliberately NOT enabled site-wide for these tests. `YOB Auth Settings`
is a Single, and a successful login commits the transaction, so a stored change
could outlive the run. Every flag is applied to the settings object
`yob_auth.security.otp` itself reads, through `patch.object`, and the throwaway
`YOB Application` records carry the per-application flags. The site's own
posture (email OTP off for STOREFRONT, mobile OTP off globally) is untouched and
is asserted separately, where it belongs, in
`yob_storefront.tests.test_storefront_login`.

DELIVERY IS ALWAYS MOCKED
-------------------------
No test sends mail or SMS. `_send_otp` is patched in every flow that reaches it,
which is also how the tests learn the code: nothing else can, because
`allow_test_otp_in_developer_mode` is off and the code is stored only as a
keyed digest. Two tests exercise `_send_otp` itself with the transport patched
one level lower, so the boundary is covered without a message leaving the bench.
"""

import json
import time
import unittest
from unittest.mock import patch

import frappe

from yob_auth.api import auth
from yob_auth.security import otp as otp_module
from yob_auth.tests import auth_harness as harness

APP = "_TESTOTP"
APP_OFF = "_TESTOTPOFF"

PASSWORD = "Yob-Test-Otp-9!x"

OTP_USER = "_test-otp-ok@yob.invalid"
NO_GRANT_USER = "_test-otp-nogrant@yob.invalid"
OTHER_APP_USER = "_test-otp-otherapp@yob.invalid"
DISABLED_USER = "_test-otp-disabled@yob.invalid"
UNVERIFIED_USER = "_test-otp-unverified@yob.invalid"
OFF_IDENTITY_USER = "_test-otp-offidentity@yob.invalid"

MOBILE = "+919812300001"
MOBILE_UNVERIFIED = "+919812300002"
MOBILE_DISABLED = "+919812300003"

ALL_USERS = (OTP_USER, NO_GRANT_USER, OTHER_APP_USER, DISABLED_USER,
             UNVERIFIED_USER, OFF_IDENTITY_USER)
ALL_APPS = (APP, APP_OFF)

ACCESS = "YOB User Application Access"
IDENTITY = "YOB Login Identity"

#: The real delivery function, captured before `setUp` patches the module
#: attribute. The three transport tests need the genuine implementation --
#: calling `otp_module._send_otp` there would reach this module's own recorder.
REAL_SEND_OTP = otp_module._send_otp


def _application(code, **overrides):
    if frappe.db.exists("YOB Application", code):
        return
    values = {
        "doctype": "YOB Application", "application_code": code,
        "application_name": f"OTP Test {code}", "enabled": 1, "domains": "",
        "allow_password_login": 1, "allow_email_otp": 1, "allow_mobile_otp": 1,
    }
    values.update(overrides)
    frappe.get_doc(values).insert(ignore_permissions=True)


def _user(email, *, enabled=1):
    if frappe.db.exists("User", email):
        return
    doc = frappe.get_doc({
        "doctype": "User", "email": email, "first_name": "Otp",
        "last_name": email.split("@")[0], "send_welcome_email": 0,
        "new_password": PASSWORD,
    })
    doc.flags.ignore_permissions = True
    doc.insert(ignore_permissions=True)
    if not enabled:
        frappe.db.set_value("User", email, "enabled", 0)


def _grant(user, application):
    if frappe.db.exists(ACCESS, {"user": user, "application": application}):
        return
    frappe.get_doc({"doctype": ACCESS, "user": user, "application": application,
                    "enabled": 1}).insert(ignore_permissions=True)


def _identity(user, value, *, verified=1, enabled=1):
    if frappe.db.exists(IDENTITY, {"user": user, "normalized_value": value}):
        return
    frappe.get_doc({"doctype": IDENTITY, "user": user, "identity_type": "Mobile",
                    "normalized_value": value, "verified": verified,
                    "enabled": enabled}).insert(ignore_permissions=True)



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
    _application(APP_OFF, allow_email_otp=0, allow_mobile_otp=0)

    for email in ALL_USERS:
        _user(email, enabled=0 if email == DISABLED_USER else 1)

    for email in (OTP_USER, DISABLED_USER, UNVERIFIED_USER, OFF_IDENTITY_USER):
        _grant(email, APP)
    _grant(OTHER_APP_USER, APP_OFF)

    _identity(OTP_USER, MOBILE)
    _identity(UNVERIFIED_USER, MOBILE_UNVERIFIED, verified=0)
    _identity(OFF_IDENTITY_USER, MOBILE_DISABLED, enabled=0)


def _destroy_fixtures():
    frappe.set_user("Administrator")
    harness.purge_auth_traces(*ALL_USERS)
    for email in ALL_USERS:
        for doctype in (ACCESS, IDENTITY):
            for name in frappe.get_all(doctype, filters={"user": email}, pluck="name"):
                frappe.delete_doc(doctype, name, force=True, ignore_permissions=True)
        if frappe.db.exists("User", email):
            frappe.delete_doc("User", email, force=True, ignore_permissions=True)
    for code in ALL_APPS:
        if frappe.db.exists("YOB Application", code):
            frappe.delete_doc("YOB Application", code, force=True,
                              ignore_permissions=True)


class OtpEndpointCase(unittest.TestCase):
    """Both endpoints, with OTP enabled only inside the test."""

    @classmethod
    def setUpClass(cls):
        frappe.set_user("Administrator")
        if not str(frappe.conf.get("yob_auth_otp_secret") or "").strip():
            raise unittest.SkipTest(
                "yob_auth_otp_secret is not configured in site_config.json, so "
                "no OTP can be hashed on this site")
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
            frappe.db.exists("User", OTP_USER),
            "the fixture user is missing, so this module's assertions would "
            "pass vacuously")
        self.assertTrue(frappe.db.exists("YOB Application", APP))
        self.assertTrue(frappe.db.exists(
            IDENTITY, {"user": OTP_USER, "normalized_value": MOBILE,
                       "verified": 1, "enabled": 1}))

        self.locals = harness.snapshot_locals()
        self.addCleanup(harness.restore_locals, self.locals)
        self.addCleanup(frappe.clear_cache)
        self.addCleanup(frappe.db.rollback)

        self.challenges = []
        self.addCleanup(self._forget_challenges)

        harness.install_guest_request()

        # Every identifier these tests touch, so a resend cooldown or an hourly
        # counter left by an earlier test cannot refuse a later one. The limits
        # themselves stay armed: `test_a_resend_inside_the_cooldown_is_refused`
        # proves the cooldown works.
        for method, identifier in (
            ("email_otp", OTP_USER), ("email_otp", NO_GRANT_USER),
            ("email_otp", OTHER_APP_USER), ("email_otp", DISABLED_USER),
            ("email_otp", "_test-otp-nobody@yob.invalid"),
            ("mobile_otp", MOBILE), ("mobile_otp", MOBILE_UNVERIFIED),
            ("mobile_otp", MOBILE_DISABLED), ("mobile_otp", "9812300001"),
        ):
            harness.clear_otp_limits(method, identifier)

        self.settings = frappe._dict(frappe.get_single("YOB Auth Settings").as_dict())
        self.settings.email_otp_enabled = 1
        self.settings.mobile_otp_enabled = 1
        # Deterministically off: a site with developer mode AND this flag on
        # returns the code in the response, which these tests must not depend on.
        self.settings.allow_test_otp_in_developer_mode = 0

        self.sent = []
        settings_patch = patch.object(otp_module, "_settings",
                                      side_effect=lambda: self.settings)
        send_patch = patch.object(otp_module, "_send_otp",
                                  side_effect=self._record_delivery)
        settings_patch.start()
        send_patch.start()
        self.addCleanup(settings_patch.stop)
        self.addCleanup(send_patch.stop)

    # ------------------------------------------------------------------ helpers

    def _record_delivery(self, identifier, method, code, challenge_id, settings):
        self.sent.append({"identifier": identifier, "method": method,
                          "otp": code, "challenge_id": challenge_id})

    def _forget_challenges(self):
        for challenge_id in self.challenges:
            harness.forget_challenge(challenge_id)

    def request(self, identifier=OTP_USER, method="email_otp", application=APP):
        response = auth.request_otp(application=application, identifier=identifier,
                                    method=method)
        if "data" in response:
            self.challenges.append(response["data"]["challenge_id"])
        return response

    def issue(self, identifier=OTP_USER, method="email_otp", application=APP):
        """Request an OTP and return `(challenge_id, code)`.

        The code comes from the mocked delivery boundary, because that is the
        only place a plaintext OTP exists: the challenge stores a keyed digest.
        """

        response = self.request(identifier, method, application)
        self.assertNotIn("errors", response, f"request_otp failed: {response}")
        return response["data"]["challenge_id"], self.sent[-1]["otp"]

    def assertRefused(self, response, code, http_status):
        self.assertIn("errors", response, f"expected a refusal, got {response}")
        self.assertNotIn("data", response)
        self.assertEqual(response["errors"][0]["code"], code)
        self.assertEqual(harness.status(), http_status)

    def assertNoSession(self):
        self.assertEqual(frappe.session.user, "Guest",
                         "a refused OTP login left the caller authenticated")

    # ------------------------------------------------------- method is disabled

    def test_an_application_with_email_otp_off_refuses(self):
        response = self.request(application=APP_OFF)

        self.assertRefused(response, "application_access_denied", 403)
        self.assertEqual(self.sent, [], "an OTP was sent for a disabled method")

    def test_an_application_with_mobile_otp_off_refuses(self):
        response = self.request(MOBILE, "mobile_otp", application=APP_OFF)

        self.assertRefused(response, "application_access_denied", 403)
        self.assertEqual(self.sent, [])

    def test_the_site_wide_email_otp_switch_refuses(self):
        self.settings.email_otp_enabled = 0

        response = self.request()

        self.assertRefused(response, "login_method_disabled", 422)
        self.assertEqual(self.sent, [])

    def test_the_site_wide_mobile_otp_switch_refuses(self):
        """This is the shipped default: `mobile_otp_enabled` is 0 out of the box."""

        self.settings.mobile_otp_enabled = 0

        response = self.request(MOBILE, "mobile_otp")

        self.assertRefused(response, "login_method_disabled", 422)
        self.assertEqual(self.sent, [])

    def test_an_unrecognised_method_is_refused(self):
        response = self.request(method="carrier_pigeon")

        self.assertRefused(response, "application_access_denied", 403)
        self.assertEqual(self.sent, [])

    def test_a_missing_identifier_is_a_client_error(self):
        response = auth.request_otp(application=APP, method="email_otp")

        self.assertRefused(response, "validation_failed", 422)
        self.assertEqual(response["errors"][0]["field"], "identifier")

    # ------------------------------------------------------- challenge creation

    def test_a_request_creates_a_challenge_with_the_configured_lifetime(self):
        response = self.request()

        data = response["data"]
        self.assertEqual(set(data), {"challenge_id", "expires_in"})
        self.assertRegex(data["challenge_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(data["expires_in"], self.settings.otp_expiry_seconds)

        payload = harness.challenge(data["challenge_id"])
        self.assertIsNotNone(payload, "no challenge was stored")
        self.assertEqual(payload["user"], OTP_USER)
        self.assertEqual(payload["method"], "email_otp")
        self.assertEqual(payload["application"], APP)
        self.assertEqual(payload["attempts"], 0)
        self.assertAlmostEqual(payload["created"], int(time.time()), delta=30)

    def test_the_challenge_stores_a_digest_and_never_the_code(self):
        challenge_id, code = self.issue()

        payload = harness.challenge(challenge_id)

        self.assertIn("hash", payload)
        self.assertIn("salt", payload)
        self.assertNotIn(code, json.dumps(payload, default=str),
                         "the plaintext OTP is stored in the challenge")
        self.assertNotEqual(payload["hash"], code)

    def test_the_response_never_carries_the_code(self):
        response = self.request()
        code = self.sent[-1]["otp"]

        body = json.dumps(response, default=str)

        self.assertNotIn(code, body)
        self.assertNotIn("test_otp", body)

    def test_the_notice_is_identical_for_an_eligible_and_an_unknown_account(self):
        """Non-enumeration: the answer must not reveal that an account exists."""

        eligible = self.request()
        unknown = self.request(identifier="_test-otp-nobody@yob.invalid")

        self.assertEqual(eligible["notice"], unknown["notice"])
        self.assertEqual(set(eligible["data"]), set(unknown["data"]))
        self.assertEqual(eligible["data"]["expires_in"],
                         unknown["data"]["expires_in"])
        self.assertNotEqual(eligible["data"]["challenge_id"],
                            unknown["data"]["challenge_id"])

    def test_the_delivery_boundary_receives_the_identifier_and_the_code(self):
        challenge_id, code = self.issue()

        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0]["identifier"], OTP_USER)
        self.assertEqual(self.sent[0]["method"], "email_otp")
        self.assertEqual(self.sent[0]["challenge_id"], challenge_id)
        self.assertRegex(code, r"^\d{%d}$" % self.settings.otp_length)

    def test_a_delivery_failure_does_not_change_the_answer(self):
        """Documented behaviour: the caller is told the same thing either way."""

        with patch.object(otp_module, "_send_otp",
                          side_effect=RuntimeError("smtp is down")):
            response = self.request()

        self.assertNotIn("errors", response)
        self.assertTrue(response["data"]["challenge_id"])

        row = frappe.get_all("YOB Auth Log",
                             filters={"event": "OTP Requested", "user": OTP_USER},
                             fields=["status", "details"],
                             order_by="creation desc", limit=1)
        self.assertTrue(row)
        self.assertEqual(row[0].status, "Success")
        self.assertIn("delivery failed", row[0].details)

    def test_a_resend_inside_the_cooldown_is_refused(self):
        self.request()

        second = self.request()

        self.assertRefused(second, "rate_limit_exceeded", 429)

    # ------------------------------------------------------------ verification

    def test_a_valid_code_authenticates(self):
        challenge_id, code = self.issue()

        response = auth.login_with_otp(challenge_id=challenge_id, otp=code)

        self.assertNotIn("errors", response, f"login failed: {response}")
        data = response["data"]
        self.assertTrue(data["authenticated"])
        self.assertEqual(data["authentication_method"], "email_otp")
        self.assertEqual(data["user"]["name"], OTP_USER)
        self.assertEqual(data["context"]["application"], APP)
        self.assertTrue(data["csrf_token"])
        self.assertEqual(frappe.session.user, OTP_USER)

    def test_a_successful_verification_is_audited(self):
        challenge_id, code = self.issue()

        auth.login_with_otp(challenge_id=challenge_id, otp=code)

        self.assertTrue(
            frappe.get_all("YOB Auth Log",
                           filters={"event": "OTP Verified", "status": "Success",
                                    "reference": challenge_id}, limit=1),
            "a verified OTP wrote no audit row")

    def test_a_wrong_code_is_refused_and_counted(self):
        challenge_id, code = self.issue()

        response = auth.login_with_otp(challenge_id=challenge_id, otp="000000")

        self.assertRefused(response, "otp_invalid", 401)
        self.assertNoSession()

        payload = harness.challenge(challenge_id)
        self.assertIsNotNone(payload, "a single wrong attempt destroyed the challenge")
        self.assertEqual(payload["attempts"], 1)

        # Still usable: a wrong guess must not lock out the legitimate payer.
        self.assertNotIn("errors",
                         auth.login_with_otp(challenge_id=challenge_id, otp=code))

    def test_a_consumed_challenge_cannot_be_replayed(self):
        challenge_id, code = self.issue()

        first = auth.login_with_otp(challenge_id=challenge_id, otp=code)
        harness.install_guest_request()
        replay = auth.login_with_otp(challenge_id=challenge_id, otp=code)

        self.assertNotIn("errors", first)
        self.assertRefused(replay, "otp_invalid", 401)
        self.assertIsNone(harness.challenge(challenge_id),
                          "the challenge survived its single use")
        self.assertNoSession()

    def test_an_expired_challenge_is_refused(self):
        """Expiry is measured from issuance, not from the last attempt.

        The challenge is aged in place rather than slept on: `_remaining_ttl`
        computes `otp_expiry_seconds - (now - created)`, so rewinding `created`
        is exactly the state a stale challenge is in.
        """

        challenge_id, code = self.issue()
        payload = harness.challenge(challenge_id)
        payload["created"] = int(time.time()) - (self.settings.otp_expiry_seconds + 60)
        frappe.cache.set_value(f"yob_auth:otp:{challenge_id}", payload,
                               expires_in_sec=600)

        response = auth.login_with_otp(challenge_id=challenge_id, otp=code)

        self.assertRefused(response, "otp_invalid", 401)
        self.assertIsNone(harness.challenge(challenge_id),
                          "an expired challenge was left in the cache")
        self.assertNoSession()

    def test_an_attempt_does_not_restart_the_expiry_clock(self):
        """A challenge must not be kept alive by guessing at it."""

        challenge_id, _ = self.issue()
        payload = harness.challenge(challenge_id)
        aged = int(time.time()) - 120
        payload["created"] = aged
        frappe.cache.set_value(f"yob_auth:otp:{challenge_id}", payload,
                               expires_in_sec=600)

        auth.login_with_otp(challenge_id=challenge_id, otp="000000")

        self.assertEqual(harness.challenge(challenge_id)["created"], aged)

    def test_the_attempt_budget_destroys_the_challenge(self):
        self.settings.max_otp_attempts = 2
        challenge_id, code = self.issue()

        for _ in range(3):
            auth.login_with_otp(challenge_id=challenge_id, otp="000000")

        self.assertIsNone(harness.challenge(challenge_id),
                          "the challenge survived its attempt budget")

        response = auth.login_with_otp(challenge_id=challenge_id, otp=code)

        self.assertRefused(response, "otp_invalid", 401)
        self.assertNoSession()

    def test_an_unknown_challenge_is_refused(self):
        response = auth.login_with_otp(challenge_id="0" * 32, otp="123456")

        self.assertRefused(response, "otp_invalid", 401)
        self.assertNoSession()

    def test_a_missing_code_is_a_client_error(self):
        challenge_id, _ = self.issue()

        response = auth.login_with_otp(challenge_id=challenge_id)

        self.assertRefused(response, "validation_failed", 422)
        self.assertEqual(response["errors"][0]["field"], "otp")
        self.assertNoSession()

    # ----------------------------------------------- access-scoped resolution

    def test_an_account_with_no_grant_is_never_sent_an_otp(self):
        response = self.request(identifier=NO_GRANT_USER)

        self.assertNotIn("errors", response, "the refusal was visible to the caller")
        self.assertEqual(self.sent, [], "an OTP was sent to an ineligible account")
        self.assertIsNone(harness.challenge(response["data"]["challenge_id"])["user"],
                          "an ineligible account was bound to the challenge")

    def test_an_unbound_challenge_can_never_authenticate(self):
        """No code exists for it, and even a correct digest would be refused."""

        response = self.request(identifier=NO_GRANT_USER)
        challenge_id = response["data"]["challenge_id"]

        self.assertRefused(
            auth.login_with_otp(challenge_id=challenge_id, otp="123456"),
            "otp_invalid", 401)
        self.assertNoSession()

    def test_a_grant_for_another_application_does_not_resolve(self):
        response = self.request(identifier=OTHER_APP_USER)

        self.assertEqual(self.sent, [])
        self.assertIsNone(harness.challenge(response["data"]["challenge_id"])["user"])

    def test_a_disabled_user_does_not_resolve(self):
        response = self.request(identifier=DISABLED_USER)

        self.assertEqual(self.sent, [])
        self.assertIsNone(harness.challenge(response["data"]["challenge_id"])["user"])

    def test_the_audit_records_an_ignored_request_without_naming_a_user(self):
        response = self.request(identifier=NO_GRANT_USER)

        row = frappe.get_all(
            "YOB Auth Log",
            filters={"event": "OTP Requested",
                     "reference": response["data"]["challenge_id"]},
            fields=["status", "user", "identifier_masked"], limit=1)

        self.assertTrue(row)
        self.assertEqual(row[0].status, "Ignored")
        self.assertIsNone(row[0].user)
        self.assertNotEqual(row[0].identifier_masked, NO_GRANT_USER)

    # ---------------------------------------------------------- mobile OTP

    def test_mobile_otp_needs_a_verified_identity(self):
        response = self.request(MOBILE_UNVERIFIED, "mobile_otp")

        self.assertEqual(self.sent, [],
                         "an OTP was sent to an unverified mobile identity")
        self.assertIsNone(harness.challenge(response["data"]["challenge_id"])["user"])

    def test_mobile_otp_needs_an_enabled_identity(self):
        response = self.request(MOBILE_DISABLED, "mobile_otp")

        self.assertEqual(self.sent, [])
        self.assertIsNone(harness.challenge(response["data"]["challenge_id"])["user"])

    def test_a_verified_mobile_identity_authenticates(self):
        challenge_id, code = self.issue(MOBILE, "mobile_otp")

        response = auth.login_with_otp(challenge_id=challenge_id, otp=code)

        self.assertNotIn("errors", response, f"login failed: {response}")
        self.assertEqual(response["data"]["authentication_method"], "mobile_otp")
        self.assertEqual(response["data"]["user"]["name"], OTP_USER)
        self.assertEqual(frappe.session.user, OTP_USER)

    def test_a_local_number_resolves_the_same_identity(self):
        """The endpoint normalises, so a buyer need not type a country code."""

        challenge_id, code = self.issue("9812300001", "mobile_otp")

        self.assertEqual(harness.challenge(challenge_id)["user"], OTP_USER)
        self.assertNotIn("errors",
                         auth.login_with_otp(challenge_id=challenge_id, otp=code))

    # ------------------------------------------------------ the real transport

    def test_the_email_transport_is_frappe_sendmail(self):
        """`_send_otp` itself, with the transport patched one level lower."""

        with patch.object(frappe, "sendmail") as sendmail:
            REAL_SEND_OTP(OTP_USER, "email_otp", "123456", "abc", self.settings)

        sendmail.assert_called_once()
        self.assertEqual(sendmail.call_args.kwargs["recipients"], [OTP_USER])
        self.assertIn("123456", sendmail.call_args.kwargs["message"])

    def test_mobile_delivery_refuses_when_no_sender_is_configured(self):
        """No silent no-op: an unconfigured sender must fail loudly, not pretend."""

        self.settings.sms_sender_method = ""

        with self.assertRaises(frappe.ValidationError):
            REAL_SEND_OTP(MOBILE, "mobile_otp", "123456", "abc", self.settings)

    def test_mobile_delivery_calls_the_configured_sender_with_the_normalised_number(self):
        """A REAL dotted path, resolved by `frappe.get_attr`, to a local recorder.

        `frappe.get_attr` is deliberately not patched: it is also how Frappe
        resolves a DocType controller, so patching it globally recorded an extra
        call the moment anything loaded a document -- which is how this test
        first failed with `2 != 1`. Registering a genuine dotted path exercises
        the resolution the setting actually depends on.
        """

        self.settings.sms_sender_method = f"{__name__}.record_sms"
        SENT_SMS.clear()
        self.addCleanup(SENT_SMS.clear)

        REAL_SEND_OTP("9812300001", "mobile_otp", "123456", "abc", self.settings)

        self.assertEqual(len(SENT_SMS), 1)
        number, message, reference = SENT_SMS[0]
        self.assertEqual(number, MOBILE, "the sender was handed an unnormalised number")
        self.assertIn("123456", message)
        self.assertEqual(reference, "abc")


#: Where `record_sms` puts what it was asked to send. Nothing leaves the bench.
SENT_SMS = []


def record_sms(number, message, reference=None):
    """A stand-in SMS sender, reached through `sms_sender_method`."""

    SENT_SMS.append((number, message, reference))


if __name__ == "__main__":
    unittest.main()
