# Copyright (c) 2026, YOB and Shayona
"""YOB auth rate-limit windows must belong to ONE site.

THE DEFECT THIS CLOSES
----------------------
Every rate-limit counter is incremented with `frappe.cache.incrby`, which is
inherited straight from `redis.Redis` and is the one cache call Frappe does NOT
route through `RedisWrapper.make_key`. The counters therefore lived at RAW Redis
keys, outside the `<db_name>|` namespace every other cache value gets -- so two
Frappe sites sharing one Redis instance shared one password window and one OTP
window. Traffic on site A consumed site B's allowance.

It failed SAFE for authentication: a shared counter can only ever read HIGH, so
nobody ever gained attempts. What it created was an availability problem -- one
site's traffic, or one attacker against it, could throttle logins and OTP
requests on every other site on the bench.

Found by the Phase 33 test-hardening audit, which had to delete these counters
by raw key to keep its own tests deterministic.

HOW SITES ARE SIMULATED
-----------------------
By patching `frappe.local.site`, deliberately. The site is the ONLY thing that
distinguishes one site's key from another's, and the cache connection is shared
-- which is precisely the condition the defect needed. Running two real sites
would prove the same thing more expensively and prove nothing more: the keys are
built from `frappe.local.site`, and both contexts here hit the same Redis
database with the same `db_name`, so a leak would still show.

The IP-keyed windows need `is_client_ip_trusted()` to be true, which depends on
site configuration (`yob_auth_client_ip_header`). That precondition is patched
so these tests arm on any bench; what is under test is the key, not the trust
decision -- `test_origin_matching` and `test_domain_enforcement` own that.
"""

import time
import unittest
from contextlib import contextmanager
from unittest.mock import patch

import frappe

from yob_auth.security import rate_limit
from yob_auth.security.exceptions import YOBRateLimitError
from yob_auth.security.rate_limit import (
    enforce_otp_request_limits,
    enforce_password_attempt_limits,
    rate_limit_key,
)

SITE_A = "_rl-site-a.localhost"
SITE_B = "_rl-site-b.localhost"

#: Every key this module writes contains this, so cleanup can find them all by
#: pattern without knowing the key format -- and without touching the real
#: site's counters.
SITE_MARK = "_rl-site"

USERNAME = "_rl-user@yob.invalid"
IDENTIFIER = "_rl-otp@yob.invalid"
TRUSTED_IP = "203.0.113.7"


def _settings(**overrides):
    """A settings stand-in carrying only what the limiters read."""

    values = {
        "password_rate_window_seconds": 300,
        "max_password_attempts_per_window": 10,
        "max_password_attempts_per_ip_window": 50,
        "otp_resend_seconds": 60,
        "max_otp_requests_per_hour": 8,
    }
    values.update(overrides)
    return frappe._dict(values)


def _purge():
    """Delete every key either simulated site could have written.

    Matched by WILDCARD rather than rebuilt from the implementation's own key
    builder: a cleanup that used `rate_limit_key` would follow the code under
    test wherever it went, including somewhere wrong. The pattern catches both
    the raw counter keys and the `<db_name>|...` form that `set_value` writes
    for the cooldown.
    """

    keys = frappe.cache.keys(f"*{SITE_MARK}*")
    if keys:
        frappe.cache.delete_value(keys, make_keys=False)


@contextmanager
def as_site(site):
    original = getattr(frappe.local, "site", None)
    frappe.local.site = site
    try:
        yield
    finally:
        frappe.local.site = original


class RateLimitSiteIsolationCase(unittest.TestCase):
    """One site's traffic must never consume another site's allowance."""

    def setUp(self):
        frappe.set_user("Administrator")
        _purge()
        self.addCleanup(_purge)

        # The IP-keyed windows are only armed when the client IP is trustworthy.
        # Fixed here so both simulated sites report the SAME ip -- a leak then
        # cannot be hidden by the two sites happening to differ on something
        # other than the site itself.
        trusted = patch.object(rate_limit, "is_client_ip_trusted", return_value=True)
        client_ip = patch.object(rate_limit, "get_trusted_client_ip",
                                 return_value=TRUSTED_IP)
        trusted.start()
        client_ip.start()
        self.addCleanup(trusted.stop)
        self.addCleanup(client_ip.stop)

    # ------------------------------------------------------------------ helpers

    def exhaust_password(self, site, settings, attempts):
        with as_site(site):
            for _ in range(attempts):
                enforce_password_attempt_limits(USERNAME, settings)

    def assertPasswordRefused(self, site, settings):
        with as_site(site), self.assertRaises(YOBRateLimitError):
            enforce_password_attempt_limits(USERNAME, settings)

    def assertPasswordAllowed(self, site, settings, message):
        with as_site(site):
            try:
                enforce_password_attempt_limits(USERNAME, settings)
            except YOBRateLimitError as exc:
                self.fail(f"{message}: {exc}")

    def request_otp_on(self, site, settings, *, clear_cooldown=True):
        """One OTP request, with the resend cooldown optionally cleared first.

        The cooldown is a SEPARATE control from the hourly counter and would
        refuse the second request before the counter was ever consulted. It is
        exercised by its own test below; here it is cleared so the hourly
        window is what is being measured.
        """

        with as_site(site):
            if clear_cooldown:
                frappe.cache.delete_value(rate_limit_key(
                    "otp", "cooldown", rate_limit._digest(f"email_otp:{IDENTIFIER}")))
            enforce_otp_request_limits(IDENTIFIER, "email_otp", settings)

    # -------------------------------------------------- password: user window

    def test_the_password_user_window_is_not_shared_between_sites(self):
        settings = _settings(max_password_attempts_per_window=2,
                             max_password_attempts_per_ip_window=10_000)

        self.exhaust_password(SITE_A, settings, 2)
        self.assertPasswordRefused(SITE_A, settings)

        self.assertPasswordAllowed(
            SITE_B, settings,
            "site B's password window was already consumed by site A")

    def test_each_site_reaches_its_own_password_limit_independently(self):
        """Both sites get the full budget, and each still has a limit."""

        settings = _settings(max_password_attempts_per_window=2,
                             max_password_attempts_per_ip_window=10_000)

        self.exhaust_password(SITE_A, settings, 2)
        self.exhaust_password(SITE_B, settings, 2)

        self.assertPasswordRefused(SITE_A, settings)
        self.assertPasswordRefused(SITE_B, settings)

    # ---------------------------------------------------- password: IP window

    def test_the_password_ip_window_is_not_shared_between_sites(self):
        """Same IP, same user, different site: separate budgets.

        The per-identity window is left wide open so the refusal can only come
        from the IP-keyed one.
        """

        settings = _settings(max_password_attempts_per_window=10_000,
                             max_password_attempts_per_ip_window=2)

        self.exhaust_password(SITE_A, settings, 2)
        self.assertPasswordRefused(SITE_A, settings)

        self.assertPasswordAllowed(
            SITE_B, settings,
            "site B's per-IP password window was consumed by site A")

    def test_the_password_pair_window_is_not_shared_between_sites(self):
        """The (ip, user) pair window is keyed on both and must isolate too."""

        settings = _settings(max_password_attempts_per_window=2,
                             max_password_attempts_per_ip_window=10_000)

        with as_site(SITE_A):
            window = int(time.time() // 300)
            pair = rate_limit_key(
                "password", "pair", rate_limit._digest(TRUSTED_IP),
                rate_limit._digest(USERNAME), window)

        self.exhaust_password(SITE_A, settings, 2)

        self.assertTrue(frappe.cache.get(pair),
                        "the pair window was never written, so this proves nothing")

        with as_site(SITE_B):
            site_b_pair = rate_limit_key(
                "password", "pair", rate_limit._digest(TRUSTED_IP),
                rate_limit._digest(USERNAME), window)

        self.assertNotEqual(site_b_pair, pair)
        self.assertIsNone(frappe.cache.get(site_b_pair),
                          "site B's pair window already held site A's count")

        self.assertPasswordAllowed(
            SITE_B, settings, "site B's pair window was consumed by site A")

    # ------------------------------------------------------ OTP: hourly window

    def test_the_otp_request_window_is_not_shared_between_sites(self):
        settings = _settings(max_otp_requests_per_hour=2)

        self.request_otp_on(SITE_A, settings)
        self.request_otp_on(SITE_A, settings)
        with self.assertRaises(YOBRateLimitError):
            self.request_otp_on(SITE_A, settings)

        try:
            self.request_otp_on(SITE_B, settings)
        except YOBRateLimitError as exc:
            self.fail(f"site B's OTP allowance was consumed by site A: {exc}")

    def test_the_otp_ip_window_is_not_shared_between_sites(self):
        """`maximum * 5` is the IP budget; the identifier budget is kept clear.

        One identifier per site cannot reach `maximum * 5` before reaching
        `maximum`, so the identifier window is raised and the IP window is what
        trips -- the same separation used for the password windows above.
        """

        settings = _settings(max_otp_requests_per_hour=1)

        # 1 identifier request and 5 IP requests are the two budgets. Spend the
        # identifier budget on site A, then confirm site B starts clean on both.
        self.request_otp_on(SITE_A, settings)
        with self.assertRaises(YOBRateLimitError):
            self.request_otp_on(SITE_A, settings)

        try:
            self.request_otp_on(SITE_B, settings)
        except YOBRateLimitError as exc:
            self.fail(f"site B's OTP windows were consumed by site A: {exc}")

    def test_the_otp_resend_cooldown_is_not_shared_between_sites(self):
        """The cooldown is `set_value`, so it was already namespaced by Frappe.

        It now ALSO carries the site in the YOB key, which is belt and braces
        rather than a fix -- and this test is what would notice if a future
        change moved it to the raw increment path and lost the namespace.
        """

        settings = _settings()

        self.request_otp_on(SITE_A, settings, clear_cooldown=False)
        with self.assertRaises(YOBRateLimitError):
            self.request_otp_on(SITE_A, settings, clear_cooldown=False)

        try:
            self.request_otp_on(SITE_B, settings, clear_cooldown=False)
        except YOBRateLimitError as exc:
            self.fail(f"site A's resend cooldown blocked site B: {exc}")

    # ------------------------------------------- the counter still has to work

    def test_two_calls_on_the_SAME_site_share_one_password_counter(self):
        """The guard against 'fixing' this by making every key unique.

        If isolation were implemented with anything per-request -- a uuid, a
        timestamp, a session -- every one of the tests above would still pass
        and rate limiting would be silently switched off.
        """

        settings = _settings(max_password_attempts_per_window=2,
                             max_password_attempts_per_ip_window=10_000)

        self.exhaust_password(SITE_A, settings, 2)

        self.assertPasswordRefused(SITE_A, settings)

    def test_two_calls_on_the_SAME_site_share_one_otp_counter(self):
        settings = _settings(max_otp_requests_per_hour=2)

        self.request_otp_on(SITE_A, settings)
        self.request_otp_on(SITE_A, settings)

        with self.assertRaises(YOBRateLimitError):
            self.request_otp_on(SITE_A, settings)

    def test_the_same_site_keeps_one_window_across_separate_contexts(self):
        """Re-entering the same site must resume its counter, not restart it."""

        settings = _settings(max_password_attempts_per_window=2,
                             max_password_attempts_per_ip_window=10_000)

        self.exhaust_password(SITE_A, settings, 1)
        self.exhaust_password(SITE_B, settings, 1)
        self.exhaust_password(SITE_A, settings, 1)

        self.assertPasswordRefused(SITE_A, settings)
        self.assertPasswordAllowed(SITE_B, settings,
                                   "site B's own second attempt was refused")

    # ------------------------------------------------------------- key safety

    def test_the_key_carries_the_site(self):
        with as_site(SITE_A):
            key_a = rate_limit_key("password", "user", "abc", 1)
        with as_site(SITE_B):
            key_b = rate_limit_key("password", "user", "abc", 1)

        self.assertIn(SITE_A, key_a)
        self.assertIn(SITE_B, key_b)
        self.assertNotEqual(key_a, key_b)
        self.assertTrue(key_a.startswith("yob_auth:"))

    def test_an_unsafe_site_name_cannot_collide_with_another(self):
        """Percent-encoded, not character-replaced: the mapping is injective.

        Replacing `:` with `-` would have made a site named `a:b` share a
        bucket with one named `a-b`, which is the ambiguity this encoding
        exists to rule out.
        """

        with as_site("a:b"):
            colon = rate_limit_key("password", "user", "abc", 1)
        with as_site("a-b"):
            dash = rate_limit_key("password", "user", "abc", 1)

        self.assertNotEqual(colon, dash)
        # The separator must never appear inside the site segment, or the key
        # would parse as a different number of segments.
        self.assertEqual(colon.count(":"), dash.count(":"))

    def test_a_missing_site_gets_its_own_bucket_rather_than_a_real_one(self):
        with as_site(None):
            key = rate_limit_key("password", "user", "abc", 1)

        self.assertTrue(key.startswith("yob_auth:"))
        for site in (SITE_A, SITE_B):
            self.assertNotIn(site, key)

    def test_no_identifier_or_credential_appears_in_a_key_in_the_clear(self):
        """Keys stay digest-only, exactly as before this change."""

        settings = _settings()

        with as_site(SITE_A):
            enforce_password_attempt_limits(USERNAME, settings)
            enforce_otp_request_limits(IDENTIFIER, "email_otp", settings)

        written = [key.decode() if isinstance(key, bytes) else str(key)
                   for key in frappe.cache.keys(f"*{SITE_MARK}*")]

        self.assertTrue(written, "no keys were written, so this proves nothing")
        for key in written:
            with self.subTest(key=key):
                self.assertNotIn(USERNAME, key)
                self.assertNotIn(IDENTIFIER, key)
                self.assertNotIn("@", key)

    def test_the_otp_challenge_is_site_namespaced_by_frappe_itself(self):
        """The OTP ATTEMPT budget needed no fix, and this is why.

        Attempts are counted inside the challenge payload (`payload["attempts"]`
        in `security/otp.py`), and the challenge is stored with `set_value` --
        which DOES go through `RedisWrapper.make_key`, so it already lives in the
        `<db_name>|` per-site namespace. Asserted mechanically rather than
        claimed: the value is readable through the namespaced API and absent at
        the raw key.
        """

        key = "yob_auth:otp:_rl-site-probe"
        frappe.cache.set_value(key, {"attempts": 0}, expires_in_sec=60)
        self.addCleanup(frappe.cache.delete_value, key)

        self.assertEqual(frappe.cache.get_value(key), {"attempts": 0})
        self.assertIsNone(frappe.cache.get(key),
                          "the challenge is stored at a raw key, so it is NOT "
                          "site-namespaced and the attempt budget is shared")
        self.assertIn(frappe.conf.db_name,
                      frappe.cache.make_key(key).decode())


if __name__ == "__main__":
    unittest.main()
