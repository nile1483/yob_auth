# Copyright (c) 2026, YOB and Shayona
"""`allowed_origins` matching (Phase 32I).

WHAT WAS WRONG
--------------
`allowed_origins` entries were lowercased and compared as RAW STRINGS against
the browser's `Origin` header. A browser always sends `scheme://host[:port]`, so
a scheme-less entry could never match anything:

    configured  storefront.local:4200
    Origin      http://storefront.local:4200      -> no match

`storefront.local:4200` nevertheless LOOKED like it worked, because
`storefront.local` is in `domains` and the separate hostname fallback accepted
it. That fallback ignores the port, so port 9999 was accepted just as readily:
an administrator who wrote a port got no port restriction at all. `localhost:8000`
had no such cover and simply never matched.

Raw-string comparison also broke two cases for FULLY QUALIFIED entries, because
a browser omits a default port:

    configured  http://example.com:80
    Origin      http://example.com                -> no match

ONE ENTRY FORM: A FULL, SCHEME-EXPLICIT ORIGIN
----------------------------------------------
    https://shop.example.com
    https://shop.example.com:8443
    http://localhost:4200

Scheme, host and port must all match. The field's own contract has always said
"a full origin including scheme and port", and the scheme is part of an origin's
identity -- an https-only application must never become reachable over http
because of a permissive origin rule.

So a scheme-less `localhost:8000` is fixed by CORRECTING IT, not by guessing
what it meant. Reinterpreting it as permission for both http and https would
hand out a scheme nobody wrote, and reading it as a host rule would make
`allowed_origins` quietly as broad as `domains` -- which is the opposite of why a
second field exists. Hostname-level access is `domains`, and it stays there.

WHAT PHASE 32I ACTUALLY FIXED
-----------------------------
Canonical comparison instead of a raw string, so configuration that IS a valid
origin stops failing to match over spelling: a default port a browser omits on
the wire, a trailing slash someone pasted, scheme or host casing. Everything
that is not an origin still matches nothing, and now does so for a stated reason
rather than by accident.
"""

import unittest

import frappe
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

from yob_auth.security.access import (
    _validate_request_domain,
    get_application,
    is_origin_allowed,
)
from yob_auth.security.exceptions import YOBAccessDeniedError

APP_CODE = "ORIGINTEST"
DOMAIN = "storefront.test"


def allowed(origin: str, *entries: str) -> bool:
    """`is_origin_allowed` with the entries written as the field stores them."""

    return is_origin_allowed(origin, "\n".join(entries))


# =========================================================
# 1. FULLY QUALIFIED ENTRIES  (must keep working)
# =========================================================

class ExplicitOriginCase(unittest.TestCase):
    """Existing valid configuration. These passed before Phase 32I and must still."""

    def test_an_exact_https_origin_is_allowed(self):
        self.assertTrue(allowed("https://shop.example.com", "https://shop.example.com"))

    def test_an_exact_http_origin_is_allowed(self):
        self.assertTrue(allowed("http://shop.example.com", "http://shop.example.com"))

    def test_a_custom_port_is_allowed(self):
        self.assertTrue(allowed("http://192.168.1.25:4021", "http://192.168.1.25:4021"))

    def test_one_of_several_configured_origins_is_allowed(self):
        entries = ("https://a.example.com", "http://b.example.com:3000",
                   "http://192.168.1.25:4021")

        for origin in entries:
            with self.subTest(origin=origin):
                self.assertTrue(allowed(origin, *entries))

    def test_an_origin_not_in_the_list_is_refused(self):
        self.assertFalse(allowed("https://c.example.com",
                                 "https://a.example.com", "http://b.example.com:3000"))

    def test_case_is_irrelevant_on_both_sides(self):
        self.assertTrue(allowed("HTTPS://SHOP.EXAMPLE.COM", "https://shop.example.com"))
        self.assertTrue(allowed("https://shop.example.com", "HTTPS://Shop.Example.COM"))

    def test_a_trailing_slash_is_tolerated(self):
        """Browsers do not send one, but administrators paste URLs that have it."""

        self.assertTrue(allowed("https://shop.example.com", "https://shop.example.com/"))
        self.assertTrue(allowed("https://shop.example.com/", "https://shop.example.com"))

    # ----------------------------------------------------- default ports

    def test_a_spelled_out_default_port_equals_an_omitted_one(self):
        """REGRESSION (32I). A browser omits :80 and :443; configuration may not."""

        self.assertTrue(allowed("http://example.com", "http://example.com:80"))
        self.assertTrue(allowed("http://example.com:80", "http://example.com"))
        self.assertTrue(allowed("https://example.com", "https://example.com:443"))
        self.assertTrue(allowed("https://example.com:443", "https://example.com"))

    def test_a_default_port_of_the_other_scheme_is_not_equivalent(self):
        """443 is only https's default; it is an ordinary port under http."""

        self.assertFalse(allowed("http://example.com", "http://example.com:443"))
        self.assertFalse(allowed("https://example.com", "https://example.com:80"))


# =========================================================
# 2. AN EXPLICIT SCHEME IS BINDING
# =========================================================

class ExplicitSchemeIsEnforcedCase(unittest.TestCase):
    """If configuration names a scheme, the request must use that scheme.

    The single most important assertion here: downgrading an https-only
    application to http must never be allowed by an origin rule.
    """

    def test_an_https_entry_refuses_http(self):
        self.assertFalse(allowed("http://shop.example.com", "https://shop.example.com"))

    def test_an_http_entry_refuses_https(self):
        self.assertFalse(allowed("https://shop.example.com", "http://shop.example.com"))

    def test_the_https_entry_still_allows_https(self):
        """The other half -- proving the rejection above is about the scheme."""

        self.assertTrue(allowed("https://shop.example.com", "https://shop.example.com"))

    def test_an_invalid_entry_beside_a_valid_one_changes_nothing(self):
        """A junk line must neither grant anything nor disable the good entry."""

        entries = ("https://shop.example.com", "localhost:8000", "*.example.com")

        self.assertTrue(allowed("https://shop.example.com", *entries))
        self.assertFalse(allowed("http://shop.example.com", *entries))
        self.assertFalse(allowed("http://localhost:8000", *entries))


# =========================================================
# 3. SCHEME-LESS ENTRIES MATCH NOTHING  (the approved policy)
# =========================================================

class SchemeLessEntryIsRefusedCase(unittest.TestCase):
    """A `host:port` line is not an origin, and is not guessed at.

    These are the two values a real site actually had. They were invalid
    configuration; Phase 32I's answer is that they stay invalid and get
    corrected, rather than being reinterpreted into a scheme.
    """

    def test_the_legacy_dev_entry_matches_nothing(self):
        for origin in ("http://storefront.local:4200", "https://storefront.local:4200"):
            with self.subTest(origin=origin):
                self.assertFalse(allowed(origin, "storefront.local:4200"))

    def test_the_legacy_localhost_entry_matches_nothing(self):
        for origin in ("http://localhost:8000", "https://localhost:8000"):
            with self.subTest(origin=origin):
                self.assertFalse(allowed(origin, "localhost:8000"))

    def test_no_scheme_is_inferred_in_either_direction(self):
        """Neither http nor https is assumed -- the point of the decision."""

        self.assertFalse(allowed("http://localhost:8000", "localhost:8000"))
        self.assertFalse(allowed("https://localhost:8000", "localhost:8000"))

    def test_the_explicit_form_of_the_same_value_does_match(self):
        """The corrected configuration, so the refusals above are about FORM."""

        self.assertTrue(allowed("http://localhost:8000", "http://localhost:8000"))
        self.assertTrue(allowed("http://storefront.local:4200",
                                "http://storefront.local:4200"))

    def test_the_corrected_entry_still_binds_the_scheme(self):
        self.assertFalse(allowed("https://localhost:8000", "http://localhost:8000"))

    def test_the_corrected_entry_still_binds_the_port(self):
        self.assertFalse(allowed("http://localhost:8001", "http://localhost:8000"))

    def test_a_scheme_less_entry_does_not_help_a_host_in_domains(self):
        """It contributes nothing even where the host is otherwise known.

        `domains` may still admit the host through its own fallback -- that is a
        separate rule, asserted in HostnameFallbackCase -- but the entry itself
        adds no origin.
        """

        self.assertFalse(allowed("http://storefront.local:4200",
                                 "storefront.local:4200", "storefront.local"))

    def test_an_authority_shaped_value_with_a_bad_port_matches_nothing(self):
        for entry in ("localhost:", ":8000", "localhost:notaport", "//localhost:8000"):
            with self.subTest(entry=entry):
                self.assertFalse(allowed("http://localhost:8000", entry))

    def test_an_explicit_ipv6_origin_matches_and_binds_its_port(self):
        self.assertTrue(allowed("http://[::1]:8000", "http://[::1]:8000"))
        self.assertFalse(allowed("http://[::1]:8001", "http://[::1]:8000"))
        self.assertFalse(allowed("http://[::1]:8000", "[::1]:8000"))


# =========================================================
# 4. SECURITY -- NOTHING MAY BE LOOSER THAN BEFORE
# =========================================================

class OriginSpoofingCase(unittest.TestCase):
    """Exact host comparison, never a substring test."""

    def test_a_prefixed_hostname_is_refused(self):
        self.assertFalse(allowed("http://evil-localhost:8000", "localhost:8000"))
        self.assertFalse(allowed("https://evil-example.com", "https://example.com"))

    def test_a_suffixed_hostname_is_refused(self):
        self.assertFalse(allowed("http://localhost.attacker.test:8000", "localhost:8000"))
        self.assertFalse(allowed("https://example.com.attacker.test", "https://example.com"))

    def test_a_subdomain_is_refused(self):
        self.assertFalse(allowed("http://evil.localhost:8000", "localhost:8000"))
        self.assertFalse(allowed("https://sub.example.com", "https://example.com"))

    def test_a_parent_domain_is_refused(self):
        self.assertFalse(allowed("https://example.com", "https://sub.example.com"))

    def test_a_loopback_literal_is_not_localhost(self):
        """No host equivalence is invented; `localhost` and 127.0.0.1 differ."""

        self.assertFalse(allowed("http://127.0.0.1:8000", "localhost:8000"))
        self.assertFalse(allowed("http://localhost:8000", "127.0.0.1:8000"))

    def test_no_wildcard_syntax_is_honoured(self):
        """Wildcards were never supported and this phase did not add them."""

        for entry in ("*", "*.example.com", "https://*.example.com", "*://example.com"):
            with self.subTest(entry=entry):
                self.assertFalse(allowed("https://sub.example.com", entry))
                self.assertFalse(allowed("https://example.com", entry))

    def test_an_origin_carrying_a_path_is_refused(self):
        """An origin has no path, so anything with one is not an origin."""

        self.assertFalse(allowed("https://example.com/app", "https://example.com"))
        self.assertFalse(allowed("https://example.com/app", "https://example.com/app"))

    def test_an_origin_carrying_a_query_or_fragment_is_refused(self):
        self.assertFalse(allowed("https://example.com?a=1", "https://example.com"))
        self.assertFalse(allowed("https://example.com#x", "https://example.com"))


class MalformedInputCase(unittest.TestCase):
    """Everything uninterpretable fails closed, on both sides."""

    def test_a_malformed_origin_matches_nothing(self):
        for origin in ("garbage", "://x", "http://", "ftp://example.com",
                       "http://h:notaport", " ", "example.com"):
            with self.subTest(origin=origin):
                self.assertFalse(allowed(origin, "https://example.com",
                                         "localhost:8000", "example.com"))

    def test_an_absent_origin_matches_nothing(self):
        self.assertFalse(allowed("", "https://example.com"))
        self.assertFalse(is_origin_allowed(None, "https://example.com"))

    def test_the_literal_null_origin_matches_nothing(self):
        """A sandboxed iframe sends `null`; it is never an allowed origin.

        `get_request_origin()` already maps it to "" upstream, so the request
        then takes the "no Origin to verify" path rather than this one -- which
        is why this asserts the matcher, not the endpoint.
        """

        self.assertFalse(allowed("null", "https://example.com", "localhost:8000"))

    def test_a_malformed_entry_matches_nothing(self):
        for entry in ("storefront.local", "https://example.com/app", "*.example.com",
                      "http://h:notaport", "//x", "ftp://example.com", "::1",
                      "localhost:", ":8000"):
            with self.subTest(entry=entry):
                for origin in ("http://storefront.local:4200", "https://example.com",
                               "http://example.com", "http://localhost:8000"):
                    self.assertFalse(allowed(origin, entry),
                                     f"entry {entry!r} matched {origin!r}")

    def test_an_empty_configuration_matches_nothing(self):
        self.assertFalse(is_origin_allowed("https://example.com", None))
        self.assertFalse(is_origin_allowed("https://example.com", ""))
        self.assertFalse(is_origin_allowed("https://example.com", "\n  \n"))

    def test_a_bare_hostname_entry_is_refused_by_design(self):
        """`domains` is the host-level field; this one is not.

        Asserted explicitly because it is the one case where "fails closed"
        might look like an oversight rather than a decision.
        """

        self.assertFalse(allowed("http://storefront.local:4200", "storefront.local"))
        self.assertFalse(allowed("http://storefront.local", "storefront.local"))
        self.assertFalse(allowed("https://storefront.local", "storefront.local"))

    def test_an_ftp_or_other_scheme_entry_matches_nothing(self):
        """Only http and https are browser origin schemes."""

        for entry in ("ftp://example.com", "file://example.com", "ws://example.com"):
            with self.subTest(entry=entry):
                self.assertFalse(allowed("https://example.com", entry))
                self.assertFalse(allowed("http://example.com", entry))


# =========================================================
# 5. THE HOSTNAME FALLBACK IS A SEPARATE RULE
# =========================================================

class HostnameFallbackCase(unittest.TestCase):
    """`domains` is a HOST rule and stays one; it is not an origin rule.

    Tested through the real `_validate_request_domain` rather than the matcher,
    because the fallback lives there and conflating the two is exactly how the
    port in `storefront.local:4200` came to mean nothing.
    """

    @classmethod
    def setUpClass(cls):
        if frappe.db.exists("YOB Application", APP_CODE):
            frappe.delete_doc("YOB Application", APP_CODE, force=True,
                              ignore_permissions=True)
        frappe.get_doc({
            "doctype": "YOB Application", "application_code": APP_CODE,
            "application_name": "Origin Test App", "enabled": 1,
            "domains": DOMAIN, "allowed_origins": "",
        }).insert(ignore_permissions=True)
        frappe.db.commit()

    @classmethod
    def tearDownClass(cls):
        frappe.delete_doc("YOB Application", APP_CODE, force=True, ignore_permissions=True)
        frappe.db.commit()

    def tearDown(self):
        frappe.local.request = None

    def configure(self, allowed_origins: str):
        frappe.db.set_value("YOB Application", APP_CODE, "allowed_origins", allowed_origins)
        frappe.clear_cache()

    def request(self, origin: str | None):
        headers = {"X-YOB-Original-Host": DOMAIN}
        if origin is not None:
            headers["Origin"] = origin
        frappe.local.request = Request(EnvironBuilder(headers=headers).get_environ())
        return get_application(APP_CODE, validate_domain=False)

    def test_the_fallback_allows_any_port_on_a_configured_domain(self):
        """Unchanged by this phase, and the reason a port needs its own rule."""

        self.configure("")

        for origin in (f"http://{DOMAIN}", f"http://{DOMAIN}:4200",
                       f"https://{DOMAIN}:9999"):
            with self.subTest(origin=origin):
                _validate_request_domain(self.request(origin))  # must not raise

    def test_the_fallback_refuses_a_host_that_is_not_a_domain(self):
        self.configure("")

        with self.assertRaises(YOBAccessDeniedError):
            _validate_request_domain(self.request("http://attacker.test:4200"))

    def test_an_allowed_origin_admits_a_host_the_domains_do_not(self):
        """What `allowed_origins` is FOR: a dev server on another host."""

        self.configure("http://localhost:4200")

        _validate_request_domain(self.request("http://localhost:4200"))

        with self.assertRaises(YOBAccessDeniedError):
            _validate_request_domain(self.request("http://localhost:4201"))

    def test_a_scheme_less_entry_admits_nothing_end_to_end(self):
        """The legacy configuration, through the real check: it grants nothing.

        The host is not in `domains` either, so there is no fallback to mask the
        refusal -- which is exactly the state `localhost:8000` was really in.
        """

        self.configure("localhost:8000")

        for origin in ("http://localhost:8000", "https://localhost:8000"):
            with self.subTest(origin=origin):
                with self.assertRaises(YOBAccessDeniedError):
                    _validate_request_domain(self.request(origin))

    def test_the_corrected_explicit_entry_admits_it_end_to_end(self):
        """And the fix an administrator should apply instead."""

        self.configure("http://localhost:8000")

        _validate_request_domain(self.request("http://localhost:8000"))

        with self.assertRaises(YOBAccessDeniedError):
            _validate_request_domain(self.request("https://localhost:8000"))
        with self.assertRaises(YOBAccessDeniedError):
            _validate_request_domain(self.request("http://localhost:8001"))

    def test_an_absent_origin_is_still_accepted(self):
        """Non-browser callers and same-origin GETs send none."""

        self.configure("")
        _validate_request_domain(self.request(None))

    def test_a_null_origin_is_treated_as_absent(self):
        """Pre-existing behaviour, pinned so this phase cannot be blamed for it.

        `get_request_origin()` maps `null` to "", so the origin check is skipped
        and only the host rule applies. Worth recording explicitly: `null` is
        NOT rejected.
        """

        self.configure("")
        _validate_request_domain(self.request("null"))

    def test_a_malformed_origin_is_refused_when_the_host_is_not_a_domain(self):
        self.configure("http://localhost:4200")
        frappe.local.request = Request(EnvironBuilder(headers={
            "X-YOB-Original-Host": DOMAIN, "Origin": "garbage",
        }).get_environ())

        with self.assertRaises(YOBAccessDeniedError):
            _validate_request_domain(get_application(APP_CODE, validate_domain=False))

    def test_an_empty_domains_list_skips_the_whole_check(self):
        """Pre-existing short-circuit, pinned so it is not mistaken for a bug."""

        frappe.db.set_value("YOB Application", APP_CODE, "domains", "")
        frappe.clear_cache()
        try:
            _validate_request_domain(self.request("http://attacker.test"))
        finally:
            frappe.db.set_value("YOB Application", APP_CODE, "domains", DOMAIN)
            frappe.clear_cache()


if __name__ == "__main__":
    unittest.main()
