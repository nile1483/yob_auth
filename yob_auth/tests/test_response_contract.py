# Copyright (c) 2026, YOB and Shayona
"""Public API response-contract tests for yob_auth.

The envelope helpers themselves are tested once, in
``yob_core.tests.test_response_envelope`` -- this app re-exports them rather
than owning a second copy. What remains here is what yob_auth actually owns:
its own stable error codes, the auth exception-to-envelope mapping, and proof
that every whitelisted endpoint in the app answers through the shared helpers.

The static scans are driven by ``yob_core.testing.api_contract``.
"""

import pathlib
import unittest

from yob_core.testing.api_contract import APIContractChecker

from yob_auth.api import response as auth_response

APP_ROOT = pathlib.Path(__file__).resolve().parents[1]

CHECKER = APIContractChecker(app_root=APP_ROOT, response_module=auth_response)


class TestSharedHelperIsSingleSourced(unittest.TestCase):
    """Neither app may fork its own copy of the generic helpers."""

    GENERIC = ("success_response", "error_response", "errors_response",
               "build_error", "is_error", "server_error", "set_status")

    def test_auth_reexports_the_core_objects(self):
        from yob_core.api import response as core_response

        for name in self.GENERIC:
            self.assertIs(
                getattr(auth_response, name),
                getattr(core_response, name),
                f"{name} is not the shared yob_core implementation",
            )

    def test_storefront_reexports_the_same_objects(self):
        try:
            from yob_storefront.api import response as storefront_response
        except ImportError:
            self.skipTest("yob_storefront is not installed on this site")

        from yob_core.api import response as core_response

        for name in self.GENERIC:
            self.assertIs(
                getattr(storefront_response, name),
                getattr(core_response, name),
                f"{name} is not the shared yob_core implementation",
            )


class TestErrorCodes(unittest.TestCase):
    def test_every_visible_code_is_lowercase_snake_case(self):
        offenders = CHECKER.error_code_offenders()
        self.assertEqual(
            offenders,
            [],
            "error codes must be lowercase snake_case:\n" + "\n".join(offenders),
        )

    def test_auth_domain_codes_keep_their_published_values(self):
        """Renaming any of these silently breaks every deployed client."""

        self.assertEqual(auth_response.INVALID_CREDENTIALS, "invalid_credentials")
        self.assertEqual(auth_response.APPLICATION_ACCESS_DENIED, "application_access_denied")
        self.assertEqual(auth_response.LOGIN_METHOD_DISABLED, "login_method_disabled")
        self.assertEqual(auth_response.OTP_INVALID, "otp_invalid")

    def test_generic_codes_remain_importable_from_here(self):
        """Existing callers import these from yob_auth; that must keep working."""

        self.assertEqual(auth_response.VALIDATION_FAILED, "validation_failed")
        self.assertEqual(auth_response.AUTHENTICATION_REQUIRED, "authentication_required")
        self.assertEqual(auth_response.RATE_LIMIT_EXCEEDED, "rate_limit_exceeded")
        self.assertEqual(auth_response.INTERNAL_SERVER_ERROR, "internal_server_error")
        self.assertEqual(auth_response.HTTP_UNPROCESSABLE, 422)


class TestAuthExceptionMapping(unittest.TestCase):
    """``envelope_yob_errors`` stays in yob_auth and keeps its mapping."""

    def test_module_still_owns_the_mapping(self):
        self.assertTrue(callable(auth_response.envelope_yob_errors))

    def test_each_refusal_maps_to_its_documented_code_and_status(self):
        import frappe

        from yob_auth.security.exceptions import (
            YOBAccessDeniedError,
            YOBAuthenticationError,
            YOBRateLimitError,
        )

        cases = (
            (YOBRateLimitError, "rate_limit_exceeded", 429),
            (YOBAccessDeniedError, "application_access_denied", 403),
            (YOBAuthenticationError, "authentication_required", 401),
        )

        previous = frappe.local.response.get("http_status_code")
        try:
            for exception, code, status in cases:
                @auth_response.envelope_yob_errors
                def endpoint():
                    raise exception("refused")

                body = endpoint()
                self.assertEqual(body["errors"][0]["code"], code)
                self.assertNotIn("data", body)
                self.assertEqual(frappe.local.response.get("http_status_code"), status)
        finally:
            if previous is None:
                frappe.local.response.pop("http_status_code", None)
            else:
                frappe.local.response["http_status_code"] = previous

    def test_unknown_exceptions_still_escape(self):
        """They must reach Frappe so it answers 500 and logs a traceback."""

        @auth_response.envelope_yob_errors
        def endpoint():
            raise KeyError("boom")

        with self.assertRaises(KeyError):
            endpoint()


class TestEndpointsUseTheContract(unittest.TestCase):
    def test_every_whitelisted_endpoint_returns_a_standard_envelope(self):
        offenders = CHECKER.envelope_offenders()
        self.assertEqual(
            offenders,
            [],
            "endpoints must answer through the response helpers:\n" + "\n".join(offenders),
        )

    def test_no_endpoint_returns_the_legacy_shape(self):
        offenders = CHECKER.legacy_shape_offenders()
        self.assertEqual(
            offenders, [], "legacy response shape survives:\n" + "\n".join(offenders)
        )

    def test_no_endpoint_can_leak_a_traceback(self):
        offenders = CHECKER.traceback_leak_offenders()
        self.assertEqual(
            offenders, [], "tracebacks must never be returned:\n" + "\n".join(offenders)
        )
