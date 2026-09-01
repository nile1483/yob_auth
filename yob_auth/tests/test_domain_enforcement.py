# Copyright (c) 2026, YOB and Shayona
"""Domain allow-list enforcement tests (CHG-002 / CHG-001 F-11).

Context: `test_tenant_isolation` previously errored on any site where the
allow-list was actually configured. The cause was the test environment, not the
control -- unit tests run with no HTTP request, so `get_original_host()` returns
"" and the check correctly fails closed. The fix is to give the tests a request,
NOT to relax the control.

These tests configure `domains` on a throwaway YOB Application so the check is
genuinely armed, then prove all three outcomes.
"""

import unittest

import frappe
from werkzeug.test import EnvironBuilder
from werkzeug.wrappers import Request

from yob_auth.security.access import _validate_request_domain, get_application
from yob_auth.security.exceptions import YOBAccessDeniedError

TRUSTED_HOST = "storefront.test"
UNAPPROVED_HOST = "attacker.test"
APP_CODE = "DOMAINTEST"


def set_request(headers: dict | None = None) -> None:
    """Install a request carrying exactly the given headers."""

    frappe.local.request = Request(EnvironBuilder(headers=headers or {}).get_environ())


class DomainEnforcementCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not frappe.db.exists("YOB Application", APP_CODE):
            frappe.get_doc({
                "doctype": "YOB Application",
                "application_code": APP_CODE,
                "application_name": "Domain Test App",
                "enabled": 1,
                "domains": TRUSTED_HOST,
            }).insert(ignore_permissions=True)
        else:
            frappe.db.set_value("YOB Application", APP_CODE, "domains", TRUSTED_HOST)
        frappe.db.commit()

    @classmethod
    def tearDownClass(cls):
        frappe.delete_doc("YOB Application", APP_CODE, force=True, ignore_permissions=True)
        frappe.db.commit()

    def tearDown(self):
        frappe.local.request = None

    def _app(self):
        # validate_domain=False so the fixture load itself is not the assertion.
        return get_application(APP_CODE, validate_domain=False)

    def test_allow_list_is_actually_armed(self):
        """Guard: an empty `domains` short-circuits the whole check."""

        self.assertEqual(
            frappe.db.get_value("YOB Application", APP_CODE, "domains"), TRUSTED_HOST
        )

    def test_trusted_host_succeeds(self):
        set_request({"X-YOB-Original-Host": TRUSTED_HOST})
        _validate_request_domain(self._app())  # must not raise

    def test_missing_host_fails_closed(self):
        """No proxy header at all -- the request never passed the edge."""

        set_request({})
        with self.assertRaises(YOBAccessDeniedError):
            _validate_request_domain(self._app())

    def test_unapproved_host_fails_closed(self):
        """A host the application does not list must be refused."""

        set_request({"X-YOB-Original-Host": UNAPPROVED_HOST})
        with self.assertRaises(YOBAccessDeniedError):
            _validate_request_domain(self._app())

    def test_host_with_port_is_normalised_not_bypassed(self):
        """`host:port` must reduce to the hostname, not sidestep the list."""

        set_request({"X-YOB-Original-Host": f"{TRUSTED_HOST}:8080"})
        _validate_request_domain(self._app())

        set_request({"X-YOB-Original-Host": f"{UNAPPROVED_HOST}:8080"})
        with self.assertRaises(YOBAccessDeniedError):
            _validate_request_domain(self._app())

    def test_no_request_at_all_fails_closed(self):
        """A background job has no request; it must not pass the host check."""

        frappe.local.request = None
        with self.assertRaises(YOBAccessDeniedError):
            _validate_request_domain(self._app())
