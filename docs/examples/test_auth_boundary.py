"""Illustrative auth-context security tests; use real project factories."""

from __future__ import annotations

from frappe.tests.utils import FrappeTestCase


class TestAuthContextBoundary(FrappeTestCase):
	def test_client_context_is_never_authority(self) -> None:
		"""Call with a forged context and assert server context wins."""
		self.skipTest("Replace with the project's HTTP/test-client factory")

	def test_customer_a_cannot_request_customer_b(self) -> None:
		"""Authenticate as A, name B through legacy parameters, and expect 403."""
		self.skipTest("Replace with project Customer/access factories")
