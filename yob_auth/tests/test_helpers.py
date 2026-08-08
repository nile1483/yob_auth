import unittest
from pathlib import Path

from yob_auth.security.audit import mask_identifier
from yob_auth.security.otp import normalize_mobile


class TestHelpers(unittest.TestCase):
    def test_mobile_normalization(self):
        self.assertEqual(normalize_mobile("98765 43210"), "+919876543210")
        self.assertEqual(normalize_mobile("+91-98765-43210"), "+919876543210")

    def test_identifier_masking(self):
        self.assertEqual(mask_identifier("name@example.com"), "na***@example.com")
        self.assertEqual(mask_identifier("9876543210"), "***3210")

    def test_decorator_never_uses_setdefault_for_auth_context(self):
        source = (Path(__file__).parents[1] / "security" / "decorators.py").read_text()
        self.assertNotIn('setdefault("auth_context"', source)
        self.assertIn('kwargs["auth_context"] = context', source)

    def test_otp_has_no_public_secret_fallback(self):
        source = (Path(__file__).parents[1] / "security" / "otp.py").read_text()
        self.assertNotIn("frappe.local.site", source)
        self.assertIn("yob_auth_otp_secret", source)
