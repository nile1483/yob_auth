# Copyright (c) 2026, YOB and Shayona
"""Desk titles on the auth DocTypes, and what must never become one (Phase 32G).

Phase 32G changed NOTHING in `yob_auth`. This module records why, and guards the
one thing that could go wrong if a later phase revisits it: an authentication
DocType's most "identifying" field is often the most sensitive one, and a Desk
Link label is read by anyone who can open the form that holds the Link.

THE THREE CANDIDATES, AND THE VERDICTS
--------------------------------------
    YOB Application             name IS `application_code` (STOREFRONT) -- the
                                identity used in config and API calls. Already
                                the useful business identifier, so the name is
                                left as the label.
    YOB User Application Access hash-named, but `title_field = user` was already
                                set, so its list view and form heading already
                                read the user. Nothing links TO it, and
                                `show_title_field_in_link` is consulted only on
                                link-target paths, so the flag would change
                                nothing visible.
    YOB Login Identity          same: hash-named with `title_field =
                                normalized_value` already set, and no inbound
                                Link. The flag would add no display and would
                                put an email address or a phone number into link
                                labels the first time something did link to it.

So all three are KEEP: the metadata they need is already there, and the flag has
nothing to render.

WHAT IS ACTUALLY BEING GUARDED
------------------------------
`normalized_value` is acceptable as a title because it holds the normalised
email or mobile -- the intended identity -- and `YOB Login Identity` stores no
credential at all. The OTP and password controls live on `YOB Auth Settings` as
policy toggles and numeric limits, and no DocType in this app has a `Password`
field or a secret/token/hash field of any kind. `NoSecretBecomesALabelCase`
asserts that, so adding such a field later and titling on it fails loudly.
"""

import unittest

import frappe

#: Current, deliberate state: DocType -> (title_field, show_title_field_in_link).
#:
#: `None` means "no title_field", which for a readable name is correct rather
#: than missing.
EXPECTED = {
    "YOB Application": ("application_name", 0),
    "YOB User Application Access": ("user", 0),
    "YOB Login Identity": ("normalized_value", 0),
    "YOB Auth Log": (None, 0),
    "YOB Auth Settings": (None, 0),
}

#: Substrings that may never appear in a field used as a Desk title.
SECRET_WORDS = ("secret", "token", "password", "otp", "hash", "salt",
                "signature", "api_key", "private", "credential")


def _app_doctypes():
    return frappe.get_all("DocType", filters={"module": "YOB Auth"}, pluck="name")


class AuthTitleMetadataCase(unittest.TestCase):
    """The recorded verdicts, asserted against the runtime."""

    def test_auth_doctypes_keep_their_current_title_metadata(self):
        for doctype, (title_field, flag) in EXPECTED.items():
            with self.subTest(doctype=doctype):
                meta = frappe.get_meta(doctype)
                self.assertEqual(meta.title_field, title_field)
                self.assertEqual(
                    meta.show_title_field_in_link or 0, flag,
                    f"{doctype} gained show_title_field_in_link; re-check the "
                    "security review in this module's docstring first")

    def test_the_auth_log_is_never_given_a_title(self):
        """An audit record identifies itself by when and what, not by a label."""

        self.assertIsNone(frappe.get_meta("YOB Auth Log").title_field)

    def test_application_is_still_named_by_its_code(self):
        """The code is the identity config and API callers use.

        If this ever became a hash, `YOB Application` would need a title_field
        and this exclusion would no longer be valid.
        """

        self.assertEqual(
            frappe.db.get_value("DocType", "YOB Application", "autoname"),
            "field:application_code")


class NoSecretBecomesALabelCase(unittest.TestCase):
    """The guard that outlives this phase."""

    def test_no_auth_doctype_titles_on_a_secret_shaped_field(self):
        for doctype in _app_doctypes():
            meta = frappe.get_meta(doctype)
            if not meta.title_field:
                continue
            with self.subTest(doctype=doctype):
                hits = [w for w in SECRET_WORDS if w in meta.title_field.lower()]
                self.assertFalse(
                    hits, f"{doctype} titles on {meta.title_field!r} ({hits})")

    def test_no_auth_doctype_titles_on_a_password_field(self):
        """Fieldtype, not just fieldname -- a `Password` field by any name."""

        for doctype in _app_doctypes():
            meta = frappe.get_meta(doctype)
            if not meta.title_field:
                continue
            field = meta.get_field(meta.title_field)
            if not field:
                continue
            with self.subTest(doctype=doctype):
                self.assertNotEqual(field.fieldtype, "Password",
                                    f"{doctype} titles on a Password field")

    def test_login_identity_stores_no_credential_to_leak(self):
        """Why `normalized_value` is safe: there is nothing secret beside it.

        The field is PII -- an email or a phone number -- and that is exactly
        what the record is for. It is not a credential, and this DocType holds
        none.
        """

        fieldnames = [f.fieldname for f in frappe.get_meta("YOB Login Identity").fields]

        for name in fieldnames:
            hits = [w for w in SECRET_WORDS if w in name.lower()]
            self.assertFalse(hits, f"YOB Login Identity gained {name!r} ({hits})")

        self.assertIn("normalized_value", fieldnames)

    def test_the_title_field_of_login_identity_is_the_identity_value(self):
        meta = frappe.get_meta("YOB Login Identity")
        field = meta.get_field(meta.title_field)

        self.assertEqual(field.fieldtype, "Data")
        self.assertTrue(field.reqd, "a blank title would render as an empty label")


if __name__ == "__main__":
    unittest.main()
