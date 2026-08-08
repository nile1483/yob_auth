import frappe
from frappe.model.document import Document

from yob_auth.security.otp import normalize_mobile


class YOBLoginIdentity(Document):
    def validate(self):
        if self.identity_type == "Mobile":
            self.normalized_value = normalize_mobile(self.normalized_value)
        elif self.identity_type == "Email":
            self.normalized_value = (self.normalized_value or "").strip().lower()
