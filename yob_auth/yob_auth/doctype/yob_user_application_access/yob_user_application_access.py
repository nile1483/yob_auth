import frappe
from frappe.model.document import Document
from frappe.utils import get_datetime


class YOBUserApplicationAccess(Document):
    def validate(self):
        if self.valid_from and self.valid_until and get_datetime(self.valid_until) <= get_datetime(self.valid_from):
            frappe.throw("Valid Until must be later than Valid From")
        duplicate = frappe.db.exists(
            "YOB User Application Access",
            {"user": self.user, "application": self.application, "name": ["!=", self.name]},
        )
        if duplicate:
            frappe.throw("This user already has an access record for the selected application")
