import re
from urllib.parse import urlparse

import frappe
from frappe.model.document import Document


class YOBApplication(Document):
    def validate(self):
        self.application_code = re.sub(r"[^A-Z0-9_]+", "_", (self.application_code or "").strip().upper()).strip("_")
        if not self.application_code:
            frappe.throw("Application Code is required")
        self.domains = "\n".join(_normalize_host(row) for row in (self.domains or "").splitlines() if row.strip())


def _normalize_host(value: str) -> str:
    value = value.strip().lower()
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return (parsed.hostname or "").strip(".")
