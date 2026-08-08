import json
import frappe

from yob_auth.security.request import get_trusted_client_ip


def mask_identifier(value: str | None) -> str:
    value = (value or "").strip()
    if "@" in value:
        local, domain = value.split("@", 1)
        return f"{local[:2]}***@{domain}"
    digits = "".join(ch for ch in value if ch.isdigit())
    return f"***{digits[-4:]}" if digits else "***"


def log_event(event, status, *, user=None, application=None, method=None, identifier=None, reference=None, details=None):
    try:
        req = getattr(frappe.local, "request", None)
        doc = frappe.get_doc({
            "doctype": "YOB Auth Log",
            "event": event,
            "status": status,
            "user": user,
            "application": application,
            "method": method,
            "identifier_masked": mask_identifier(identifier),
            "ip_address": get_trusted_client_ip(),
            "user_agent": (req.headers.get("User-Agent", "")[:500] if req else ""),
            "reference": reference,
            "details": json.dumps(details, default=str)[:1000] if isinstance(details, (dict, list)) else str(details or "")[:1000],
        })
        doc.insert(ignore_permissions=True)
    except Exception:
        frappe.log_error(frappe.get_traceback(), "YOB Auth audit logging failed")
