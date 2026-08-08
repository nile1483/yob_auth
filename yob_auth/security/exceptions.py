import frappe


class YOBAuditableError(Exception):
    """Mixin carrying what an audit row needs about a refusal.

    The audit row cannot be written where the refusal happens: the response
    layer rolls the transaction back before answering, which would discard it.
    So the details ride on the exception and are logged after the rollback -- see
    ``yob_auth.api.response.envelope_yob_errors``.
    """

    def __init__(self, message, *, application=None, audit_detail=None):
        super().__init__(message)
        self.application = application
        self.audit_detail = audit_detail


class YOBAuthenticationError(YOBAuditableError, frappe.AuthenticationError):
    http_status_code = 401


class YOBAccessDeniedError(YOBAuditableError, frappe.PermissionError):
    http_status_code = 403


class YOBRateLimitError(frappe.ValidationError):
    """Too many attempts. Kept distinct from YOBAuthenticationError so that a
    throttled caller answers 429 instead of 401."""

    http_status_code = 429
