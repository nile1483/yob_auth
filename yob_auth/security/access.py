from dataclasses import asdict, dataclass
import frappe
from frappe.utils import get_datetime, now_datetime

from yob_auth.security.exceptions import YOBAccessDeniedError, YOBAuthenticationError
from yob_auth.security.request import get_original_host, get_request_origin


@dataclass(frozen=True)
class AuthContext:
    user: str
    application: str
    profile_doctype: str | None
    profile_name: str | None
    company: str | None
    roles: list[str]

    def to_dict(self):
        return asdict(self)


def normalize_application_code(value: str) -> str:
    return (value or "").strip().upper()


def get_application(application_code: str, *, validate_domain: bool = True):
    code = normalize_application_code(application_code)
    app = frappe.db.get_value(
        "YOB Application", code,
        ["name", "application_name", "enabled", "domains", "allowed_origins", "required_profile_doctype", "required_role", "allow_password_login", "allow_email_otp", "allow_mobile_otp"],
        as_dict=True,
    )
    if not app or not app.enabled:
        # Same message for "unknown" and "disabled" so the response cannot be
        # used to enumerate which application codes exist. The code travels in
        # the detail text rather than the `application` field, because that
        # field is a Link and the code may well not exist.
        _reject(None, "Application is disabled or unavailable", detail=f"application={code}")
    if validate_domain:
        _validate_request_domain(app)
    return app


def _lines(value: str | None) -> set[str]:
    return {line.strip().lower() for line in (value or "").splitlines() if line.strip()}


def _reject(application: str | None, message: str, *, detail: str = ""):
    """Refuse the request, carrying what the audit row will need.

    Domain and origin rejections used to raise before any logging ran, so the
    single most security-relevant refusal in the system wrote nothing at all.
    The row is written by the response layer rather than here, because that
    layer rolls the transaction back before answering and would otherwise
    discard anything logged at this point.
    """

    raise YOBAccessDeniedError(
        message, application=application, audit_detail=detail or message
    )


def _validate_request_domain(app):
    """Check the calling host, and the browser-supplied Origin when present.

    The host comes from a header the edge proxy asserts, so it establishes which
    site the request arrived through. Origin is set by the browser and cannot be
    forged by page script, so it additionally establishes which site the request
    was *initiated* from -- which is what stops another site silently POSTing a
    login on a visitor's behalf.
    """

    allowed = _lines(app.domains)
    if not allowed:
        return

    host = get_original_host()
    if not host or host not in allowed:
        # No angle brackets: audit `details` is a Small Text field and Frappe
        # strips anything that parses as an HTML tag.
        _reject(
            app.name,
            "This application is not allowed from the current domain",
            detail=f"host={host or '(none)'}",
        )

    origin, origin_host = get_request_origin()
    if not origin:
        # Absent on same-origin GETs and on non-browser callers. The host check
        # above has already run, so there is nothing further to verify.
        return

    # An explicit entry wins (this is how a dev server on another port is
    # allowed); otherwise the origin's hostname must be one of the domains.
    if origin.lower() in _lines(app.allowed_origins):
        return
    if origin_host and origin_host in allowed:
        return

    _reject(
        app.name,
        "This application is not allowed from the current origin",
        detail=f"origin={origin}",
    )


def validate_login_method(app, method: str):
    field = {"password": "allow_password_login", "email_otp": "allow_email_otp", "mobile_otp": "allow_mobile_otp"}.get(method)
    if not field or not app.get(field):
        raise YOBAccessDeniedError("Selected login method is not enabled for this application")


def resolve_access(user: str, application_code: str, *, validate_domain: bool = True) -> AuthContext:
    if not user or user == "Guest":
        raise YOBAuthenticationError("Authentication required")
    # Frappe checks `enabled` when a password is verified, not on every request.
    # Without this, an account disabled mid-session keeps passing authorization
    # on every endpoint until the session happens to end.
    if not frappe.db.get_value("User", user, "enabled"):
        raise YOBAuthenticationError("Authentication required")
    app = get_application(application_code, validate_domain=validate_domain)
    row = frappe.db.get_value(
        "YOB User Application Access",
        {"user": user, "application": app.name, "enabled": 1},
        ["name", "valid_from", "valid_until", "profile_doctype", "profile_name", "company"],
        as_dict=True,
    )
    if not row:
        raise YOBAccessDeniedError("User is not authorized for this application")
    current = now_datetime()
    if row.valid_from and get_datetime(row.valid_from) > current:
        raise YOBAccessDeniedError("Application access is not active yet")
    if row.valid_until and get_datetime(row.valid_until) < current:
        raise YOBAccessDeniedError("Application access has expired")
    roles = frappe.get_roles(user)
    if app.required_role and app.required_role not in roles:
        raise YOBAccessDeniedError("Required application role is missing")
    profile_doctype = row.profile_doctype or app.required_profile_doctype
    profile_name = row.profile_name
    if app.required_profile_doctype and profile_doctype != app.required_profile_doctype:
        raise YOBAccessDeniedError("Invalid business profile type")
    if profile_doctype:
        if not profile_name or not frappe.db.exists(profile_doctype, profile_name):
            raise YOBAccessDeniedError("Required business profile is missing")
        _validate_profile(profile_doctype, profile_name, user)
    return AuthContext(user=user, application=app.name, profile_doctype=profile_doctype, profile_name=profile_name, company=row.company, roles=roles)


def _validate_profile(doctype: str, name: str, user: str):
    if doctype == "Employee":
        data = frappe.db.get_value("Employee", name, ["user_id", "status"], as_dict=True)
        if not data or data.user_id != user or data.status != "Active":
            raise YOBAccessDeniedError("Employee profile is not active or not linked to this user")

def get_current_context(application_code: str) -> AuthContext:
    return resolve_access(frappe.session.user, application_code)
