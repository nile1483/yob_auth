from dataclasses import asdict, dataclass
from urllib.parse import urlparse

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


#: Default port for each scheme a browser can send an Origin from.
#:
#: A browser OMITS the port when it is the default, so `http://example.com` and
#: `http://example.com:80` are the same origin. Comparing raw strings treated
#: them as different, which silently broke any entry written the long way.
DEFAULT_PORTS = {"http": 80, "https": 443}


def _canonical_origin(value: str) -> tuple[str, str, int] | None:
    """`(scheme, host, port)` for a full origin, or None if it is not one.

    Fails closed: an origin carries no path, query or fragment, so anything that
    does is a configuration mistake rather than a rule to interpret. A bare `/`
    is tolerated because administrators paste browser URLs.
    """

    try:
        parts = urlparse(value.strip())
    except ValueError:
        return None

    scheme = (parts.scheme or "").lower()
    if scheme not in DEFAULT_PORTS:
        return None
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.params:
        return None

    try:
        port = parts.port or DEFAULT_PORTS[scheme]
    except ValueError:  # non-numeric port
        return None

    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return None

    return scheme, host, port


def is_origin_allowed(origin: str, allowed_origins: str | None) -> bool:
    """Does the browser's Origin exactly match a configured `allowed_origins` entry?

    `allowed_origins` is SCHEME-EXPLICIT. One full browser origin per line:

        https://shop.example.com
        https://shop.example.com:8443
        http://localhost:4200

    Scheme, host and port must all match, so an `https` entry refuses the `http`
    origin of the same host. The scheme is part of an origin's identity, and an
    https-only application must never be reachable over http because of a
    permissive origin rule.

    Comparison is canonical, never a substring test -- `example.com` cannot
    match `evil-example.com` or `example.com.attacker.test` -- and the only
    things normalised are the ones that are the SAME origin by definition:
    scheme and host casing, a trailing dot on the host, a trailing slash in
    configuration, and a default port a browser omits on the wire
    (`http://x:80` == `http://x`, `https://x:443` == `https://x`).

    Anything that is not a full origin matches nothing: a scheme-less
    `host:port`, a bare hostname, a path, a query, a fragment, a wildcard, a bad
    port. A scheme-less value is NOT reinterpreted as permission for both http
    and https -- that would hand out a scheme the administrator never wrote.
    Hostname-level access is what the separate `domains` field is for.
    """

    request = _canonical_origin(origin or "")
    if not request:
        # No parseable origin, so nothing can legitimately match it. The caller
        # still runs the `domains` fallback, which fails closed on its own.
        return False

    return any(_canonical_origin(entry) == request for entry in _lines(allowed_origins))


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

    # An `allowed_origins` entry wins (this is how a dev server on another port
    # is allowed); otherwise the origin's hostname must be one of the domains.
    #
    # The two are deliberately separate rules, not one list: `allowed_origins`
    # is an ORIGIN rule and pins scheme, host and port, while the `domains`
    # fallback is a HOST rule that accepts any scheme and any port.
    #
    # Phase 32I made the first compare canonically rather than as a raw string,
    # so a default port a browser omits (`http://x:80` == `http://x`) and a
    # trailing slash in configuration stop silently failing to match. A
    # scheme-less `host:port` line still matches nothing: it is not an origin,
    # and guessing its scheme would grant one nobody configured.
    if is_origin_allowed(origin, app.allowed_origins):
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
