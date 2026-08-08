import frappe
from frappe.sessions import get_csrf_token
from frappe.utils import cint

# Auth-owned names come from this app; the generic envelope comes from yob_core
# directly. yob_auth.api.response still re-exports the generics for external
# callers, but this app's own modules import them from where they live.
from yob_auth.api.response import (
    APPLICATION_ACCESS_DENIED,
    INVALID_CREDENTIALS,
    LOGIN_METHOD_DISABLED,
    OTP_INVALID,
    envelope_yob_errors,
)
from yob_auth.security.access import get_application, resolve_access, validate_login_method
from yob_auth.security.audit import log_event
from yob_auth.security.exceptions import (
    YOBAccessDeniedError,
    YOBAuthenticationError,
    YOBRateLimitError,
)
from yob_auth.security.otp import request_otp as create_otp, verify_otp as consume_otp
from yob_auth.security.rate_limit import enforce_password_attempt_limits
from yob_auth.security.session import create_frappe_session
from yob_core.api.errors import RATE_LIMIT_EXCEEDED
from yob_core.api.http import (
    HTTP_FORBIDDEN,
    HTTP_TOO_MANY_REQUESTS,
    HTTP_UNAUTHORIZED,
    HTTP_UNPROCESSABLE,
)
from yob_core.api.response import error_response, success_response


def _settings():
    return frappe.get_single("YOB Auth Settings")


def _auth_payload(context, authentication_method):
    """Build the ``data`` payload shared by every authenticated response.

    Frappe's own login response keys (``home_page``, ``full_name``) are set by
    ``login_manager.post_login()`` directly on ``frappe.local.response`` and
    therefore stay at the TOP level of the JSON, next to ``message``. Nothing
    here touches them.
    """

    user = frappe.db.get_value("User", context.user, ["full_name", "user_image", "email", "mobile_no"], as_dict=True)
    return {
        "authenticated": True,
        "authentication_method": authentication_method,
        "user": {"name": context.user, **(user or {})},
        # Only the context fields a storefront UI renders. `roles` and `company`
        # are deliberately withheld: the role list describes internal
        # authorization structure, and `company` names the business operating
        # the storefront. Authorization is re-decided server-side on every
        # request by require_application(), so the client needs neither -- and
        # a client that cannot see them cannot be tempted to branch on them.
        "context": {
            "application": context.application,
            "profile_doctype": context.profile_doctype,
            "profile_name": context.profile_name,
        },
        # Frappe generates the CSRF token lazily. Reading
        # frappe.session.data.csrf_token directly returns None on a fresh login
        # because nothing has triggered generation yet, which silently broke the
        # documented client contract.
        "csrf_token": get_csrf_token(),
    }


@frappe.whitelist(allow_guest=True, methods=["POST"] )
@envelope_yob_errors
def login_with_password(application: str, username: str, password: str):
    settings = _settings()
    if not cint(settings.password_login_enabled):
        return error_response(
            LOGIN_METHOD_DISABLED,
            "Password login is disabled.",
            status_code=HTTP_UNPROCESSABLE,
        )
    app = get_application(application)
    validate_login_method(app, "password")
    try:
        enforce_password_attempt_limits(username, settings)
    except YOBRateLimitError as exc:
        return error_response(RATE_LIMIT_EXCEEDED, str(exc), status_code=HTTP_TOO_MANY_REQUESTS)
    manager = frappe.local.login_manager
    try:
        manager.authenticate(user=username, pwd=password)
        context = resolve_access(manager.user, app.name, validate_domain=False)
        manager.post_login()
    except YOBAccessDeniedError as exc:
        log_event("Login", "Failed", application=app.name, method="password", identifier=username)
        return error_response(APPLICATION_ACCESS_DENIED, str(exc), status_code=HTTP_FORBIDDEN)
    except frappe.AuthenticationError:
        log_event("Login", "Failed", application=app.name, method="password", identifier=username)
        return error_response(
            INVALID_CREDENTIALS,
            "Invalid login credentials.",
            status_code=HTTP_UNAUTHORIZED,
        )
    except frappe.SecurityException as exc:
        # Frappe's own consecutive-failure lockout (System Settings ->
        # allow_consecutive_login_attempts / allow_login_after_fail). A locked
        # account is an expected outcome, not a server fault -- but
        # SecurityException is NOT a subclass of AuthenticationError, so without
        # this clause it falls through to `except Exception` and the caller gets
        # HTTP 500 with a raw exception body on a perfectly ordinary path
        # (someone mistyping their password ten times).
        log_event(
            "Login", "Failed", application=app.name, method="password",
            identifier=username, details="Locked by Frappe login attempt tracker",
        )
        return error_response(RATE_LIMIT_EXCEEDED, str(exc), status_code=HTTP_TOO_MANY_REQUESTS)
    except Exception:
        # Unknown failures stay unknown: re-raise so Frappe answers 500.
        log_event("Login", "Failed", application=app.name, method="password", identifier=username)
        raise
    log_event("Login", "Success", user=context.user, application=context.application, method="password", identifier=username)
    return success_response(_auth_payload(context, "password"), notice="Login successful.")


@frappe.whitelist(allow_guest=True, methods=["POST"] )
@envelope_yob_errors
def request_otp(application: str, identifier: str, method: str):
    app = get_application(application)
    validate_login_method(app, method)
    try:
        result = create_otp(identifier, method, app.name)
    except YOBRateLimitError as exc:
        return error_response(RATE_LIMIT_EXCEEDED, str(exc), status_code=HTTP_TOO_MANY_REQUESTS)
    except YOBAuthenticationError as exc:
        return error_response(LOGIN_METHOD_DISABLED, str(exc), status_code=HTTP_UNPROCESSABLE)
    # The generic "if the account is eligible..." text is a notice, not data:
    # it must never let a client infer whether the account exists.
    notice = result.pop("message", None)
    return success_response(result, notice=notice)


@frappe.whitelist(allow_guest=True, methods=["POST"] )
@envelope_yob_errors
def login_with_otp(challenge_id: str, otp: str):
    try:
        user, application, method = consume_otp(challenge_id, otp)
    except YOBRateLimitError as exc:
        return error_response(RATE_LIMIT_EXCEEDED, str(exc), status_code=HTTP_TOO_MANY_REQUESTS)
    except YOBAuthenticationError as exc:
        return error_response(OTP_INVALID, str(exc), status_code=HTTP_UNAUTHORIZED)
    app = get_application(application)
    validate_login_method(app, method)
    context = resolve_access(user, app.name, validate_domain=False)
    create_frappe_session(user)
    log_event("Login", "Success", user=user, application=application, method=method, reference=challenge_id)
    return success_response(_auth_payload(context, method), notice="Login successful.")


@frappe.whitelist(methods=["GET"] )
@envelope_yob_errors
def get_session_context(application: str):
    context = resolve_access(frappe.session.user, application)
    return success_response(_auth_payload(context, "session"))


@frappe.whitelist(methods=["POST"] )
@envelope_yob_errors
def logout():
    user = frappe.session.user
    frappe.local.login_manager.logout()
    log_event("Logout", "Success", user=user, method="session")
    return success_response({"authenticated": False}, notice="Logout successful.")
