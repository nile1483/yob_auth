# Copyright (c) 2026, YOB and Shayona
# path: apps/yob_auth/yob_auth/api/response.py
"""Authentication's view of the shared YOB public API response envelope.

The generic implementation now lives in ``yob_core``:

    yob_core.api.http      HTTP status constants
    yob_core.api.errors    platform-wide stable error codes
    yob_core.api.response  set_status / success_response / build_error /
                           error_response / errors_response / is_error /
                           server_error

They are re-exported below so that existing imports such as::

    from yob_auth.api.response import success_response

keep working unchanged. Do not add a second implementation here -- import from
``yob_core`` instead, or the two copies will drift and clients will see two
different envelopes.

What this module still *owns* is the authentication domain:

* the auth-specific stable error codes, and
* ``envelope_yob_errors``, which translates raised YOB authorization failures
  into the standard envelope and writes the refusal audit row.

That translation cannot move into ``yob_core``: it depends on
``yob_auth.security.exceptions`` and ``yob_auth.security.audit``, and core must
never import an app above it.
"""

import frappe

from yob_core.api.errors import (  # noqa: F401  (re-exported API)
    AUTHENTICATION_REQUIRED,
    INTERNAL_SERVER_ERROR,
    RATE_LIMIT_EXCEEDED,
    VALIDATION_FAILED,
)
from yob_core.api.http import (  # noqa: F401  (re-exported API)
    HTTP_BAD_REQUEST,
    HTTP_CONFLICT,
    HTTP_CREATED,
    HTTP_FORBIDDEN,
    HTTP_INTERNAL_SERVER_ERROR,
    HTTP_NOT_FOUND,
    HTTP_OK,
    HTTP_TOO_MANY_REQUESTS,
    HTTP_UNAUTHORIZED,
    HTTP_UNPROCESSABLE,
)
from yob_core.api.response import (  # noqa: F401  (re-exported API)
    build_error,
    error_response,
    errors_response,
    is_error,
    server_error,
    set_status,
    success_response,
)

# ---------------------------------------------------------
# AUTHENTICATION STABLE ERROR CODES
# ---------------------------------------------------------
# Machine-readable, lowercase snake_case and stable across releases. These name
# reasons that only the authentication domain can produce; the transport-level
# refusals every app shares (authentication_required, rate_limit_exceeded) come
# from yob_core.api.errors above.

INVALID_CREDENTIALS = "invalid_credentials"
APPLICATION_ACCESS_DENIED = "application_access_denied"
LOGIN_METHOD_DISABLED = "login_method_disabled"
OTP_INVALID = "otp_invalid"


# ---------------------------------------------------------
# AUTH EXCEPTION -> ENVELOPE
# ---------------------------------------------------------

def envelope_yob_errors(fn):
    """Return raised YOB authorization failures as the standard envelope.

    These failures are *raised* rather than returned so that the transaction is
    rolled back and a partial write can never be answered with 200. That is
    correct, but it also means Frappe renders its own ``exc_type`` body, so the
    documented ``errors[]`` shape applied only to the paths that happened to use
    ``return``.

    The rollback is preserved explicitly below, because catching the exception
    stops Frappe from doing it. Unknown exceptions are deliberately not caught:
    they must keep escaping so Frappe answers 500 and logs a traceback.
    """

    from functools import wraps

    from yob_auth.security.exceptions import (
        YOBAccessDeniedError,
        YOBAuthenticationError,
        YOBRateLimitError,
    )

    mapping = (
        (YOBRateLimitError, RATE_LIMIT_EXCEEDED, HTTP_TOO_MANY_REQUESTS),
        (YOBAccessDeniedError, APPLICATION_ACCESS_DENIED, HTTP_FORBIDDEN),
        (YOBAuthenticationError, AUTHENTICATION_REQUIRED, HTTP_UNAUTHORIZED),
    )

    @wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except tuple(exc for exc, _, _ in mapping) as caught:
            frappe.db.rollback()
            # Only after the rollback, or the row would be discarded with it.
            # Returning (rather than re-raising) means Frappe commits normally,
            # so this insert survives.
            _log_refusal(caught)
            for exc_type, code, status in mapping:
                if isinstance(caught, exc_type):
                    return error_response(code, str(caught), status_code=status)
            raise  # unreachable; keeps the intent explicit

    return wrapped


def _log_refusal(exc):
    """Record a refused request. Never let auditing break the response."""

    detail = getattr(exc, "audit_detail", None)
    if not detail:
        return

    try:
        from yob_auth.security.audit import log_event

        log_event(
            "Access Denied", "Failed",
            application=getattr(exc, "application", None),
            details=detail,
        )
    except Exception:
        frappe.log_error(frappe.get_traceback(), "YOB Auth refusal logging failed")
