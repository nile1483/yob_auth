from functools import wraps

import frappe

from yob_auth.security.access import get_current_context


def require_application(application_code: str, *, profile_doctype: str | None = None):
    """Authorize the active Frappe session for one YOB application.

    The context is always generated server-side. Any HTTP-supplied
    ``auth_context`` value is removed and overwritten.

    Authorization failures are returned as the standard error envelope rather
    than escaping as a raw Frappe ``exc_type`` body -- see
    ``yob_auth.api.response.envelope_yob_errors``, which also preserves the
    transaction rollback that raising used to provide.
    """

    from yob_auth.api.response import envelope_yob_errors

    def decorator(fn):
        @wraps(fn)
        @envelope_yob_errors
        def wrapped(*args, **kwargs):
            # Never allow Frappe request binding to inject an authorization context.
            form_dict = getattr(frappe.local, "form_dict", None)
            if form_dict is not None:
                form_dict.pop("auth_context", None)
            kwargs.pop("auth_context", None)

            context = get_current_context(application_code)
            if profile_doctype and context.profile_doctype != profile_doctype:
                from yob_auth.security.exceptions import YOBAccessDeniedError

                raise YOBAccessDeniedError(f"{profile_doctype} profile is required")

            kwargs["auth_context"] = context
            return fn(*args, **kwargs)

        return wrapped

    return decorator
