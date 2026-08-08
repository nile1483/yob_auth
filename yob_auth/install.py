import secrets

import frappe
from frappe.installer import update_site_config


def after_install():
    _ensure_settings()
    _ensure_otp_secret()
    _report_deployment_requirements()


def _report_deployment_requirements():
    """Tell the installer what yob_auth cannot configure for itself.

    Two controls depend on the reverse proxy, which an installable app has no
    way to set up. Printing the check here means a fresh install starts with the
    gaps visible rather than discovered later.
    """

    try:
        from yob_auth.setup import check_configuration

        check_configuration()
    except Exception:
        # Never let a diagnostic abort an install.
        print("yob_auth: deployment check could not run; "
              "run `bench --site <site> execute yob_auth.setup.check_configuration`")


def _ensure_settings():
    if frappe.db.exists("YOB Auth Settings", "YOB Auth Settings"):
        return

    doc = frappe.new_doc("YOB Auth Settings")
    doc.password_login_enabled = 1
    doc.password_rate_window_seconds = 300
    doc.max_password_attempts_per_window = 10
    doc.max_password_attempts_per_ip_window = 50
    doc.email_otp_enabled = 1
    doc.mobile_otp_enabled = 0
    doc.otp_length = 6
    doc.otp_expiry_seconds = 300
    doc.otp_resend_seconds = 60
    doc.max_otp_attempts = 5
    doc.max_otp_requests_per_hour = 8
    doc.insert(ignore_permissions=True)


def _ensure_otp_secret():
    """Generate the persistent OTP signing secret if it is not configured.

    ``security.otp`` refuses to run without ``yob_auth_otp_secret`` (minimum 32
    characters) and deliberately has no fallback, so on a fresh install the
    first OTP request would throw. Generating it here keeps the secret
    persistent across restarts without weakening that requirement.

    An existing value is never overwritten: rotating the secret invalidates
    every in-flight OTP challenge.
    """

    if str(frappe.conf.get("yob_auth_otp_secret") or "").strip():
        return

    update_site_config("yob_auth_otp_secret", secrets.token_hex(32))
    print("yob_auth: generated yob_auth_otp_secret in site_config.json")
