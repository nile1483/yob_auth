import hashlib
import hmac
import re
import secrets
import time
import uuid

import frappe
from frappe.utils import cint

from yob_auth.security.audit import log_event
from yob_auth.security.exceptions import YOBAuthenticationError
from yob_auth.security.rate_limit import enforce_otp_request_limits


def _settings():
    return frappe.get_single("YOB Auth Settings")


def _default_country_code() -> str:
    """Dialling code applied to a number entered without one.

    Configurable because guessing wrongly is not harmless: ``normalized_value``
    is unique on YOB Login Identity, so a bare foreign number silently mapped to
    the wrong country can collide with an unrelated person's identity and send
    their OTP to somebody else.
    """

    try:
        code = (frappe.get_cached_value("YOB Auth Settings", None, "default_country_code") or "").strip()
    except Exception:
        code = ""
    code = re.sub(r"\D", "", code or "91")
    return f"+{code}" if code else "+91"


def normalize_mobile(value: str) -> str:
    value = re.sub(r"[^0-9+]", "", (value or "").strip())
    if value.startswith("00"):
        value = "+" + value[2:]
    if value.startswith("+"):
        return "+" + re.sub(r"\D", "", value[1:])
    digits = re.sub(r"\D", "", value)
    if len(digits) == 10:
        return _default_country_code() + digits
    return "+" + digits


def resolve_user(identifier: str, method: str) -> str | None:
    identifier = (identifier or "").strip()
    if method == "email_otp":
        return frappe.db.get_value("User", {"name": identifier.lower(), "enabled": 1}, "name")
    if method == "mobile_otp":
        target = normalize_mobile(identifier)
        identity = frappe.db.get_value(
            "YOB Login Identity",
            {"identity_type": "Mobile", "normalized_value": target, "enabled": 1, "verified": 1},
            "user",
        )
        if identity and frappe.db.get_value("User", identity, "enabled"):
            return identity
        return None
    return None


def request_otp(identifier: str, method: str, application: str) -> dict:
    settings = _settings()
    enabled = (method == "email_otp" and settings.email_otp_enabled) or (method == "mobile_otp" and settings.mobile_otp_enabled)
    if not enabled:
        raise YOBAuthenticationError("Selected OTP method is disabled")
    enforce_otp_request_limits(identifier, method, settings)
    challenge_id = uuid.uuid4().hex
    user = resolve_user(identifier, method)
    if user:
        try:
            from yob_auth.security.access import resolve_access
            resolve_access(user, application, validate_domain=False)
        except Exception:
            # Preserve a generic response and do not send OTP to an ineligible account.
            user = None
    otp = "".join(str(secrets.randbelow(10)) for _ in range(cint(settings.otp_length) or 6))
    salt = secrets.token_hex(16)
    payload = {
        "hash": _hash_otp(challenge_id, otp, salt), "salt": salt, "user": user,
        "identifier": identifier, "method": method, "application": application,
        "attempts": 0, "created": int(time.time()),
    }
    frappe.cache.set_value(_challenge_key(challenge_id), payload, expires_in_sec=cint(settings.otp_expiry_seconds) or 300)
    delivery = "not attempted (no eligible account)"
    if user:
        try:
            _send_otp(identifier, method, otp, challenge_id, settings)
            delivery = "handed to sender"
        except Exception as exc:
            # Delivery is queued, so a failure here is invisible to the caller --
            # they are told an OTP was sent either way, by design. Record it, or
            # a broken mail queue looks identical to a successful send.
            delivery = f"delivery failed: {exc}"
            frappe.log_error(frappe.get_traceback(), "YOB Auth OTP delivery failed")
    log_event("OTP Requested", "Success" if user else "Ignored", user=user, application=application, method=method, identifier=identifier, reference=challenge_id, details=delivery)
    result = {"challenge_id": challenge_id, "expires_in": cint(settings.otp_expiry_seconds) or 300, "message": "If the account is eligible, an OTP has been sent."}
    if cint(settings.allow_test_otp_in_developer_mode) and cint(frappe.conf.developer_mode):
        result["test_otp"] = otp
    return result


def verify_otp(challenge_id: str, otp: str) -> tuple[str, str, str]:
    settings = _settings()
    key = _challenge_key(challenge_id)
    payload = frappe.cache.get_value(key)
    if not payload:
        raise YOBAuthenticationError("OTP is invalid or expired")
    payload["attempts"] = int(payload.get("attempts") or 0) + 1
    if payload["attempts"] > (cint(settings.max_otp_attempts) or 5):
        frappe.cache.delete_value(key)
        log_event("OTP Verified", "Failed", user=payload.get("user"), application=payload.get("application"), method=payload.get("method"), identifier=payload.get("identifier"), reference=challenge_id, details="Maximum attempts exceeded")
        raise YOBAuthenticationError("OTP is invalid or expired")
    # Re-store with the time already elapsed subtracted. Writing the full expiry
    # back would restart the clock on every attempt, so a challenge configured to
    # last five minutes could be kept alive for as long as the attempt budget.
    remaining = _remaining_ttl(payload, settings)
    if remaining <= 0:
        frappe.cache.delete_value(key)
        raise YOBAuthenticationError("OTP is invalid or expired")
    frappe.cache.set_value(key, payload, expires_in_sec=remaining)
    expected = payload.get("hash", "")
    actual = _hash_otp(challenge_id, str(otp or ""), payload.get("salt", ""))
    if not payload.get("user") or not hmac.compare_digest(expected, actual):
        log_event("OTP Verified", "Failed", user=payload.get("user"), application=payload.get("application"), method=payload.get("method"), identifier=payload.get("identifier"), reference=challenge_id)
        raise YOBAuthenticationError("OTP is invalid or expired")
    frappe.cache.delete_value(key)
    log_event("OTP Verified", "Success", user=payload["user"], application=payload["application"], method=payload["method"], identifier=payload["identifier"], reference=challenge_id)
    return payload["user"], payload["application"], payload["method"]


def _remaining_ttl(payload: dict, settings) -> int:
    """Seconds left on a challenge, measured from when it was created."""

    total = cint(settings.otp_expiry_seconds) or 300
    elapsed = int(time.time()) - int(payload.get("created") or 0)
    return max(0, total - elapsed)


def _get_otp_secret() -> str:
    secret = str(frappe.conf.get("yob_auth_otp_secret") or "").strip()
    if len(secret) < 32:
        frappe.throw(
            "yob_auth_otp_secret is missing or too weak. Configure a persistent random secret of at least 32 characters in site_config.json.",
            frappe.ValidationError,
        )
    return secret


def _hash_otp(challenge_id, otp, salt):
    secret = _get_otp_secret()
    return hmac.new(secret.encode(), f"{challenge_id}:{otp}:{salt}".encode(), hashlib.sha256).hexdigest()


def _challenge_key(challenge_id):
    return f"yob_auth:otp:{challenge_id}"



def _send_otp(identifier, method, otp, challenge_id, settings):
    if method == "email_otp":
        frappe.sendmail(recipients=[identifier], subject="Your login OTP", message=f"Your OTP is <b>{otp}</b>. It expires shortly. Do not share it.")
        return
    sender_path = (settings.sms_sender_method or "").strip()
    if not sender_path:
        frappe.throw("Mobile OTP is enabled but SMS Sender Python Method is not configured")
    frappe.get_attr(sender_path)(normalize_mobile(identifier), f"Your login OTP is {otp}. Do not share it.", reference=challenge_id)
