import hashlib
import time

import frappe
from frappe.utils import cint

from yob_auth.security.exceptions import YOBRateLimitError
from yob_auth.security.request import get_trusted_client_ip, is_client_ip_trusted


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _increment_window(key: str, ttl: int) -> int:
    count = frappe.cache.incrby(key, 1)
    frappe.cache.expire(key, ttl)
    return int(count or 0)


def enforce_otp_request_limits(identifier: str, method: str, settings) -> None:
    identifier_key = _digest(f"{method}:{(identifier or '').strip().lower()}")
    ip = get_trusted_client_ip() or "unknown"
    ip_key = _digest(ip)
    cooldown = cint(settings.otp_resend_seconds) or 60
    maximum = cint(settings.max_otp_requests_per_hour) or 8

    cooldown_key = f"yob_auth:otp:cooldown:{identifier_key}"
    if frappe.cache.get_value(cooldown_key):
        raise YOBRateLimitError("Please wait before requesting another OTP")

    window = int(time.time() // 3600)
    checks = [(f"yob_auth:otp:hour:id:{identifier_key}:{window}", maximum)]
    # IP-keyed limits are only meaningful when the IP actually identifies the
    # caller. Behind an unconfigured proxy every request shares one address, so
    # these would throttle the whole platform on one caller's behaviour.
    if is_client_ip_trusted():
        checks.append((f"yob_auth:otp:hour:ip:{ip_key}:{window}", maximum * 5))
        checks.append((f"yob_auth:otp:hour:pair:{ip_key}:{identifier_key}:{window}", maximum))
    for key, limit in checks:
        if _increment_window(key, 3700) > limit:
            raise YOBRateLimitError("Too many OTP requests. Please try later")

    frappe.cache.set_value(cooldown_key, 1, expires_in_sec=cooldown)


def enforce_password_attempt_limits(username: str, settings) -> None:
    ip = get_trusted_client_ip() or "unknown"
    user_key = _digest((username or "").strip().lower())
    ip_key = _digest(ip)
    window_seconds = cint(getattr(settings, "password_rate_window_seconds", 0)) or 300
    per_identity = cint(getattr(settings, "max_password_attempts_per_window", 0)) or 10
    per_ip = cint(getattr(settings, "max_password_attempts_per_ip_window", 0)) or 50
    window = int(time.time() // window_seconds)

    # The per-user window always applies. The IP-keyed windows only apply when
    # the IP is trustworthy -- otherwise they are one shared bucket that lets a
    # single attacker lock every user out (see is_client_ip_trusted).
    checks = [(f"yob_auth:password:user:{user_key}:{window}", per_identity)]
    if is_client_ip_trusted():
        checks.append((f"yob_auth:password:ip:{ip_key}:{window}", per_ip))
        checks.append((f"yob_auth:password:pair:{ip_key}:{user_key}:{window}", per_identity))
    for key, limit in checks:
        if _increment_window(key, window_seconds + 60) > limit:
            raise YOBRateLimitError("Too many login attempts. Please try later")
