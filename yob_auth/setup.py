# Copyright (c) 2026, YOB and Shayona
"""Deployment self-check for yob_auth.

yob_auth ships as an installable app, so it cannot configure the reverse proxy
or the site it lands on. Two of its controls depend on that environment:

* the domain allow-list trusts a header the edge proxy must overwrite, and
* the per-IP rate limits need an IP the edge proxy must assert.

Left unconfigured, both fail *quietly* -- the app keeps serving logins while the
control does nothing. This module makes that state visible instead:

    bench --site <site> execute yob_auth.setup.check_configuration

It only reports. It changes nothing, and it never prints a secret value -- only
whether one is present and long enough.
"""

import frappe

OK = "ok"
WARN = "warn"
FAIL = "fail"

_SYMBOL = {OK: "PASS", WARN: "WARN", FAIL: "FAIL"}


def _check(name, state, detail, action=None):
    return {"name": name, "state": state, "detail": detail, "action": action}


def _check_otp_secret():
    secret = str(frappe.conf.get("yob_auth_otp_secret") or "").strip()
    if not secret:
        return _check(
            "OTP signing secret", FAIL,
            "yob_auth_otp_secret is not set -- every OTP request will throw.",
            "Reinstall the app, or set a random 64-character value in site_config.json.",
        )
    if len(secret) < 32:
        return _check(
            "OTP signing secret", FAIL,
            f"yob_auth_otp_secret is only {len(secret)} characters; 32 is the minimum.",
            "Replace it with a longer random value. Note: rotating invalidates in-flight OTPs.",
        )
    return _check("OTP signing secret", OK, f"present, {len(secret)} characters")


def _check_client_ip_header():
    header = str(frappe.conf.get("yob_auth_client_ip_header") or "").strip()
    if not header:
        return _check(
            "Trusted client IP", WARN,
            "yob_auth_client_ip_header is not set, so every caller looks like the "
            "proxy. Per-IP rate limits are DISABLED rather than applied to one "
            "shared bucket; per-user limits still apply.",
            "Have the edge proxy overwrite a header with the real client address "
            "(e.g. X-YOB-Client-IP), then set yob_auth_client_ip_header to it.",
        )
    return _check("Trusted client IP", OK, f"reading {header}; per-IP limits active")


def _check_original_host():
    header = str(frappe.conf.get("yob_auth_original_host_header") or "X-YOB-Original-Host")
    scoped = frappe.get_all(
        "YOB Application", filters={"enabled": 1}, fields=["name", "domains"]
    )
    with_domains = [a for a in scoped if (a.domains or "").strip()]
    if not with_domains:
        return _check(
            "Domain allow-list", WARN,
            "No enabled YOB Application restricts its domains, so the host check "
            "never runs and any origin may authenticate.",
            "Populate `domains` on each YOB Application with the hosts it serves.",
        )
    names = ", ".join(a.name for a in with_domains)
    return _check(
        "Domain allow-list", OK,
        f"enforced for: {names} (via {header})",
    )


def _check_proxy_trust():
    """Always a warning: the app cannot verify the proxy from inside Frappe."""
    header = str(frappe.conf.get("yob_auth_original_host_header") or "X-YOB-Original-Host")
    return _check(
        "Proxy header hygiene", WARN,
        f"{header} is trusted whenever it is present. yob_auth cannot verify "
        "from inside Frappe that your proxy overwrites it on EVERY public vhost.",
        f"Confirm each public vhost sets or clears {header}. Verify by sending it "
        "yourself to a non-storefront vhost -- the request must be rejected.",
    )


def _check_method_flags():
    settings = frappe.get_single("YOB Auth Settings")
    problems = []
    for app in frappe.get_all(
        "YOB Application", filters={"enabled": 1},
        fields=["name", "allow_password_login", "allow_email_otp", "allow_mobile_otp"],
    ):
        for label, app_flag, global_flag in (
            ("password", app.allow_password_login, settings.password_login_enabled),
            ("email OTP", app.allow_email_otp, settings.email_otp_enabled),
            ("mobile OTP", app.allow_mobile_otp, settings.mobile_otp_enabled),
        ):
            if global_flag and not app_flag:
                problems.append(f"{app.name}: {label} enabled globally but off for this application")
    if problems:
        return _check(
            "Login method flags", WARN,
            "; ".join(problems) + ".",
            "Both the global switch and the per-application flag must be on. A "
            "method enabled in only one place is silently unavailable.",
        )
    return _check("Login method flags", OK, "global switches and application flags agree")


def _check_sms_sender():
    settings = frappe.get_single("YOB Auth Settings")
    needs_sms = frappe.db.exists("YOB Application", {"enabled": 1, "allow_mobile_otp": 1})
    configured = bool((settings.sms_sender_method or "").strip())
    if needs_sms and not configured:
        return _check(
            "SMS sender", FAIL,
            "Mobile OTP is enabled but sms_sender_method is not set -- requests "
            "will throw at send time.",
            "Set a dotted path with signature send(mobile_no, message, reference=None).",
        )
    if not needs_sms:
        return _check("SMS sender", OK, "not required (mobile OTP not enabled)")
    return _check("SMS sender", OK, f"configured: {settings.sms_sender_method}")


CHECKS = (
    _check_otp_secret,
    _check_client_ip_header,
    _check_original_host,
    _check_proxy_trust,
    _check_method_flags,
    _check_sms_sender,
)


def run_checks() -> list[dict]:
    """Return every check result. Safe to call from code; prints nothing."""

    results = []
    for fn in CHECKS:
        try:
            results.append(fn())
        except Exception as exc:  # a broken check must never mask the others
            results.append(
                _check(fn.__name__, FAIL, f"check itself failed: {exc}", None)
            )
    return results


def check_configuration():
    """Print the deployment self-check. Entry point for `bench execute`."""

    results = run_checks()
    width = max(len(r["name"]) for r in results)

    print("\nyob_auth deployment check\n" + "=" * (width + 46))
    for r in results:
        print(f"  [{_SYMBOL[r['state']]}] {r['name'].ljust(width)}  {r['detail']}")
        if r["action"] and r["state"] != OK:
            print(f"{'':>{width + 10}}-> {r['action']}")

    failures = [r for r in results if r["state"] == FAIL]
    warnings = [r for r in results if r["state"] == WARN]
    print("=" * (width + 46))
    print(f"  {len(results) - len(failures) - len(warnings)} passed, "
          f"{len(warnings)} warning(s), {len(failures)} failure(s)\n")
    return results
