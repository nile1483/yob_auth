from urllib.parse import urlparse

import frappe


def _request():
    return getattr(frappe.local, "request", None)


def get_original_host() -> str:
    """Return the host asserted by the trusted edge proxy, or "" if none was.

    The edge proxy must OVERWRITE the configured header on every public vhost --
    including vhosts that serve no storefront -- because a client that can set
    the header itself gets to choose which application's domain check it passes.
    X-Forwarded-Host is deliberately not trusted here because multi-hop proxies
    frequently replace it.

    There is deliberately no fallback to ``request.host``. Falling back means a
    request that never passed through the proxy is treated as though it had,
    which is precisely the case the domain check exists to reject. Returning ""
    makes ``_validate_request_domain`` fail closed instead.

    See ``yob_auth.setup.check_configuration`` for the proxy requirements this
    depends on, and note that failing closed does not by itself stop a spoofed
    header -- only the proxy clearing it does.
    """
    request = _request()
    if not request:
        return ""
    configured_header = str(frappe.conf.get("yob_auth_original_host_header") or "X-YOB-Original-Host")
    raw = request.headers.get(configured_header, "").split(",", 1)[0].strip()
    if not raw:
        return ""
    return (urlparse(f"//{raw}").hostname or "").lower()


def get_request_origin() -> tuple[str, str]:
    """Return ``(origin, hostname)`` from the browser's Origin header.

    Unlike the host header this is set by the browser and cannot be forged by
    page script, which is what makes it useful against a third-party site
    submitting a login on a visitor's behalf. It is absent on same-origin GETs
    and on non-browser callers, so an empty result means "nothing to check"
    rather than "reject".
    """
    request = _request()
    if not request:
        return "", ""
    origin = (request.headers.get("Origin") or "").strip()
    if not origin or origin == "null":
        return "", ""
    return origin, (urlparse(origin).hostname or "").lower()


def is_client_ip_trusted() -> bool:
    """True when the client IP is read from a header a trusted proxy overwrites.

    When ``yob_auth_client_ip_header`` is unset, ``get_trusted_client_ip``
    returns ``request.remote_addr`` -- the proxy's own address, identical for
    every caller. Any per-IP counter then becomes a single bucket shared by the
    whole platform: worthless as a control, and usable as a denial-of-service
    lever, since one caller can exhaust everybody's budget.

    Callers that key a limit on the IP must check this first.
    """
    return bool(str(frappe.conf.get("yob_auth_client_ip_header") or "").strip())


def get_trusted_client_ip() -> str:
    """Return the client IP after the edge proxy has sanitized it.

    Configure ``yob_auth_client_ip_header`` only for a header overwritten by a
    trusted edge proxy. Otherwise REMOTE_ADDR/request.remote_addr is used.
    """
    request = _request()
    if not request:
        return ""
    header = str(frappe.conf.get("yob_auth_client_ip_header") or "").strip()
    if header:
        value = request.headers.get(header, "").split(",", 1)[0].strip()
        if value:
            return value[:64]
    return str(request.remote_addr or "")[:64]
