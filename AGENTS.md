# YOB Auth — rules for humans and coding agents

Start with the platform guideline at the repository root: [`AGENTS.md`](../../AGENTS.md).
This file covers what is specific to `yob_auth`.

`yob_auth` is the **only** app allowed to decide who a caller is and which YOB
application they may use. Everything above it trusts that decision, so a bug
here is a platform-wide security bug.

```text
frappe → yob_core → yob_auth → business apps
```

## 1. What this app owns

- DocTypes: `YOB Application`, `YOB Auth Log`, `YOB Auth Settings`,
  `YOB Login Identity`, `YOB User Application Access`
- Password authentication, email/mobile OTP, session creation
- Application access resolution and profile resolution
- Login rate limiting (`security/rate_limit.py`)
- Auth audit logging (`security/audit.py`)
- The auth error codes and the exception→envelope mapping
  (`api/response.py`)
- Trusted request inspection (`security/request.py`)

## 2. What this app must not own

Ecommerce logic, or anything a non-auth app would have to import to do its own
job. If a business app needs it and it isn't about identity, it belongs in
`yob_core` (if genuinely generic) or in that app.

`yob_auth` depends on `yob_core` only. **Do not add ERPNext, payments or any
business dependency to `required_apps`** — authentication touches none of them.

## 3. The response envelope is not ours

The generic helpers, HTTP constants and platform-wide error codes live in
`yob_core.api`. `yob_auth/api/response.py` re-exports them so existing imports
such as `from yob_auth.api.response import success_response` keep working.

- **Never** add a second implementation of a generic helper here.
- New code in this app imports generics from `yob_core` directly and takes only
  auth-owned names from `yob_auth.api.response` — see `api/auth.py` for the
  pattern.

We own exactly four error codes; they are permanent:

```text
invalid_credentials
application_access_denied
login_method_disabled
otp_invalid
```

`authentication_required` and `rate_limit_exceeded` are **not** ours — they are
transport-level refusals any app can raise, and live in `yob_core.api.errors`.

## 4. `envelope_yob_errors` stays here

It maps `YOBRateLimitError` → 429, `YOBAccessDeniedError` → 403 and
`YOBAuthenticationError` → 401, and writes the refusal audit row. It cannot move
to `yob_core`: it depends on `security/exceptions.py` and `security/audit.py`.

Two behaviours in it are load-bearing — preserve both:

1. **The rollback happens before the audit insert.** Catching the exception
   stops Frappe from rolling back, so it is done explicitly; the audit row is
   inserted *after* the rollback or it would be discarded with it.
2. **Unknown exceptions are deliberately not caught.** They must keep escaping
   so Frappe answers 500 and logs a traceback. Never widen the `except`.

## 5. Security invariants

Breaking any of these is a security regression, not a style issue:

- **Authorization context is always generated server-side.** `require_application`
  strips any client-supplied `auth_context` from `form_dict` and kwargs before
  resolving it. Never read identity from a request parameter.
- **Refusals are raised, not returned**, so the transaction rolls back and a
  partial write can never be answered with 200.
- **IP-keyed limits only apply when the IP is trustworthy.** Check
  `is_client_ip_trusted()` first. Behind an unconfigured proxy every request
  shares one address, so an IP-keyed counter becomes a single platform-wide
  bucket — useless as a control and usable as a denial-of-service lever.
- **`get_original_host()` fails closed**, returning `""` when the trusted proxy
  header is absent. There is deliberately no fallback to `request.host`: that
  would treat a request which never passed the proxy as though it had. The edge
  proxy must *overwrite* the header on every public vhost.
- **Auditing must never break a response.** `log_event` and `_log_refusal`
  swallow their own failures into the Error Log.
- **Never log a raw identifier.** `mask_identifier()` exists for that.

## 6. Changing authentication behaviour

Password login, OTP, session creation and logout are consumed by shipped
clients. Treat their request/response shapes as frozen unless the change is the
explicit point of the task.

Before changing anything in `security/`, read `yob_auth/SETUP.md` for the site
configuration (`yob_auth_client_ip_header`, `yob_auth_original_host_header`)
that the proxy contract depends on.

## 7. Tests

```bash
bench --site <site> run-tests --app yob_auth
```

We test auth-specific error codes, the exception→envelope mapping, audit
behaviour and authentication responses. The generic envelope behaviour is
tested once, in `yob_core` — do not copy those tests here.

Static contract scans come from `yob_core.testing.api_contract.APIContractChecker`;
see `tests/test_response_contract.py`.

## 8. Never

1. Modify Frappe or ERPNext core.
2. Add a generic helper implementation to this app.
3. Rename or re-value a published error code.
4. Trust a client-supplied header, field or cookie for identity.
5. Add a business-app dependency to `required_apps`.
6. Import `yob_storefront` or any other business app from here.
