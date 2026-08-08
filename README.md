# YOB Auth

Central authentication and application-access app for Frappe v16.

Supported login modes:

- Username/password
- Email OTP
- Mobile OTP through a pluggable SMS sender

Successful verification always creates a standard Frappe `sid` session. Business apps call `require_application()` and consume the resolved user context.

See the bundle-level `IMPLEMENTATION_GUIDE.md` for installation and API examples.


Production requires `yob_auth_otp_secret` in site_config.json and trusted reverse-proxy headers as documented in the bundle guide.
