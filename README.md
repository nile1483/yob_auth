# YOB Auth

Central authentication and application-access app for Frappe v16.

Supported login modes:

- Username/password
- Email OTP
- Mobile OTP through a pluggable SMS sender

Successful verification always creates a standard Frappe `sid` session. Business apps call `require_application()` and consume the resolved user context.

See [`yob_auth/SETUP.md`](yob_auth/SETUP.md) for setup, proxy headers, and
development/production modes. Rules for changing this app are in
[`AGENTS.md`](AGENTS.md); the shared platform standards are in
[`../yob_core/docs/platform/`](../yob_core/docs/platform/).

Check what is still unconfigured at any time:

```bash
bench --site <your-site> execute yob_auth.setup.check_configuration
```

`yob_auth_otp_secret` is generated into `site_config.json` on install. Production
additionally requires the trusted reverse-proxy headers documented in `SETUP.md`.
