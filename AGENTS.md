# `yob_auth` — App-Specific Mandatory Rules

Read the platform standard under `../yob_core/docs/platform/`, especially
`AGENTS.md`, `authentication.md`, `security.md`, `error-handling.md`, and the
auth/error contracts first.

## Purpose

`yob_auth` alone decides who a YOB caller is and which application/profile they
may use. It owns password/OTP flows, standard Frappe session creation/logout for
YOB clients, application access, trusted request context, auth rate limits, and
auth audit events.

It directly depends on `yob_core` only unless an accepted ADR proves another
dependency is required. It never imports a business app.

## Security invariants

- strip caller-supplied `auth_context` and inject a fresh server context;
- never accept request user/customer/company/profile/role as authority;
- never call `frappe.set_user()` from a caller-controlled token/header;
- deny absent, disabled, expired, wrong-role, wrong-profile, or ambiguous access;
- do not intercept normal Frappe Desk authentication globally;
- only trust host/IP headers under the documented proxy contract;
- store no raw OTP/password/session/token and log only masked identifiers;
- auth refusal audit failure never changes the refusal.

## Core integration

Use core response helpers and exception protocol. Auth defines only auth-owned
codes/classes and optional post-rollback audit behavior. A legacy
`yob_auth.api.response` may re-export core helpers but contains no generic
implementation. New code imports core names from `yob_core`.

## DocTypes, launcher, and Workspace

All auth DocTypes live beneath the generated `YOB Auth` module folder. Provide
one permission-gated Apps Page entry that opens one standard public `YOB Auth`
Workspace restricted to authorized admin roles. The launcher, Workspace,
sidebar links, reports, lists, exports, notifications, and logs must not expose
secrets. Child DocTypes do not receive standalone navigation.

## Required tests

Test every login method, disabled method, unknown user non-enumeration, rate
limits, OTP expiry/replay/attempts, access validity/profile/role checks,
caller-context stripping, trusted/untrusted headers, session creation/logout,
rollback-before-audit, audit failure, contract responses, and unchanged Desk
login behavior.
