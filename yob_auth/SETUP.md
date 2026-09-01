# yob_auth — Setup

Everything `yob_auth` cannot configure for itself, in the order you need it.

Run this at any time to see what is still missing:

```bash
bench --site <your-site> execute yob_auth.setup.check_configuration
```

---

## 1. One-time setup (needed for both development and production)

### 1a. Register the application

In Desk → **YOB Application**, create one record per SPA website.

| Field | Value |
|---|---|
| Application Code | `STOREFRONT` |
| Allowed Domains | `myfirststorefront.com` |
| Extra Allowed Origins | *(leave empty in production)* |
| Enabled | ✅ |
| Required Profile DocType | `Customer` |
| Allow Password Login | ✅ |

> **Developing with `ng serve`?** The browser sends an `Origin` header naming the
> dev server, which is not one of the Allowed Domains, so login will be refused
> with 403. Add the dev server's full origin — scheme, host and port — to
> **Extra Allowed Origins**:
>
> ```
> http://192.168.1.25:4021
> ```
>
> Remove it before going live. Anything listed here can submit a login.

**One application code per SPA website, one domain per application.** Never list two
SPA domains under one application code — they would share a single access
boundary, and a user of one site could log into the other.

Each user also needs a **YOB User Application Access** record granting them that
application. Without it every request returns 403.

### 1b. Web server headers

Two vhosts, in `/etc/nginx/conf.d/`. Both are edited once and then serve
development and production alike.

On the recorded local WSL2 bench there is no reverse proxy in front of Frappe by
default — `bench start` serves directly on port 8000. Until these vhosts exist
and direct access to port 8000 is blocked, `X-YOB-Original-Host` and
`X-YOB-Client-IP` are caller-supplied strings and are not security authority.

**Storefront vhost** (`myfirststorefront.com.conf`), inside `location ^~ /api/`:

```nginx
proxy_pass http://myerpsite_frappe;          # direct to Frappe; no second hop

proxy_set_header Host myerpsite.com;
proxy_set_header X-Frappe-Site-Name myerpsite.com;

proxy_set_header X-YOB-Original-Host $host;  # which storefront is calling
proxy_set_header X-YOB-Client-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;   # overwrite, never append
proxy_set_header X-Real-IP $remote_addr;

proxy_set_header X-Forwarded-Host $host;
proxy_set_header X-Forwarded-Port 443;
proxy_set_header X-Forwarded-Proto https;
```

Delete any `proxy_ssl_*` lines — they are only needed when proxying to HTTPS.

**ERP vhost** (`myerpsite.com.conf`), inside `location /`:

```nginx
proxy_set_header X-YOB-Original-Host "";     # ← the important one
proxy_set_header X-YOB-Client-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;   # replaces $proxy_add_x_forwarded_for
```

Clearing `X-YOB-Original-Host` here is what stops a caller asserting it directly
and passing another site's domain check. Without it the domain restriction can be
bypassed with a single request header.

Apply:

```bash
sudo nginx -t && sudo nginx -s reload
```

### 1c. Tell Frappe which header carries the client IP

```bash
bench --site <your-site> set-config yob_auth_client_ip_header X-YOB-Client-IP
```

Without this every caller looks like the proxy, so `yob_auth` disables per-IP
rate limits rather than applying one shared bucket to everybody.

### 1d. Verify

```bash
bench --site <your-site> execute yob_auth.setup.check_configuration
```

`Trusted client IP` and `Domain allow-list` should both read **PASS**.

Then confirm the domain check cannot be bypassed — this must return **403**:

```bash
curl -sk -o /dev/null -w '%{http_code}\n' \
  -X POST https://myerpsite.com/api/method/yob_auth.api.auth.login_with_password \
  -H 'Content-Type: application/json' \
  -H 'X-YOB-Original-Host: myfirststorefront.com' \
  -d '{"application":"STOREFRONT","username":"x@y.z","password":"x"}'
```

---

## 2. Development mode

Session cookies must **not** be HTTPS-only, or a plain-`http://` dev server will
silently discard them and logins will appear to succeed without persisting.

### 2a. Cookies are already permissive on the local bench

There is nothing to switch. Frappe derives the `Secure` flag from the request
scheme rather than from a setting — `apps/frappe/frappe/auth.py`:

```python
if not secure and hasattr(frappe.local, "request"):
    secure = frappe.local.request.scheme == "https"
```

`bench start` serves plain `http://` on port 8000, so `sid` is issued without
`Secure` and a dev login persists:

```bash
bench start
```

If you put a TLS proxy in front of the dev bench, run it with `--proxy` so
`X-Forwarded-Proto` is honoured; otherwise the scheme stays `http`:

```bash
bench serve --proxy
```

### 2b. Angular

Create `proxy.conf.json` next to `angular.json`:

```json
{
  "/api": {
    "target": "https://myfirststorefront.com",
    "secure": false,
    "changeOrigin": true
  }
}
```

Point at the **storefront domain**, not the ERP domain. The storefront vhost adds
the headers `yob_auth` needs; the ERP vhost deliberately strips them.

In `angular.json`, under `projects → <app> → architect → serve → options`:

```json
"proxyConfig": "proxy.conf.json"
```

In your app code, call the API with **relative** paths — `/api/method/...`, never
`https://myerpsite.com/api/method/...`. An absolute URL bypasses the proxy and the
browser blocks it as cross-origin.

### 2c. Run

```bash
ng serve --host 0.0.0.0 --port 4021
```

Open `http://192.168.1.25:4021`. Login works, and the browser only ever talks to
one origin, so there is no CORS or cookie problem to solve.

---

## 3. Production mode

The production hosting model is **Unknown — confirm before implementation**
(see `open-items.md`). WSL2 is the recorded local development environment, not a
production target. The rule below holds for any hosting model.

### 3a. Cookies become HTTPS-only on their own

Serve the site over `https://` and the same scheme check issues `sid` with
`Secure`. No flag sets this directly.

When Frappe sits behind a TLS-terminating proxy, the proxy must send
`X-Forwarded-Proto: https` **and** Frappe must trust it, or `request.scheme`
stays `http` and `Secure` is never set:

```bash
bench setup production <user>   # gunicorn behind nginx; forwards the scheme
```

Confirm the forwarded headers in the generated nginx config before relying on
this.

### 3b. Verify

The session cookie must now carry `Secure`:

```bash
curl -skI https://myfirststorefront.com/api/method/ping | grep -i set-cookie
```

Expect `HttpOnly`, `Secure`, `SameSite=Lax` on `sid`.

### 3c. Serve the built SPA

The storefront vhost already serves the Angular build from its `root` directory,
with `try_files $uri $uri/ /index.html` for client-side routing. Deploy the
contents of `dist/browser/` there. No proxy config is involved in production — the
SPA and the API are the same origin by construction.

---

## 4. Switching between modes

There is no flag to flip — the scheme you serve over decides everything:

| | How Frappe runs | Cookie `Secure` | Angular |
|---|---|---|---|
| Development | `bench start` on `http://…:8000` | not set | `ng serve` over http |
| Production | served over `https://` behind nginx | set automatically | built files served by nginx |

Everything in section 1 stays the same in both modes.

---

## 5. Adding another SPA website

1. Create a new **YOB Application** with its own code and its own single domain.
2. Copy the storefront vhost, change `server_name` and the certificate paths.
3. Grant users access with a **YOB User Application Access** record for the new
   application code.

Do **not** add the new domain to an existing application's Allowed Domains.

---

## Known limitations

* A user disabled while holding a live session keeps that session until logout.
  Frappe clears sessions when a user is disabled through Desk, so this only
  applies to direct database edits.
* There is no tenant model. Separation between SPA websites comes from having one
  application code per site. If you later host *different businesses* that must
  not see each other's data, that needs a tenant layer.
