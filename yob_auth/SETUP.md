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

Two vhosts, in `nginx/conf.d/`. Both are edited once and then serve development
and production alike.

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
docker exec nginx-proxy-frappe nginx -t && docker exec nginx-proxy-frappe nginx -s reload
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

### 2a. Switch cookies to permissive

In `.env`:

```bash
FRAPPE_HTTPS_ONLY=
```

In your compose file, the `backend` service needs this line under `environment:`
(add it once; the `.env` value is what you change):

```yaml
      USE_PROXY: ${FRAPPE_HTTPS_ONLY:-}
```

Restart the backend:

```bash
docker compose -f <compose-file> -p <project> up -d backend
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

### 3a. Switch cookies to HTTPS-only

In `.env`:

```bash
FRAPPE_HTTPS_ONLY=1
```

```bash
docker compose -f <compose-file> -p <project> up -d backend
```

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

Only one value changes:

| | `.env` | Angular |
|---|---|---|
| Development | `FRAPPE_HTTPS_ONLY=` | `ng serve` over http |
| Production | `FRAPPE_HTTPS_ONLY=1` | built files served by nginx |

Restart the `backend` service after changing it. Everything in section 1 stays the
same in both modes.

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
