app_name = "yob_auth"
app_title = "YOB Auth"
app_publisher = "Shayona Technology"
app_description = "Central authentication and application access"
app_email = "support@example.com"
app_license = "MIT"

# yob_core MUST be installed first: the public API response envelope
# (yob_auth.api.response) re-exports its implementation from yob_core.api.
# There is no ERPNext dependency here -- authentication touches none of it.
required_apps = ["yob_core"]

# Shown as a tile on the /apps screen. The Desk entry point itself is the
# Desktop Icon + Workspace Sidebar pair in desktop_icon/ and workspace_sidebar/,
# which Frappe imports from disk on `bench migrate` (frappe.model.sync).
add_to_apps_screen = [
    {
        "name": "yob_auth",
        "logo": "/assets/yob_auth/images/logo.svg",
        "title": "YOB Auth",
        "route": "/desk/yob_auth",
    }
]

after_install = "yob_auth.install.after_install"

# Keep standard Frappe lifecycle behavior. These are intentionally lightweight.
on_logout = "yob_auth.security.session.on_logout"

# YOB Auth Log stores an IP address and User-Agent per event. Ninety days is
# long enough for incident review without retaining personal data indefinitely,
# and it stops the table growing without bound.
default_log_clearing_doctypes = {"YOB Auth Log": 90}

# No doc_events: authorization is resolved from the database on every request,
# so there is no cache to invalidate. A previous version registered handlers
# that deleted cache keys nothing ever wrote, which read as though results were
# cached and would have misled the next person to add caching here.
