import frappe


def on_logout(login_manager=None):
    # Hook reserved for future device/session cleanup. Never block logout.
    return None


def create_frappe_session(user: str):
    if not user or user == "Guest":
        frappe.throw("Cannot create a session for Guest", frappe.AuthenticationError)
    user_row = frappe.db.get_value("User", user, ["name", "enabled"], as_dict=True)
    if not user_row or not user_row.enabled:
        frappe.throw("User is disabled or missing", frappe.AuthenticationError)
    frappe.local.login_manager.login_as(user)
