import frappe
from erpnext import get_default_company
from frappe.utils import get_url
from frappe.utils.password import get_decrypted_password, set_encrypted_password


def _set_cors_headers(methods: str) -> None:
    headers = frappe.local.response.setdefault("headers", {})
    origin = ""
    if frappe.local.request:
        origin = frappe.local.request.headers.get("Origin") or ""
    headers["Access-Control-Allow-Origin"] = origin or "*"
    headers["Vary"] = "Origin"
    headers["Access-Control-Allow-Credentials"] = "true"
    headers["Access-Control-Allow-Methods"] = methods
    headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"


@frappe.whitelist()
def get_user_default_company():
    return {"default_company": get_default_company()}


@frappe.whitelist(allow_guest=True)
def get_user_profile():
    _set_cors_headers("GET, OPTIONS")
    if frappe.local.request and frappe.local.request.method == "OPTIONS":
        return {}

    user = frappe.session.user
    if not user or user == "Guest":
        return {"full_name": "", "email": "", "user_image": ""}

    full_name, email, user_image = frappe.db.get_value(
        "User",
        user,
        ["full_name", "email", "user_image"],
    )

    image_url = user_image or ""
    if image_url and not image_url.startswith("http"):
        image_url = f"{get_url()}{image_url}"

    return {
        "full_name": full_name or "",
        "email": email or "",
        "user_image": image_url,
    }


@frappe.whitelist(allow_guest=True)
def login_with_profile(usr: str, pwd: str):
    _set_cors_headers("POST, OPTIONS")
    if frappe.local.request and frappe.local.request.method == "OPTIONS":
        return {}

    if not usr or not pwd:
        frappe.throw("Missing credentials", frappe.AuthenticationError)

    from frappe.auth import LoginManager

    login_manager = LoginManager()
    login_manager.authenticate(user=usr, pwd=pwd)
    login_manager.post_login()

    api_key = frappe.db.get_value("User", frappe.session.user, "api_key")
    if not api_key:
        api_key = frappe.generate_hash(length=15)
        frappe.db.set_value("User", frappe.session.user, "api_key", api_key)

    try:
        api_secret = get_decrypted_password("User", frappe.session.user, "api_secret")
    except Exception:
        api_secret = None

    if not api_secret:
        api_secret = frappe.generate_hash(length=20)
        set_encrypted_password("User", frappe.session.user, api_secret, "api_secret")

    full_name, email, user_image = frappe.db.get_value(
        "User",
        frappe.session.user,
        ["full_name", "email", "user_image"],
    )

    image_url = user_image or ""
    if image_url and not image_url.startswith("http"):
        image_url = f"{get_url()}{image_url}"

    return {
        "full_name": full_name or "",
        "email": email or "",
        "user_image": image_url,
        "token": f"token {api_key}:{api_secret}",
    }