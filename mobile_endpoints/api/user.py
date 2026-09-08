import frappe
from erpnext import get_default_company
from frappe import _
from frappe.utils import get_url
from frappe.utils.password import get_decrypted_password, set_encrypted_password

from mobile_endpoints.api.security import require_authenticated_user, set_cors_headers


@frappe.whitelist()
def get_user_default_company():
	require_authenticated_user()
	return {"default_company": get_default_company()}


@frappe.whitelist(allow_guest=True)
def get_user_profile():
	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	user = require_authenticated_user()

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


@frappe.whitelist(allow_guest=True, methods=["GET"])
def get_oauth_config():
	"""Return public OAuth2 + PKCE configuration for the Pamper client."""
	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	client_id = frappe.conf.get("pamper_oauth_client_id")
	if not client_id:
		frappe.throw(
			_("Pamper OAuth client is not configured"),
			title=_("Configuration Error"),
			http_status_code=503,
		)
	base_url = get_url().rstrip("/")
	return {
		"client_id": client_id,
		"authorization_endpoint": f"{base_url}/api/method/frappe.integrations.oauth2.authorize",
		"token_endpoint": f"{base_url}/api/method/frappe.integrations.oauth2.get_token",
		"revoke_endpoint": f"{base_url}/api/method/frappe.integrations.oauth2.revoke_token",
		"pkce_required": True,
	}


@frappe.whitelist(allow_guest=True, methods=["POST"])
def login_with_profile(usr: str, pwd: str):
	"""Deprecated compatibility login; disable after the client migrates to PKCE."""
	set_cors_headers("POST, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	if not usr or not pwd:
		frappe.throw("Missing credentials", frappe.AuthenticationError)

	if not frappe.conf.get("pamper_allow_legacy_api_key_login", True):
		frappe.throw(
			_("Password login is disabled. Use OAuth2 with PKCE."),
			title=_("Legacy Login Disabled"),
			http_status_code=410,
		)

	frappe.local.response.setdefault("headers", {})["Deprecation"] = "true"
	frappe.local.response["headers"]["X-Pamper-Auth-Deprecated"] = "use-oauth2-pkce"

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
