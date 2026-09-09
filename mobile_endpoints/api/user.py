import frappe
from erpnext import get_default_company
from frappe import _
from frappe.utils import cstr, get_url
from frappe.utils.password import get_decrypted_password, set_encrypted_password

from mobile_endpoints.api._envelope import CompanyError
from mobile_endpoints.api.security import require_authenticated_user, set_cors_headers


class OAuthConfigurationError(Exception):
	"""OAuth discovery is unavailable until the site is configured."""

	http_status_code = 503


class LegacyLoginDisabledError(Exception):
	"""The temporary password-to-API-key login has been disabled."""

	http_status_code = 410


# ---------------------------------------------------------------------------
# Phase 01 — auth / profile / OAuth discovery (restored from
# origin/codex/pamper-online-security, unchanged)
# ---------------------------------------------------------------------------


@frappe.whitelist(allow_guest=True, methods=["GET"])
def get_user_default_company():
	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()
	return {"default_company": get_default_company()}


@frappe.whitelist(allow_guest=True, methods=["GET"])
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
			exc=OAuthConfigurationError,
			title=_("Configuration Error"),
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
def login_with_profile(usr: str | None = None, pwd: str | None = None):
	"""Deprecated compatibility login; disable after the client migrates to PKCE."""
	set_cors_headers("POST, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	if not usr or not pwd:
		frappe.throw("Missing credentials", frappe.AuthenticationError)

	if not frappe.conf.get("pamper_allow_legacy_api_key_login", False):
		frappe.throw(
			_("Password login is disabled. Use OAuth2 with PKCE."),
			exc=LegacyLoginDisabledError,
			title=_("Legacy Login Disabled"),
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


# ---------------------------------------------------------------------------
# Phase 02 — company resolution for Payment Entry (BR-06)
# ---------------------------------------------------------------------------


def _permitted_companies() -> list[str]:
	return frappe.get_list("Company", pluck="name", order_by="name asc", ignore_permissions=False)


def _resolved_default_company() -> str:
	for value in (
		frappe.defaults.get_user_default("company"),
		frappe.defaults.get_global_default("company"),
		frappe.db.get_single_value("Global Defaults", "default_company"),
	):
		company = cstr(value or "").strip()
		if company and frappe.has_permission("Company", ptype="read", doc=company):
			return company
	return ""


def resolve_company(explicit) -> str:
	"""Explicit company (permission-checked) → user/global default → the single
	permitted company. Anything else raises ``CompanyError`` (mapped by
	``@mobile_api`` to HTTP 422 with ``fields.company``)."""
	explicit = cstr(explicit or "").strip()
	if explicit:
		if not frappe.db.exists("Company", explicit) or not frappe.has_permission(
			"Company", ptype="read", doc=explicit
		):
			raise CompanyError(_("You do not have access to the selected company."))
		return explicit

	default = _resolved_default_company()
	if default:
		return default

	permitted = _permitted_companies()
	if len(permitted) == 1:
		return permitted[0]
	if not permitted:
		raise CompanyError(_("No company is available for your account."))
	raise CompanyError(_("Select a company for this payment."))


@frappe.whitelist(allow_guest=True, methods=["GET"])
def list_companies():
	"""Companies this user may post against, plus the resolved default. One
	company → the client auto-selects it (no picker); many → the client shows a
	picker; none → the client shows the 'no company' error."""
	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()

	companies = _permitted_companies()
	default = _resolved_default_company()
	if default not in companies:
		default = companies[0] if len(companies) == 1 else ""
	return {
		"companies": [{"id": c, "name": c} for c in companies],
		"default": default or "",
	}
