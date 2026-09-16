import re

import frappe
from erpnext import get_default_company
from frappe import _
from frappe.utils import cstr, get_url
from frappe.utils.password import get_decrypted_password, set_encrypted_password

from mobile_endpoints.api._envelope import CompanyError, FieldValidationError, mobile_api
from mobile_endpoints.api.security import require_authenticated_user, set_cors_headers


class OAuthConfigurationError(Exception):
	"""Retained for the documented 503 error vocabulary.

	Since Phase 03 increment 2, `get_oauth_config` no longer raises it: "this
	platform is not configured yet" is a normal pre-login answer the client has
	to be able to read (together with `legacy_login_allowed`), not an error.
	"""

	http_status_code = 503


class LegacyLoginDisabledError(Exception):
	"""The temporary password-to-API-key login has been disabled."""

	http_status_code = 410


# ---------------------------------------------------------------------------
# Phase 01 — auth / profile / OAuth discovery (restored from
# origin/codex/pamper-online-security). get_user_default_company and
# get_user_profile carry the Phase 02 envelope like every other read endpoint,
# and get_oauth_config joined them in Phase 03 increment 2.
#
# login_with_profile deliberately does NOT: it raises LegacyLoginDisabledError
# (410), a plain Exception subclass Frappe's own dispatcher renders via its
# `http_status_code` attribute; @mobile_api's generic `except Exception` would
# swallow it into an undifferentiated 500, and the Phase 01 tests assert the
# raw exception plus its status code.
# ---------------------------------------------------------------------------


@frappe.whitelist(allow_guest=True, methods=["GET"])
@mobile_api
def get_user_default_company():
	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()
	return {"default_company": get_default_company()}


@frappe.whitelist(allow_guest=True, methods=["GET"])
@mobile_api
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


# ---------------------------------------------------------------------------
# OAuth2 + PKCE discovery (Phase 03 increment 2)
#
# Native Authorization Code + PKCE S256 on this Frappe version is VERIFIED
# LIVE (increment 1 probe): a token exchange carrying neither a session cookie
# nor a client secret succeeds, refresh rotates, and revoke takes effect.
#
# This endpoint is the public, pre-login contract telling a client WHERE to
# authenticate and AS WHICH client. It never returns a client secret, and it
# never echoes a client-supplied redirect URI — the redirect URI is whatever
# the site was configured with. Frappe matches it by exact membership
# (frappe/oauth.py:29-42), so a request-controlled value would be both useless
# and an open-redirect hole.
# ---------------------------------------------------------------------------

OAUTH_PLATFORMS = ("android", "ios", "web")
OAUTH_SUPPORTED_SCOPES = "openid all"
OAUTH_CODE_CHALLENGE_METHOD = "S256"

# One OAuth Client per Site x Environment x Platform. Values live in site
# config only — no real client id or redirect URI is ever committed here.
OAUTH_CONFIG_KEYS = {
	"android": ("pamper_oauth_android_client_id", "pamper_oauth_android_redirect_uri"),
	"ios": ("pamper_oauth_ios_client_id", "pamper_oauth_ios_redirect_uri"),
	"web": ("pamper_oauth_web_client_id", "pamper_oauth_web_redirect_uri"),
}

# RUNTIME KILL SWITCH, one per platform, default OFF.
#
# The client's build-time flag alone cannot be the rollback: turning OAuth off
# would need a new build and a store release. This server-side switch turns it
# off for every client immediately, and the client falls straight back to
# legacy login. Absent key == disabled, so a site that has never heard of these
# keys keeps behaving exactly as it does today.
OAUTH_ENABLED_KEYS = {
	"android": "pamper_oauth_android_enabled",
	"ios": "pamper_oauth_ios_enabled",
	"web": "pamper_oauth_web_enabled",
}


_ABSOLUTE_URI_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:\S+$")


def _oauth_redirect_uri_is_acceptable(redirect_uri: str) -> bool:
	"""A configured redirect URI must be exact and absolute, never cleartext,
	never a pattern.

	Accepts `https://…` and the RFC 8252 §7.1 private-use scheme form
	(`com.example.app:/path`, one slash) that is the documented native
	fallback. Rejects `http://`, anything containing `*`, and anything without
	a scheme.
	"""
	value = cstr(redirect_uri).strip()
	if not value or "*" in value:
		return False
	if value.lower().startswith("http://"):
		return False
	return bool(_ABSOLUTE_URI_RE.match(value))


@frappe.whitelist(allow_guest=True, methods=["GET"])
@mobile_api
def get_oauth_config(platform: str | None = None):
	"""
	GET /api/method/mobile_endpoints.api.user.get_oauth_config?platform=android

	Public (pre-login) OAuth2 + PKCE discovery for ONE platform: endpoints,
	that platform's client id and REGISTERED redirect URI, supported scopes,
	and whether OAuth / legacy login are currently available.

	`platform` is an allowlist of android | ios | web; anything else is a 422
	naming the field. Never returns a client secret.
	"""
	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	requested = cstr(platform).strip().lower()
	if requested not in OAUTH_PLATFORMS:
		raise FieldValidationError(
			_("Unsupported platform. Expected one of: {0}").format(", ".join(OAUTH_PLATFORMS)),
			field="platform",
		)

	base_url = get_url().rstrip("/")
	oauth_enabled = bool(frappe.conf.get(OAUTH_ENABLED_KEYS[requested], False))
	config = {
		"platform": requested,
		"issuer": base_url,
		"authorization_endpoint": f"{base_url}/api/method/frappe.integrations.oauth2.authorize",
		"token_endpoint": f"{base_url}/api/method/frappe.integrations.oauth2.get_token",
		"revoke_endpoint": f"{base_url}/api/method/frappe.integrations.oauth2.revoke_token",
		"scopes_supported": OAUTH_SUPPORTED_SCOPES,
		"code_challenge_method": OAUTH_CODE_CHALLENGE_METHOD,
		"pkce_required": True,
		"client_id": None,
		"redirect_uri": None,
		"oauth_enabled": oauth_enabled,
		"oauth_configured": False,
		"legacy_login_allowed": bool(frappe.conf.get("pamper_allow_legacy_api_key_login", False)),
		"status": "not_configured",
	}

	if not oauth_enabled:
		# The runtime kill switch, checked FIRST: a disabled platform hands out
		# no client id and no redirect URI at all, so a client cannot start a
		# flow even if it wanted to. Flipping this key off is the rollback —
		# it needs no new build and no store release.
		config["status"] = "disabled"
		return config

	if requested == "web":
		# Browser-held OAuth tokens are not an option for this product: Web must
		# go through a server-side BFF. Until that exists, `web` reports that it
		# is required — deliberately WITHOUT handing the browser a client id it
		# could start a browser-only PKCE flow with.
		config["status"] = "bff_required"
		return config

	client_id_key, redirect_uri_key = OAUTH_CONFIG_KEYS[requested]
	client_id = cstr(frappe.conf.get(client_id_key) or "").strip()
	redirect_uri = cstr(frappe.conf.get(redirect_uri_key) or "").strip()

	if not client_id or not redirect_uri:
		# Deliberately does not say WHICH key is missing: this endpoint is
		# reachable by guests and must not map out the site's configuration.
		return config

	if not _oauth_redirect_uri_is_acceptable(redirect_uri):
		frappe.log_error(
			f"Configured {redirect_uri_key} is not an acceptable redirect URI",
			"mobile_endpoints:get_oauth_config",
		)
		config["status"] = "misconfigured"
		return config

	config["client_id"] = client_id
	config["redirect_uri"] = redirect_uri
	config["oauth_configured"] = True
	config["status"] = "ready"
	return config


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
@mobile_api
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
