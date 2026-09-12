"""Standalone regression tests guarding the Phase 01 <-> Phase 02 merge.

Context: the Phase 02 branch (`phase-02-reliable-operations`) was first cut from
a base that predated the Phase 01 security hardening
(`origin/codex/pamper-online-security`). Merging Phase 01 back in must keep BOTH:

  * Phase 01 auth / CORS / OAuth surface
    (`login_with_profile`, `get_user_profile`, `get_oauth_config`,
     `require_authenticated_user`, `set_cors_headers`,
     `pamper_allow_legacy_api_key_login` defaulting to False,
     `OAuthConfigurationError`, `LegacyLoginDisabledError`), and
  * Phase 02 reliability additions
    (`list_companies`, `resolve_company`, the `@mobile_api` envelope,
     `CompanyError`, server-side idempotency, `get_operation_status`).

Frappe is intentionally not installed outside Bench; a module stub keeps these
runnable in CI while each function under test is handed an explicit fake runtime.
The bench-only Phase 02 suite lives in ``mobile_endpoints/tests/test_reliability.py``
and is exercised separately with ``bench run-tests``.
"""

from __future__ import annotations

import json
import sys
import types
from types import SimpleNamespace

import pytest


class AuthenticationError(Exception):
	http_status_code = 401


class PermissionError(Exception):  # noqa: A001 - mirrors frappe.PermissionError
	http_status_code = 403


class DoesNotExistError(Exception):
	http_status_code = 404


class ValidationError(Exception):
	http_status_code = 417


def _whitelist(allow_guest=False, methods=None):
	def decorator(function):
		function.allow_guest = allow_guest
		function.allowed_http_methods = methods
		return function

	return decorator


def _throw(message, exc=ValidationError, title=None):
	del title
	raise exc(message)


if "frappe" not in sys.modules:
	frappe_stub = types.ModuleType("frappe")
	frappe_stub._ = lambda message: message
	frappe_stub.AuthenticationError = AuthenticationError
	frappe_stub.PermissionError = PermissionError
	frappe_stub.DoesNotExistError = DoesNotExistError
	frappe_stub.ValidationError = ValidationError
	frappe_stub.conf = {}
	frappe_stub.local = SimpleNamespace(response={}, request=None, message_log=[])
	frappe_stub.session = SimpleNamespace(user="Guest")
	frappe_stub.whitelist = _whitelist
	frappe_stub.throw = _throw
	frappe_stub.generate_hash = lambda length=10: "0" * int(length or 10)
	frappe_stub.get_traceback = lambda: "traceback"
	frappe_stub.log_error = lambda *args, **kwargs: None

	frappe_utils = types.ModuleType("frappe.utils")
	frappe_utils.cint = lambda value: int(value or 0)
	frappe_utils.cstr = lambda value: "" if value is None else str(value)
	frappe_utils.flt = lambda value: float(value or 0)
	frappe_utils.get_url = lambda: "https://erp.example.com"
	frappe_utils.now_datetime = lambda: None
	frappe_utils.nowtime = lambda: "00:00:00"
	frappe_utils.today = lambda: "2026-09-09"
	frappe_utils.add_days = lambda dt, days: dt
	frappe_utils.strip_html_tags = lambda value: value
	frappe_stub.utils = frappe_utils

	file_manager = types.ModuleType("frappe.utils.file_manager")
	file_manager.save_file = lambda *args, **kwargs: None

	password = types.ModuleType("frappe.utils.password")
	password.get_decrypted_password = lambda *args, **kwargs: None
	password.set_encrypted_password = lambda *args, **kwargs: None

	erpnext_stub = types.ModuleType("erpnext")
	erpnext_stub.get_default_company = lambda: "Test Company"

	sys.modules["frappe"] = frappe_stub
	sys.modules["frappe.utils"] = frappe_utils
	sys.modules["frappe.utils.file_manager"] = file_manager
	sys.modules["frappe.utils.password"] = password
	sys.modules["erpnext"] = erpnext_stub


from mobile_endpoints.api import _envelope, _idempotency, operation, security, user  # noqa: E402


# --------------------------------------------------------------------------- #
#  helpers                                                                    #
# --------------------------------------------------------------------------- #


class FakeDB:
	def __init__(self, values=None, exists=True, single_value=""):
		self.values = values or {}
		self._exists = exists
		self._single_value = single_value
		self.set_calls = []

	def exists(self, doctype, name):
		return self._exists

	def get_value(self, doctype, name, fieldname, as_dict=False):
		if isinstance(fieldname, (list, tuple)):
			return [self.values.get((doctype, name, f), "") for f in fieldname]
		return self.values.get((doctype, name, fieldname), name)

	def get_single_value(self, doctype, fieldname):
		return self._single_value

	def set_value(self, *args, **kwargs):
		self.set_calls.append((args, kwargs))

	def commit(self):
		pass

	def rollback(self):
		pass

	def delete(self, *args, **kwargs):
		pass


def fake_frappe(*, user_name="user@example.com", config=None, request=None):
	runtime = SimpleNamespace()
	runtime._ = lambda message: message
	runtime.AuthenticationError = AuthenticationError
	runtime.PermissionError = PermissionError
	runtime.DoesNotExistError = DoesNotExistError
	runtime.ValidationError = ValidationError
	runtime.conf = config or {}
	runtime.local = SimpleNamespace(response={}, request=request, message_log=[])
	runtime.session = SimpleNamespace(user=user_name)
	runtime.request = request
	runtime.throw = _throw
	runtime.has_permission = lambda *a, **k: True
	runtime.db = FakeDB()
	runtime.generate_hash = lambda length=10: "0" * int(length or 10)
	runtime.get_traceback = lambda: "traceback"
	runtime.log_error = lambda *a, **k: None
	runtime.defaults = SimpleNamespace(
		get_user_default=lambda key: "",
		get_global_default=lambda key: "",
	)
	return runtime


def _patch(monkeypatch, module, runtime):
	monkeypatch.setattr(module, "frappe", runtime)


# --------------------------------------------------------------------------- #
#  Phase 01 surface still present                                             #
# --------------------------------------------------------------------------- #


def test_phase01_auth_surface_still_exported():
	for name in ("login_with_profile", "get_user_profile", "get_oauth_config", "list_companies"):
		assert callable(getattr(user, name)), f"user.{name} missing after merge"
	for name in ("require_authenticated_user", "set_cors_headers", "require_doctype_permission"):
		assert callable(getattr(security, name)), f"security.{name} missing after merge"
	assert issubclass(user.OAuthConfigurationError, Exception)
	assert issubclass(user.LegacyLoginDisabledError, Exception)
	assert user.LegacyLoginDisabledError.http_status_code == 410
	assert user.OAuthConfigurationError.http_status_code == 503


def test_login_with_profile_succeeds_when_legacy_login_enabled(monkeypatch):
	runtime = fake_frappe(config={"pamper_allow_legacy_api_key_login": True})
	runtime.local.request = SimpleNamespace(method="POST", headers={})
	runtime.session = SimpleNamespace(user="user@example.com")
	runtime.db = FakeDB(
		values={
			("User", "user@example.com", "api_key"): "KEY123",
			("User", "user@example.com", "full_name"): "Jane",
			("User", "user@example.com", "email"): "user@example.com",
			("User", "user@example.com", "user_image"): "",
		}
	)

	auth_module = types.ModuleType("frappe.auth")

	class _LoginManager:
		def authenticate(self, user=None, pwd=None):
			self._user = user

		def post_login(self):
			pass

	auth_module.LoginManager = _LoginManager
	monkeypatch.setitem(sys.modules, "frappe.auth", auth_module)

	monkeypatch.setattr(user, "get_decrypted_password", lambda *a, **k: "SECRET456")
	monkeypatch.setattr(user, "set_encrypted_password", lambda *a, **k: None)
	_patch(monkeypatch, user, runtime)
	_patch(monkeypatch, security, runtime)
	monkeypatch.setattr(user, "set_cors_headers", lambda methods: None)

	result = user.login_with_profile("user@example.com", "hunter2")

	assert result["token"] == "token KEY123:SECRET456"
	assert result["full_name"] == "Jane"


def test_login_with_profile_returns_410_when_legacy_login_disabled(monkeypatch):
	runtime = fake_frappe(config={})
	runtime.local.request = SimpleNamespace(method="POST", headers={})
	_patch(monkeypatch, user, runtime)
	_patch(monkeypatch, security, runtime)
	monkeypatch.setattr(user, "set_cors_headers", lambda methods: None)

	with pytest.raises(user.LegacyLoginDisabledError) as exc:
		user.login_with_profile("user@example.com", "hunter2")
	assert exc.value.http_status_code == 410


def test_get_user_profile_requires_authentication(monkeypatch):
	runtime = fake_frappe(user_name="Guest")
	runtime.local.request = SimpleNamespace(method="GET", headers={})
	_patch(monkeypatch, user, runtime)
	_patch(monkeypatch, security, runtime)
	monkeypatch.setattr(user, "set_cors_headers", lambda methods: None)

	with pytest.raises(AuthenticationError) as exc:
		user.get_user_profile()
	assert exc.value.http_status_code == 401


def test_get_user_profile_options_preflight_short_circuits(monkeypatch):
	runtime = fake_frappe(user_name="Guest")
	runtime.local.request = SimpleNamespace(method="OPTIONS", headers={})
	_patch(monkeypatch, user, runtime)
	_patch(monkeypatch, security, runtime)
	monkeypatch.setattr(user, "set_cors_headers", lambda methods: None)

	assert user.get_user_profile() == {}  # never reaches require_authenticated_user


def test_get_oauth_config_available_when_configured(monkeypatch):
	runtime = fake_frappe(config={"pamper_oauth_client_id": "pamper-web"})
	runtime.local.request = SimpleNamespace(method="GET", headers={})
	_patch(monkeypatch, user, runtime)
	_patch(monkeypatch, security, runtime)
	monkeypatch.setattr(user, "set_cors_headers", lambda methods: None)

	config = user.get_oauth_config()
	assert config["client_id"] == "pamper-web"
	assert config["pkce_required"] is True
	assert config["token_endpoint"].endswith("oauth2.get_token")


def test_cors_headers_only_reflect_an_allowlisted_origin(monkeypatch):
	runtime = fake_frappe(config={"allow_cors": '["https://app.pamper.example", "*"]'})
	runtime.local.request = SimpleNamespace(headers={"Origin": "https://evil.example"})
	_patch(monkeypatch, security, runtime)

	security.set_cors_headers("POST, OPTIONS")
	assert runtime.local.response == {}  # unknown origin -> no header

	runtime.local.request.headers["Origin"] = "https://app.pamper.example"
	security.set_cors_headers("POST, OPTIONS")
	headers = runtime.local.response["headers"]
	assert headers["Access-Control-Allow-Origin"] == "https://app.pamper.example"
	assert "Access-Control-Allow-Credentials" not in headers  # never with a reflected origin


class _FrappeDict(dict):
	"""Minimal stand-in for frappe._dict: missing attributes resolve to None
	instead of raising AttributeError -- this is what made a bare test/console
	request (no real werkzeug `.headers`) crash set_cors_headers in the real
	bench run (`AttributeError: 'NoneType' object has no attribute 'get'`)."""

	def __getattr__(self, key):
		return self.get(key)


def test_cors_set_cors_headers_survives_request_is_none(monkeypatch):
	runtime = fake_frappe(config={"allow_cors": '["https://app.pamper.example"]'})
	runtime.local.request = None
	_patch(monkeypatch, security, runtime)

	security.set_cors_headers("GET, OPTIONS")  # must not raise
	assert runtime.local.response == {}


def test_cors_set_cors_headers_survives_request_headers_is_none(monkeypatch):
	runtime = fake_frappe(config={"allow_cors": '["https://app.pamper.example"]'})
	runtime.local.request = _FrappeDict(method="POST")  # no "headers" key -> .headers is None
	assert runtime.local.request.headers is None
	_patch(monkeypatch, security, runtime)

	security.set_cors_headers("POST, OPTIONS")  # must not raise
	assert runtime.local.response == {}


def test_cors_missing_origin_sets_no_header(monkeypatch):
	runtime = fake_frappe(config={"allow_cors": '["https://app.pamper.example"]'})
	runtime.local.request = SimpleNamespace(headers={})  # Origin key absent entirely
	_patch(monkeypatch, security, runtime)

	security.set_cors_headers("GET, OPTIONS")
	assert runtime.local.response == {}


def test_cors_allowed_origin_gets_reflected(monkeypatch):
	runtime = fake_frappe(config={"allow_cors": '["https://app.pamper.example"]'})
	runtime.local.request = SimpleNamespace(headers={"Origin": "https://app.pamper.example"})
	_patch(monkeypatch, security, runtime)

	security.set_cors_headers("GET, OPTIONS")
	headers = runtime.local.response["headers"]
	assert headers["Access-Control-Allow-Origin"] == "https://app.pamper.example"
	assert headers["Vary"] == "Origin"


def test_cors_disallowed_origin_gets_no_header(monkeypatch):
	runtime = fake_frappe(config={"allow_cors": '["https://app.pamper.example"]'})
	runtime.local.request = SimpleNamespace(headers={"Origin": "https://attacker.example"})
	_patch(monkeypatch, security, runtime)

	security.set_cors_headers("GET, OPTIONS")
	assert runtime.local.response == {}


# --------------------------------------------------------------------------- #
#  Phase 02 additions still work                                              #
# --------------------------------------------------------------------------- #


def test_list_companies_requires_auth_and_shapes_response(monkeypatch):
	runtime = fake_frappe()
	runtime.local.request = SimpleNamespace(method="GET", headers={})
	runtime.get_list = lambda *a, **k: ["Alpha Co", "Beta Co"]
	_patch(monkeypatch, user, runtime)
	_patch(monkeypatch, security, runtime)
	monkeypatch.setattr(user, "set_cors_headers", lambda methods: None)

	result = user.list_companies()
	assert result["companies"] == [
		{"id": "Alpha Co", "name": "Alpha Co"},
		{"id": "Beta Co", "name": "Beta Co"},
	]
	# two companies, no resolvable default -> client must show a picker
	assert result["default"] == ""


def test_list_companies_rejects_guest(monkeypatch):
	runtime = fake_frappe(user_name="Guest")
	runtime.local.request = SimpleNamespace(method="GET", headers={})
	_patch(monkeypatch, user, runtime)
	_patch(monkeypatch, security, runtime)
	monkeypatch.setattr(user, "set_cors_headers", lambda methods: None)

	with pytest.raises(AuthenticationError):
		user.list_companies()


def test_resolve_company_returns_permitted_explicit_choice(monkeypatch):
	runtime = fake_frappe()
	runtime.db = FakeDB(exists=True)
	runtime.has_permission = lambda *a, **k: True
	_patch(monkeypatch, user, runtime)

	assert user.resolve_company("Alpha Co") == "Alpha Co"


def test_resolve_company_rejects_forbidden_company(monkeypatch):
	runtime = fake_frappe()
	runtime.db = FakeDB(exists=True)
	runtime.has_permission = lambda *a, **k: False
	_patch(monkeypatch, user, runtime)

	with pytest.raises(_envelope.CompanyError) as exc:
		user.resolve_company("Forbidden Co")
	assert exc.value.field == "company"


def test_resolve_company_autoselects_single_permitted(monkeypatch):
	runtime = fake_frappe()
	runtime.get_list = lambda *a, **k: ["Only Co"]
	_patch(monkeypatch, user, runtime)

	assert user.resolve_company(None) == "Only Co"


def test_resolve_company_ambiguous_raises_company_error(monkeypatch):
	runtime = fake_frappe()
	runtime.get_list = lambda *a, **k: ["Alpha Co", "Beta Co"]
	_patch(monkeypatch, user, runtime)

	with pytest.raises(_envelope.CompanyError):
		user.resolve_company(None)


def test_run_idempotent_replays_stored_response_for_same_key(monkeypatch):
	runtime = fake_frappe()
	stored = {
		"name": "abc",
		"request_hash": _idempotency._hash_payload({"a": 1}),
		"response_json": json.dumps({"name": "INV-1", "modified": "t1"}),
		"status": "done",
		"docname": "INV-1",
		"user": "user@example.com",
	}
	runtime.db = FakeDB()
	runtime.db.get_value = lambda *a, **k: SimpleNamespace(**stored)
	_patch(monkeypatch, _idempotency, runtime)

	calls = []
	result = _idempotency.run_idempotent("req-1", "invoice.create", {"a": 1}, lambda: calls.append(1))
	assert result == {"name": "INV-1", "modified": "t1"}
	assert calls == []  # fn never runs on replay


def test_run_idempotent_conflicts_on_same_key_different_payload(monkeypatch):
	runtime = fake_frappe()
	stored = {
		"name": "abc",
		"request_hash": _idempotency._hash_payload({"a": 1}),
		"response_json": "",
		"status": "processing",
		"docname": "",
		"user": "user@example.com",
	}
	runtime.db = FakeDB()
	runtime.db.get_value = lambda *a, **k: SimpleNamespace(**stored)
	_patch(monkeypatch, _idempotency, runtime)

	with pytest.raises(_idempotency.IdempotencyConflict):
		_idempotency.run_idempotent("req-1", "invoice.create", {"a": 2}, lambda: ("X", {}))


def test_run_idempotent_without_key_runs_once(monkeypatch):
	runtime = fake_frappe()
	_patch(monkeypatch, _idempotency, runtime)

	calls = []

	def _fn():
		calls.append(1)
		return "INV-9", {"name": "INV-9"}

	result = _idempotency.run_idempotent(None, "invoice.create", {}, _fn)
	assert result == {"name": "INV-9"}
	assert calls == [1]


def test_lookup_is_scoped_to_the_session_user(monkeypatch):
	runtime = fake_frappe()
	runtime.db = FakeDB()
	runtime.db.get_value = lambda *a, **k: None
	_patch(monkeypatch, _idempotency, runtime)
	assert _idempotency.lookup("req-x", "payment.create") == {"found": False}

	runtime.db.get_value = lambda *a, **k: SimpleNamespace(
		docname="PAY-2", status="done", response_json=json.dumps({"name": "PAY-2"})
	)
	found = _idempotency.lookup("req-x", "payment.create")
	assert found == {"found": True, "status": "done", "name": "PAY-2", "result": {"name": "PAY-2"}}


def test_get_operation_status_rejects_unknown_scope(monkeypatch):
	runtime = fake_frappe()
	runtime.local.request = SimpleNamespace(method="GET", headers={})
	_patch(monkeypatch, operation, runtime)
	_patch(monkeypatch, security, runtime)
	_patch(monkeypatch, _envelope, runtime)
	monkeypatch.setattr(operation, "set_cors_headers", lambda methods: None)
	monkeypatch.setattr(operation, "require_authenticated_user", lambda: "user@example.com")

	result = operation.get_operation_status(client_request_id="r1", scope="bogus.scope")
	assert result["success"] is False
	assert result["error"]["code"] == "validation_error"
	assert result["error"]["fields"] == {"scope": "invalid"}


def test_get_operation_status_end_to_end_with_headerless_request_is_422_not_500(monkeypatch):
	"""Regression: on the real bench, `frappe.local.request` for a test/console
	call has no real werkzeug `.headers`. Every endpoint calls set_cors_headers()
	FIRST -- unlike the test above, this one does NOT stub it out, so it
	reproduces the exact failure the bench run reported: an unhandled
	AttributeError inside set_cors_headers made @mobile_api report a sanitized
	500 server_error for what should have been a clean 422 validation_error."""
	runtime = fake_frappe()
	runtime.local.request = _FrappeDict(method="GET")
	_patch(monkeypatch, operation, runtime)
	_patch(monkeypatch, security, runtime)
	_patch(monkeypatch, _envelope, runtime)

	result = operation.get_operation_status(client_request_id="r1", scope="bogus.scope")
	assert result["success"] is False
	assert result["error"]["code"] == "validation_error"
	assert result["error"]["fields"] == {"scope": "invalid"}
	assert runtime.local.response.get("http_status_code") == 422


def test_mobile_api_maps_authentication_error_to_401(monkeypatch):
	runtime = fake_frappe()
	_patch(monkeypatch, _envelope, runtime)

	@_envelope.mobile_api
	def _handler():
		raise runtime.AuthenticationError("nope")

	out = _handler()
	assert out["success"] is False
	assert out["error"]["code"] == "not_authenticated"
	assert runtime.local.response.get("http_status_code") == 401


def test_mobile_api_maps_company_error_to_422_with_fields(monkeypatch):
	runtime = fake_frappe()
	_patch(monkeypatch, _envelope, runtime)

	@_envelope.mobile_api
	def _handler():
		raise _envelope.CompanyError("pick one")

	out = _handler()
	assert out["success"] is False
	assert out["error"]["code"] == "validation_error"
	assert "company" in out["error"]["fields"]
	assert runtime.local.response.get("http_status_code") == 422


def test_mobile_api_maps_stale_document_error_to_409_with_current_state(monkeypatch):
	runtime = fake_frappe()
	_patch(monkeypatch, _envelope, runtime)

	@_envelope.mobile_api
	def _handler():
		raise _envelope.StaleDocumentError("reload", current={"id": "INV-1", "modified": "t2"})

	out = _handler()
	assert out["success"] is False
	assert out["error"]["code"] == "conflict"
	assert out["data"] == {"id": "INV-1", "modified": "t2"}
	assert runtime.local.response.get("http_status_code") == 409
