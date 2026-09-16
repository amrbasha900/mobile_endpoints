"""Standalone unit tests for the Phase 01 API security boundary.

The repository intentionally does not install Frappe outside Bench.  A small
module stub keeps these tests runnable in CI while every function under test is
given an explicit fake Frappe runtime.
"""

from __future__ import annotations

import datetime
import importlib.util
import json
import sys
import types
from types import SimpleNamespace

import pytest


class AuthenticationError(Exception):
	http_status_code = 401


class PermissionError(Exception):
	http_status_code = 403


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


if importlib.util.find_spec("frappe") is None:
	frappe_stub = types.ModuleType("frappe")
	frappe_stub._ = lambda message: message
	frappe_stub.AuthenticationError = AuthenticationError
	frappe_stub.PermissionError = PermissionError
	frappe_stub.DoesNotExistError = type("DoesNotExistError", (Exception,), {"http_status_code": 404})
	frappe_stub.ValidationError = ValidationError
	frappe_stub.conf = {}
	frappe_stub.local = SimpleNamespace(response={}, request=None, message_log=[])
	frappe_stub.session = SimpleNamespace(user="Guest")
	frappe_stub.whitelist = _whitelist
	frappe_stub.throw = _throw
	# Whichever test module's `import frappe` runs first during pytest collection
	# wins this process-wide sys.modules["frappe"] stub (test_phase02_regression.py
	# defers to it too when already present). mobile_endpoints.api._envelope binds
	# `frappe` at import time, so this module-level stub -- not the richer
	# per-test fake_frappe() below -- is what backs @mobile_api's ok()/exception
	# mapping for any test here that does not explicitly monkeypatch `_envelope`.
	frappe_stub.generate_hash = lambda length=10: "0" * int(length or 10)
	frappe_stub.get_traceback = lambda: "traceback"
	frappe_stub.log_error = lambda *args, **kwargs: None
	frappe_stub.db = SimpleNamespace(rollback=lambda: None, commit=lambda: None)

	frappe_utils = types.ModuleType("frappe.utils")
	frappe_utils.cint = lambda value: int(value or 0)
	frappe_utils.cstr = lambda value: "" if value is None else str(value)
	frappe_utils.flt = lambda value, precision=None: (
		round(float(value or 0), precision) if precision is not None else float(value or 0)
	)
	frappe_utils.get_url = lambda: "https://erp.example.com"
	frappe_utils.now_datetime = lambda: None
	frappe_utils.nowtime = lambda: "00:00:00"
	frappe_utils.today = lambda: "2026-09-09"
	frappe_utils.getdate = lambda v: (
		v if isinstance(v, datetime.date) else datetime.datetime.strptime(str(v), "%Y-%m-%d").date()
	)
	frappe_utils.get_system_timezone = lambda: "Asia/Riyadh"
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


from mobile_endpoints.api import invoice, payment, security, user


class FakeDB:
	def __init__(self):
		self.values = {
			("Customer", "CUST-1", "customer_name"): "Trusted Customer",
			("Supplier", "SUP-1", "supplier_name"): "Trusted Supplier",
		}

	def exists(self, doctype, name):
		return bool(doctype and name)

	def get_value(self, doctype, name, fieldname):
		return self.values.get((doctype, name, fieldname), name)

	def get_single_value(self, doctype, fieldname):
		del doctype, fieldname
		return ""


class FakeMeta:
	def has_field(self, fieldname):
		return fieldname == "pamper_collection"


class FakeDocument:
	def __init__(self):
		self.meta = FakeMeta()
		self.values = {}
		self.rows = []
		self.name = "PAY-1"
		self.posting_date = None
		self.modified = "2026-09-09 00:00:00"
		self.inserted = False

	def update(self, values):
		self.values.update(values)
		self.posting_date = values.get("posting_date")

	def append(self, fieldname, values):
		self.rows.append((fieldname, values))

	def insert(self, ignore_permissions=False):
		assert ignore_permissions is False
		self.inserted = True


def fake_frappe(*, user_name="user@example.com", config=None):
	runtime = SimpleNamespace()
	runtime._ = lambda message: message
	runtime.AuthenticationError = AuthenticationError
	runtime.PermissionError = PermissionError
	runtime.DoesNotExistError = type("DoesNotExistError", (Exception,), {"http_status_code": 404})
	runtime.ValidationError = ValidationError
	runtime.conf = config or {}
	runtime.local = SimpleNamespace(response={}, request=None)
	runtime.session = SimpleNamespace(user=user_name)
	runtime.throw = _throw
	runtime.has_permission = lambda **kwargs: True
	runtime.db = FakeDB()
	return runtime


def test_authentication_error_uses_frappe_v15_exception_status(monkeypatch):
	runtime = fake_frappe(user_name="Guest")
	monkeypatch.setattr(security, "frappe", runtime)

	with pytest.raises(AuthenticationError) as exc_info:
		security.require_authenticated_user()

	assert exc_info.value.http_status_code == 401


def test_cors_requires_an_exact_allowlisted_origin(monkeypatch):
	runtime = fake_frappe(config={"allow_cors": '["https://allowed.example", "*"]'})
	runtime.local.request = SimpleNamespace(headers={"Origin": "https://evil.example"})
	monkeypatch.setattr(security, "frappe", runtime)

	security.set_cors_headers("GET, OPTIONS")
	assert runtime.local.response == {}

	runtime.local.request.headers["Origin"] = "https://allowed.example"
	security.set_cors_headers("GET, OPTIONS")
	assert runtime.local.response["headers"]["Access-Control-Allow-Origin"] == "https://allowed.example"
	assert "Access-Control-Allow-Credentials" not in runtime.local.response["headers"]


def test_invoice_total_ignores_client_supplied_total(monkeypatch):
	runtime = fake_frappe()
	monkeypatch.setattr(invoice, "frappe", runtime)
	monkeypatch.setattr(invoice, "cstr", lambda value: "" if value is None else str(value))
	monkeypatch.setattr(invoice, "flt", lambda value: float(value or 0))
	monkeypatch.setattr(invoice, "require_doctype_permission", lambda *args, **kwargs: None)

	row = invoice._normalized_item(
		{"item_code": "ITEM-1", "qty": 3, "price": 7, "total": 999999, "customer": "CUST-1"}
	)

	assert row["total"] == 21


def test_invoice_row_requires_customer_before_document_insert(monkeypatch):
	runtime = fake_frappe()
	monkeypatch.setattr(invoice, "frappe", runtime)
	monkeypatch.setattr(invoice, "cstr", lambda value: "" if value is None else str(value))
	monkeypatch.setattr(invoice, "flt", lambda value: float(value or 0))
	monkeypatch.setattr(invoice, "require_doctype_permission", lambda *args, **kwargs: None)

	with pytest.raises(ValidationError, match="requires a customer"):
		invoice._normalized_item({"item_code": "ITEM-1", "qty": 1, "price": 7})


def test_payment_uses_server_party_name_and_canonical_type(monkeypatch):
	runtime = fake_frappe()
	document = FakeDocument()
	payload = {
		"posting_date": "2026-09-09",
		"company": "Test Company",
		"detail": {
			"payment_type": "receive",
			"party_type": "Customer",
			"party": "CUST-1",
			"party_name": "Spoofed Name",
			"amount": 25,
			"mode_of_payment": "Cash",
		},
	}
	runtime.request = SimpleNamespace(
		method="POST",
		get_data=lambda as_text=False: json.dumps(payload) if as_text else json.dumps(payload).encode(),
	)
	runtime.local.request = runtime.request
	runtime.new_doc = lambda doctype: document
	runtime.parse_json = json.loads
	runtime.defaults = SimpleNamespace(
		get_user_default=lambda key: "Test Company",
		get_global_default=lambda key: "Test Company",
	)
	monkeypatch.setattr(payment, "frappe", runtime)
	monkeypatch.setattr(payment, "cstr", lambda value: "" if value is None else str(value))
	monkeypatch.setattr(payment, "flt", lambda value: float(value or 0))
	monkeypatch.setattr(payment, "require_authenticated_user", lambda: "user@example.com")
	monkeypatch.setattr(payment, "require_doctype_permission", lambda *args, **kwargs: None)
	monkeypatch.setattr(payment, "set_cors_headers", lambda methods: None)
	# Phase 02 wraps this endpoint: company resolution (BR-06) + server-side
	# idempotency + the @mobile_api envelope. Stub those seams so this test keeps
	# asserting only the Phase 01 guarantee (server-owned party_name / type).
	from mobile_endpoints.api import _envelope

	runtime.generate_hash = lambda length=10: "0" * int(length or 10)
	monkeypatch.setattr(_envelope, "frappe", runtime)
	monkeypatch.setattr(payment, "resolve_company", lambda company: "Test Company")
	monkeypatch.setattr(payment, "run_idempotent", lambda crid, scope, payload, fn: fn()[1])

	result = payment.create_collection_payment()
	row = document.rows[0][1]

	assert result["name"] == "PAY-1"
	assert result["success"] is True
	assert document.inserted is True
	assert row["payment_type"] == "Receive"
	assert row["party_name"] == "Trusted Customer"


def test_cashflow_queries_all_non_cancelled_documents(monkeypatch):
	runtime = fake_frappe()
	calls = []
	runtime.get_list = lambda doctype, **kwargs: calls.append((doctype, kwargs)) or []
	monkeypatch.setattr(payment, "frappe", runtime)
	monkeypatch.setattr(payment, "require_authenticated_user", lambda: "user@example.com")
	monkeypatch.setattr(payment, "require_doctype_permission", lambda *args, **kwargs: None)
	monkeypatch.setattr(payment, "set_cors_headers", lambda methods: None)

	result = payment.get_today_cashflow()

	assert result["net"] == 0
	assert calls[0][1]["limit_page_length"] == 0
	assert calls[0][1]["filters"]["docstatus"] == ("!=", 2)


def test_disabled_legacy_login_is_secure_by_default(monkeypatch):
	runtime = fake_frappe(config={})
	runtime.local.request = SimpleNamespace(method="POST", headers={})
	monkeypatch.setattr(user, "frappe", runtime)
	monkeypatch.setattr(user, "set_cors_headers", lambda methods: None)

	with pytest.raises(user.LegacyLoginDisabledError) as exc_info:
		user.login_with_profile("user@example.com", "secret")

	assert exc_info.value.http_status_code == 410


def test_missing_oauth_configuration_reports_not_configured(monkeypatch):
	"""Phase 03 changed this contract deliberately: discovery is a pre-login
	endpoint, so "this platform isn't set up yet" is a normal answer the client
	must be able to read (alongside `legacy_login_allowed`) — not a 503 that
	tells it nothing. The 503 error surface itself is still exported for the
	documented vocabulary."""
	runtime = fake_frappe(config={})
	runtime.local.request = SimpleNamespace(method="GET", headers={})
	monkeypatch.setattr(user, "frappe", runtime)
	monkeypatch.setattr(user, "set_cors_headers", lambda methods: None)

	resp = user.get_oauth_config(platform="android")

	assert resp["success"] is True
	assert resp["data"]["oauth_configured"] is False
	assert resp["data"]["status"] == "not_configured"
	assert resp["data"]["client_id"] is None
	assert user.OAuthConfigurationError.http_status_code == 503
