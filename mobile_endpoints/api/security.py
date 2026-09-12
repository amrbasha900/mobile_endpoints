"""Shared authentication, CORS, and permission helpers for mobile endpoints."""

from __future__ import annotations

import json
from collections.abc import Iterable

import frappe
from frappe import _
from frappe.utils import cstr


def _configured_origins() -> set[str]:
	"""Return normalized origins from Frappe's ``allow_cors`` site setting."""
	configured = frappe.conf.get("allow_cors") or []
	if isinstance(configured, str):
		try:
			parsed = json.loads(configured)
		except (TypeError, ValueError):
			parsed = configured.split(",")
		configured = parsed if isinstance(parsed, list) else [parsed]
	if not isinstance(configured, Iterable):
		return set()
	return {
		cstr(origin).strip().rstrip("/")
		for origin in configured
		if cstr(origin).strip() and cstr(origin).strip() != "*"
	}


def set_cors_headers(methods: str) -> None:
	"""Set browser CORS headers only for an explicitly configured origin.

	Native Android/iOS calls do not need CORS. Web origins must be listed exactly
	in the site's ``allow_cors`` setting. A wildcard is deliberately ignored here
	because reflecting arbitrary origins together with credentials is unsafe.

	``frappe.local.request`` is not always a real werkzeug request: a background
	job, a console call, or (in the test harness) a bare ``frappe._dict`` leaves
	it either missing or without a ``headers`` key. ``frappe._dict.__getattr__``
	then returns ``None`` instead of raising, so ``request.headers`` must never
	be dereferenced directly -- doing so previously crashed every endpoint with
	``AttributeError: 'NoneType' object has no attribute 'get'`` before the
	handler's own logic (auth, validation, ...) ever ran.
	"""
	request = getattr(frappe.local, "request", None)
	headers = getattr(request, "headers", None) if request is not None else None
	if headers is None:
		headers = {}
	get_header = getattr(headers, "get", None) or (lambda *_a: None)
	origin = cstr(get_header("Origin") or "").strip().rstrip("/")
	allowed = _configured_origins()
	if not origin or origin not in allowed:
		return

	headers = frappe.local.response.setdefault("headers", {})
	headers["Access-Control-Allow-Origin"] = origin
	headers["Vary"] = "Origin"
	headers["Access-Control-Allow-Methods"] = methods
	headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Request-ID"


def require_authenticated_user() -> str:
	"""Return the authenticated Frappe user or raise a real HTTP 401."""
	user = cstr(getattr(frappe.session, "user", ""))
	if not user or user == "Guest":
		frappe.throw(
			_("Authentication required"),
			exc=frappe.AuthenticationError,
			title=_("Unauthorized"),
		)
	return user


def require_doctype_permission(doctype: str, ptype: str, doc=None) -> None:
	"""Raise HTTP 403 when the active user lacks a document permission."""
	if not frappe.has_permission(doctype=doctype, ptype=ptype, doc=doc):
		frappe.throw(
			_("Not permitted"),
			exc=frappe.PermissionError,
			title=_("Forbidden"),
		)


def document_permissions(doc) -> dict[str, bool]:
	"""Return UI hints backed by the same server-side permission checks."""
	docstatus = int(getattr(doc, "docstatus", 0) or 0)
	locked = bool(getattr(doc, "lock_update", False))
	return {
		"read": bool(doc.has_permission("read")),
		"update": docstatus == 0 and bool(doc.has_permission("write")),
		"delete": docstatus == 0 and bool(doc.has_permission("delete")),
		"submit": docstatus == 0 and bool(doc.has_permission("submit")),
		"print": bool(doc.has_permission("print") or doc.has_permission("read")),
		"locked": locked,
	}
