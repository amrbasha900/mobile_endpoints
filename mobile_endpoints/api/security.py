"""Shared authentication, CORS, and permission helpers for mobile endpoints."""

from __future__ import annotations

from collections.abc import Iterable

import frappe
from frappe import _
from frappe.utils import cstr


def _configured_origins() -> set[str]:
	"""Return normalized origins from Frappe's ``allow_cors`` site setting."""
	configured = frappe.conf.get("allow_cors") or []
	if isinstance(configured, str):
		configured = configured.split(",")
	if not isinstance(configured, Iterable):
		return set()
	return {cstr(origin).strip().rstrip("/") for origin in configured if cstr(origin).strip()}


def set_cors_headers(methods: str) -> None:
	"""Set browser CORS headers only for an explicitly configured origin.

	Native Android/iOS calls do not need CORS. Web origins must be listed in the
	site's ``allow_cors`` setting. When ``*`` is configured, echoing the request
	origin avoids the invalid wildcard-plus-credentials combination.
	"""
	request = getattr(frappe.local, "request", None)
	origin = cstr(request.headers.get("Origin") if request else "").strip().rstrip("/")
	allowed = _configured_origins()
	if not origin or (origin not in allowed and "*" not in allowed):
		return

	headers = frappe.local.response.setdefault("headers", {})
	headers["Access-Control-Allow-Origin"] = origin
	headers["Vary"] = "Origin"
	headers["Access-Control-Allow-Credentials"] = "true"
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
			http_status_code=401,
		)
	return user


def require_doctype_permission(doctype: str, ptype: str, doc=None) -> None:
	"""Raise HTTP 403 when the active user lacks a document permission."""
	if not frappe.has_permission(doctype=doctype, ptype=ptype, doc=doc):
		frappe.throw(
			_("Not permitted"),
			exc=frappe.PermissionError,
			title=_("Forbidden"),
			http_status_code=403,
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
