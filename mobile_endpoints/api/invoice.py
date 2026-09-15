import json

import frappe
from frappe import _
from frappe.utils import cint, cstr, flt, get_url, now_datetime, nowtime
from frappe.utils.file_manager import save_file

from mobile_endpoints.api._dates import resolve_period, site_timezone
from mobile_endpoints.api._envelope import StaleDocumentError, mobile_api, ok
from mobile_endpoints.api._idempotency import lookup as _idem_lookup
from mobile_endpoints.api._idempotency import run_idempotent
from mobile_endpoints.api.security import (
	require_authenticated_user,
	require_doctype_permission,
	set_cors_headers,
)

DOCTYPE = "Invoice Form"


# --- helpers (Phase 01, from origin/codex/pamper-online-security) -------------

def _display_name(code: str | None, name: str | None) -> str:
	code = cstr(code or "").strip()
	name = cstr(name or "").strip()
	if not code and not name:
		return ""
	if not name or name == code:
		return code or name
	return f"{name} ({code})"


def _get_party_name(doctype: str, party: str) -> str:
	if not party:
		return ""
	return cstr(frappe.db.get_value(doctype, party, "name") or "")


def _get_party_display(doctype: str, party: str, party_name: str | None) -> str:
	stored_name = cstr(party_name or "")
	if stored_name:
		return _display_name(party, stored_name)
	return _display_name(party, _get_party_name(doctype, party))


def _require_link_access(doctype: str, name: str) -> None:
	if not name or not frappe.db.exists(doctype, name):
		frappe.throw(_("Invalid {0}: {1}").format(doctype, name), frappe.ValidationError)
	require_doctype_permission(doctype, "read", name)


def _parse_payload(data: dict | str | None = None) -> dict:
	payload = data
	if payload is None:
		payload = frappe.form_dict.get("data") if frappe.form_dict else None
	if isinstance(payload, str):
		try:
			payload = json.loads(payload or "{}")
		except (TypeError, ValueError):
			frappe.throw(_("Unable to parse JSON body"), frappe.ValidationError)
	if not payload and frappe.request and frappe.request.data:
		try:
			payload = json.loads(frappe.request.data)
		except (TypeError, ValueError):
			frappe.throw(_("Unable to parse JSON body"), frappe.ValidationError)
	if not isinstance(payload, dict):
		frappe.throw(_("JSON body must be an object"), frappe.ValidationError)
	return payload


def _invoice_rates() -> tuple[float, float]:
	"""Financial rates come from site config; clients cannot override them."""
	commission_rate = flt(frappe.conf.get("pamper_commission_rate", 5))
	tax_rate = flt(frappe.conf.get("pamper_tax_rate", 15))
	if not 0 <= commission_rate <= 100 or not 0 <= tax_rate <= 100:
		frappe.throw(_("Pamper commission and tax rates must be between 0 and 100"))
	return commission_rate, tax_rate


def _normalized_item(item: dict) -> dict:
	if not isinstance(item, dict):
		frappe.throw(_("Every invoice row must be an object"), frappe.ValidationError)
	item_code = cstr(item.get("item_code") or item.get("item_name")).strip()
	customer = cstr(item.get("customer") or item.get("customerId")).strip()
	qty = flt(item.get("qty") if item.get("qty") is not None else item.get("quantity"))
	price = flt(item.get("price"))
	if not item_code:
		frappe.throw(_("Every invoice row requires an item"), frappe.ValidationError)
	if not customer:
		frappe.throw(_("Every invoice row requires a customer"), frappe.ValidationError)
	if qty <= 0:
		frappe.throw(
			_("Quantity must be greater than zero for item {0}").format(item_code), frappe.ValidationError
		)
	if price < 0:
		frappe.throw(_("Price must not be negative for item {0}").format(item_code), frappe.ValidationError)
	_require_link_access("Item", item_code)
	_require_link_access("Customer", customer)
	return {
		"item_code": item_code,
		"item_name": cstr(frappe.db.get_value("Item", item_code, "item_name") or item_code),
		"qty": qty,
		"price": price,
		"total": qty * price,
		"customer": customer,
	}


# --- editability: ONE source of truth ---------------------------------------
#
# `lock_update` is a legacy flag this app itself stamps onto every invoice it
# creates; it never gated anything server-side (update_invoice has always
# checked docstatus + write permission, never lock_update). Feeding it into the
# permissions payload as `locked` produced a response that contradicted itself
# -- `update: true` together with `locked: true` -- which the mobile list read
# as "not editable" while the edit route and the update endpoint both happily
# allowed the edit. It is deliberately NOT consulted here any more, so the
# invoices already carrying it behave like any other draft. No existing data is
# touched; create simply stops stamping it (see create_invoice_form).


def _invoice_is_editable(doc) -> bool:
	"""Draft/Pending (docstatus 0) + document-level write permission. Submitted
	(1) and Cancelled (2) are never editable. This is the single rule behind
	get_invoices, get_invoice_details and update_invoice alike."""
	if int(getattr(doc, "docstatus", 0) or 0) != 0:
		return False
	return bool(doc.has_permission("write"))


def _invoice_permissions(doc) -> dict[str, bool]:
	"""UI hints derived from _invoice_is_editable, so `update` and `locked` can
	never disagree: locked is exactly "not editable"."""
	editable = _invoice_is_editable(doc)
	docstatus = int(getattr(doc, "docstatus", 0) or 0)
	return {
		"read": bool(doc.has_permission("read")),
		"update": editable,
		"delete": docstatus == 0 and bool(doc.has_permission("delete")),
		"submit": docstatus == 0 and bool(doc.has_permission("submit")),
		"print": bool(doc.has_permission("print") or doc.has_permission("read")),
		"locked": not editable,
	}


# --- helpers (Phase 02) -----------------------------------------------------

def _request_meta() -> dict:
	"""Pull the top-level reliability fields out of the raw JSON body once."""
	body = {}
	if frappe.request and (getattr(frappe.request, "method", "") or "").upper() == "POST":
		try:
			body = frappe.parse_json(frappe.request.get_data(as_text=True) or "{}")
		except Exception:
			body = {}
	if not isinstance(body, dict):
		body = {}
	fd = frappe.form_dict or {}
	inner = body.get("data") if isinstance(body.get("data"), dict) else {}
	return {
		"client_request_id": body.get("client_request_id")
		or fd.get("client_request_id")
		or inner.get("client_request_id"),
		"base_modified": body.get("base_modified") or fd.get("base_modified"),
		"name": body.get("name") or fd.get("name") or inner.get("name"),
	}


def _details_dict(doc) -> dict:
	"""Compact current-state snapshot used in a 409 body."""
	status_map = {0: "draft", 1: "submitted", 2: "cancelled"}
	items = []
	for it in getattr(doc, "items", []):
		item_code = cstr(getattr(it, "item_code", "")) or cstr(getattr(it, "item_name", ""))
		item_name = cstr(getattr(it, "item_name", "")) or item_code
		display = _display_name(item_code, item_name)
		items.append({
			"id": cstr(getattr(it, "name", "")),
			"name": display,
			"item_display": display,
			"quantity": flt(getattr(it, "qty", 0) or 0),
			"price": flt(getattr(it, "price", 0) or 0),
			"total": flt(getattr(it, "total", 0) or 0),
			"customerId": cstr(getattr(it, "customer", "")),
			"customerName": cstr(getattr(it, "customer", "")),
		})
	return {
		"id": cstr(getattr(doc, "name", "")),
		"invoiceNumber": cstr(getattr(doc, "name", "")),
		"supplierId": cstr(getattr(doc, "supplier", "")),
		"supplierName": _get_party_display("Supplier", getattr(doc, "supplier", ""), getattr(doc, "supplier_name", "")),
		"supplierCode": cstr(getattr(doc, "supplier", "")),
		"date": cstr(getattr(doc, "posting_date", "")),
		"posting_date": cstr(getattr(doc, "posting_date", "")),
		"posting_time": cstr(getattr(doc, "posting_time", "")),
		"amount": flt(getattr(doc, "grand_total", 0) or 0),
		"status": status_map.get(doc.docstatus or 0, "draft"),
		"tax": flt(getattr(doc, "total_commissions_and_taxes", 0) or 0),
		"customer": cstr(getattr(doc, "customer", "")),
		"customer_name": _get_party_display("Customer", getattr(doc, "customer", ""), getattr(doc, "customer_name", "")),
		"items": items,
		"modified": cstr(getattr(doc, "modified", "")),
	}


# --- reads (Phase 01, restored verbatim) -----------------------------------

@frappe.whitelist(allow_guest=True, methods=["GET"])
@mobile_api
def get_invoice_references(limit: int | str = 200):
	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()

	limit = max(1, min(1000, cint(limit)))

	suppliers = frappe.get_list(
		"Supplier", filters={"disabled": 0}, fields=["name", "supplier_name"],
		order_by="modified desc", limit_page_length=limit,
	)
	customers = frappe.get_list(
		"Customer", filters={"disabled": 0}, fields=["name", "customer_name"],
		order_by="modified desc", limit_page_length=limit,
	)
	items = frappe.get_list(
		"Item", filters={"disabled": 0}, fields=["name", "item_name"],
		order_by="modified desc", limit_page_length=limit,
	)

	return {
		"suppliers": [
			{"code": cstr(r.name), "name": cstr(r.supplier_name or r.name),
			 "display": _display_name(r.name, r.supplier_name or r.name)}
			for r in suppliers
		],
		"customers": [
			{"code": cstr(r.name), "name": cstr(r.customer_name or r.name),
			 "display": _display_name(r.name, r.customer_name or r.name)}
			for r in customers
		],
		"items": [
			{"code": cstr(r.name), "name": cstr(r.item_name or r.name),
			 "display": _display_name(r.name, r.item_name or r.name)}
			for r in items
		],
	}


@frappe.whitelist(allow_guest=True, methods=["GET"])
@mobile_api
def get_invoices(
	start_date: str | None = None,
	end_date: str | None = None,
	from_date: str | None = None,
	to_date: str | None = None,
	supplier: str | None = None,
	status: str | None = None,
	page: int | str = 1,
	page_size: int | str = 20,
	search: str | None = None,
):
	"""`from_date`/`to_date` are canonical; `start_date`/`end_date` are kept
	as aliases for backward compatibility with existing callers. Neither
	given -> defaults to "today" in the site timezone (see resolve_period)."""
	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()

	if not frappe.has_permission(doctype=DOCTYPE, ptype="read"):
		frappe.throw("Not permitted", frappe.PermissionError)

	page = max(1, cint(page))
	page_size = max(1, min(100, cint(page_size)))
	start = (page - 1) * page_size

	resolved_from, resolved_to = resolve_period(from_date or start_date, to_date or end_date)

	# Filters shared by rows AND the summary (date range + search + supplier)
	# -- everything EXCEPT the currently-selected status, so the summary can
	# ignore just that one (see the summary block below).
	base_filters = [
		["posting_date", ">=", resolved_from],
		["posting_date", "<=", resolved_to],
	]
	if supplier:
		base_filters.append(["supplier", "=", cstr(supplier)])

	meta = frappe.get_meta(DOCTYPE)
	pending_field = "status" if meta.has_field("status") else ("workflow_state" if meta.has_field("workflow_state") else None)

	filters = list(base_filters)
	if status:
		normalized = cstr(status).strip().lower()
		status_map = {"draft": 0, "submitted": 1, "cancelled": 2}
		if normalized in status_map:
			filters.append(["docstatus", "=", status_map[normalized]])
		elif normalized == "pending":
			if pending_field:
				filters.append(["docstatus", "=", 0])
				filters.append([pending_field, "=", "Pending"])
			else:
				filters.append(["docstatus", "=", 0])
		else:
			frappe.throw(_("Unsupported invoice status"), frappe.ValidationError)

	fields = ["name", "posting_date", "supplier", "supplier_name", "grand_total", "docstatus"]
	if meta.has_field("status"):
		fields.append("status")
	if meta.has_field("workflow_state"):
		fields.append("workflow_state")

	or_filters = None
	if search:
		s = cstr(search).strip()
		if s:
			or_filters = [
				["name", "like", f"%{s}%"],
				["supplier_name", "like", f"%{s}%"],
				["supplier", "like", f"%{s}%"],
			]
			if meta.has_field("customer"):
				or_filters.append(["customer", "like", f"%{s}%"])
			if meta.has_field("customer_name"):
				or_filters.append(["customer_name", "like", f"%{s}%"])

	rows = frappe.get_list(
		DOCTYPE, fields=fields, filters=filters, or_filters=or_filters,
		order_by="posting_date desc, creation desc", start=start, page_length=page_size,
	)

	count_rows = frappe.get_list(
		DOCTYPE, fields=["count(name) as total_count"], filters=filters, or_filters=or_filters,
		limit_page_length=1,
	)
	total_count = cint(count_rows[0].total_count) if count_rows else 0

	status_map = {0: "draft", 1: "submitted", 2: "cancelled"}
	invoices = []
	for r in rows:
		status_value = status_map.get(cint(r.docstatus or 0), "draft")
		if status_value == "draft":
			doc_status = cstr(getattr(r, "status", "")) or cstr(getattr(r, "workflow_state", ""))
			if doc_status.lower() == "pending":
				status_value = "pending"

		supplier_display = _get_party_display("Supplier", r.supplier, r.supplier_name)
		doc = frappe.get_doc(DOCTYPE, r.name)
		permissions = _invoice_permissions(doc)
		invoices.append({
			"id": r.name,
			"invoiceNumber": r.name,
			"supplierId": r.supplier or "",
			"supplierName": supplier_display,
			"supplierCode": r.supplier or "",
			"supplierRawName": r.supplier_name or "",
			"date": cstr(r.posting_date),
			"amount": float(r.grand_total or 0),
			"status": status_value,
			"permissions": permissions,
			"permission": {
				"can_update": permissions["update"],
				"can_delete": permissions["delete"],
				"can_submit": permissions["submit"],
				"locked": permissions["locked"],
			},
		})

	has_more = (start + len(invoices)) < total_count

	# --- summary -----------------------------------------------------------
	# Every authorized record matching the SAME date/search/supplier filters
	# as the rows above -- the whole filtered set, not just this page -- but
	# ignoring only the currently-selected status filter (base_filters, not
	# filters), so every status card stays accurate no matter which tab is
	# active. Permission-aware: frappe.get_list, never get_all/ignore_permissions.
	def _bucket_count(extra_filters):
		bucket_rows = frappe.get_list(
			DOCTYPE, fields=["count(name) as c"],
			filters=base_filters + extra_filters, or_filters=or_filters,
			limit_page_length=1,
		)
		return cint(bucket_rows[0].c) if bucket_rows else 0

	submitted_count = _bucket_count([["docstatus", "=", 1]])
	cancelled_count = _bucket_count([["docstatus", "=", 2]])
	draft_and_pending_count = _bucket_count([["docstatus", "=", 0]])
	if pending_field:
		# Subtraction (not a `!= 'Pending'` filter) so rows with a NULL/blank
		# status field -- SQL `!=` never matches NULL -- are still counted as
		# drafts instead of silently disappearing from both buckets.
		pending_count = _bucket_count([["docstatus", "=", 0], [pending_field, "=", "Pending"]])
	else:
		pending_count = 0
	draft_count = draft_and_pending_count - pending_count

	summary = {
		"total": submitted_count + cancelled_count + draft_count + pending_count,
		"submitted": submitted_count,
		"draft": draft_count,
		"pending": pending_count,
		"cancelled": cancelled_count,
	}

	data = {
		"invoices": invoices,
		"page": page,
		"page_size": page_size,
		"total_count": total_count,
		"has_more": has_more,
		"summary": summary,
		"period": {"from_date": resolved_from, "to_date": resolved_to, "timezone": site_timezone()},
	}
	return ok(data, meta={"total_count": total_count})


@frappe.whitelist(allow_guest=True, methods=["GET"])
@mobile_api
def get_invoice_details(name: str | None = None):
	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()
	if not name:
		frappe.throw(_("Missing invoice name"), frappe.ValidationError)

	doc = frappe.get_doc(DOCTYPE, name)
	if not doc.has_permission("read"):
		frappe.throw("Not permitted", frappe.PermissionError)

	status_map = {0: "draft", 1: "submitted", 2: "cancelled"}
	status = status_map.get(doc.docstatus or 0, "draft")
	# Same rule as the permissions block below -- never the legacy flag.
	is_locked = not _invoice_is_editable(doc)

	items = []
	doc_customer = cstr(getattr(doc, "customer", ""))
	doc_customer_name = cstr(getattr(doc, "customer_name", ""))

	for it in getattr(doc, "items", []):
		item_code = cstr(getattr(it, "item_code", "")) or cstr(getattr(it, "item_name", ""))
		item_name = cstr(getattr(it, "item_name", "")) or item_code
		item_display = _display_name(item_code, item_name)
		customer_code = cstr(getattr(it, "customer", ""))
		customer_name = ""
		if customer_code and doc_customer and customer_code == doc_customer:
			customer_name = doc_customer_name
		customer_display = _get_party_display("Customer", customer_code, customer_name)
		items.append({
			"id": cstr(getattr(it, "name", "")),
			"name": item_display,
			"item_code": item_code,
			"item_name": item_name,
			"item_display": item_display,
			"quantity": float(getattr(it, "qty", 0) or 0),
			"price": float(getattr(it, "price", 0) or 0),
			"total": float(getattr(it, "total", 0) or 0),
			"customerId": customer_code,
			"customerName": customer_name or customer_display,
			"customerDisplay": customer_display,
		})

	supplier_display = _get_party_display("Supplier", getattr(doc, "supplier", ""), getattr(doc, "supplier_name", ""))
	customer_display = _get_party_display("Customer", getattr(doc, "customer", ""), getattr(doc, "customer_name", ""))

	permissions = _invoice_permissions(doc)
	return {
		"id": cstr(getattr(doc, "name", name)),
		"invoiceNumber": cstr(getattr(doc, "name", name)),
		"supplierId": cstr(getattr(doc, "supplier", "")),
		"supplierName": supplier_display,
		"supplierCode": cstr(getattr(doc, "supplier", "")),
		"supplierRawName": cstr(getattr(doc, "supplier_name", "")),
		"date": cstr(getattr(doc, "posting_date", "")),
		"posting_date": cstr(getattr(doc, "posting_date", "")),
		"posting_time": cstr(getattr(doc, "posting_time", "")),
		"amount": float(getattr(doc, "grand_total", 0) or 0),
		"status": status,
		"is_locked": is_locked,
		"items": items,
		"tax": float(getattr(doc, "total_commissions_and_taxes", 0) or 0),
		"payments": [],
		"notes": cstr(getattr(doc, "remarks", "")),
		"customer": cstr(getattr(doc, "customer", "")),
		"customer_name": customer_display,
		"customer_code": cstr(getattr(doc, "customer", "")),
		"customer_raw_name": cstr(getattr(doc, "customer_name", "")),
		# version token for optimistic concurrency
		"modified": cstr(getattr(doc, "modified", "")),
		"permissions": permissions,
		"permission": {
			"can_update": permissions["update"],
			"can_delete": permissions["delete"],
			"can_submit": permissions["submit"],
			"locked": permissions["locked"],
		},
	}


@frappe.whitelist(allow_guest=True, methods=["POST"])
@mobile_api
def print_invoice(name: str | None = None, print_format: str | None = None):
	set_cors_headers("POST, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()
	if not name:
		frappe.throw("Missing invoice name")

	doc = frappe.get_doc(DOCTYPE, name)
	if not doc.has_permission("read"):
		frappe.throw("Not permitted", frappe.PermissionError)

	pdf_content = frappe.get_print(DOCTYPE, name, print_format=print_format or None, as_pdf=True)
	timestamp = now_datetime().strftime("%Y%m%d%H%M%S")
	filename = f"{name}-{timestamp}.pdf"
	file_doc = save_file(filename, pdf_content, DOCTYPE, name, is_private=1)
	file_url = file_doc.file_url or ""
	return {
		"file_url": f"{get_url()}{file_url}" if file_url and not file_url.startswith("http") else file_url
	}


@frappe.whitelist(allow_guest=True, methods=["GET"])
@mobile_api
def get_invoice_by_request_id(client_request_id: str | None = None):
	"""Post-timeout check for a create. See operation.get_operation_status for the
	generic version."""
	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}
	require_authenticated_user()
	return _idem_lookup(client_request_id, "invoice.create")


# --- writes (Phase 01 hardening + Phase 02 idempotency/concurrency) ----------

@frappe.whitelist(allow_guest=True, methods=["POST"])
@mobile_api
def create_invoice_form():
	set_cors_headers("POST, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()
	require_doctype_permission("Invoice Form", "create")

	data = _parse_payload()
	client_request_id = _request_meta()["client_request_id"] or data.get("client_request_id")

	posting_date = data.get("posting_date")
	supplier = cstr(data.get("supplier")).strip()
	if not posting_date or not supplier:
		frappe.throw("Missing required fields: posting_date, supplier")

	_require_link_access("Supplier", supplier)
	supplier_name = frappe.db.get_value("Supplier", supplier, "supplier_name") or supplier
	customer = cstr(data.get("customer")).strip()
	if customer:
		_require_link_access("Customer", customer)
	customer_name = (frappe.db.get_value("Customer", customer, "customer_name") or customer) if customer else ""

	items = data.get("items") or []
	if not items:
		frappe.throw("At least one item is required")

	commission_rate, tax_rate = _invoice_rates()
	normalized_items = [_normalized_item(item) for item in items]
	grand_total = sum(item["total"] for item in normalized_items)
	total_commission = (grand_total * commission_rate) / 100.0
	total_commissions_and_taxes = total_commission + (total_commission * tax_rate) / 100.0

	idem_payload = {
		"posting_date": posting_date,
		"supplier": supplier,
		"customer": customer,
		"items": normalized_items,
	}

	def _create():
		doc = frappe.get_doc({
			"doctype": DOCTYPE,
			"posting_date": posting_date,
			"posting_time": nowtime(),
			"is_draft": 1,
			"supplier": supplier,
			"supplier_name": supplier_name,
			"customer": customer,
			"customer_name": customer_name,
			"pamper_commission": 0.0,
			"grand_total": grand_total,
			"total_commissions_and_taxes": total_commissions_and_taxes,
			"items": [],
			"commissions": [],
		})
		for it in normalized_items:
			doc.append("items", {
				"item_code": it["item_code"],
				"item_name": it["item_name"],
				"qty": it["qty"],
				"price": it["price"],
				"total": it["total"],
				"customer": it["customer"],
			})
		doc.insert(ignore_permissions=False)  # no commit — run_idempotent owns the txn
		response = {
			"name": doc.name,
			"posting_date": doc.posting_date,
			"posting_time": doc.get("posting_time"),
			"supplier": doc.supplier,
			"supplier_name": doc.supplier_name,
			"customer": doc.get("customer"),
			"customer_name": doc.get("customer_name"),
			"grand_total": doc.get("grand_total"),
			"total_commissions_and_taxes": doc.get("total_commissions_and_taxes"),
			"pamper_commission": doc.get("pamper_commission"),
			"modified": cstr(doc.modified),
			"doctype": doc.doctype,
			"items": [
				{
					"item_code": r.item_code,
					"item_name": r.item_name,
					"qty": r.qty,
					"price": r.price,
					"total": r.total,
					"customer": r.get("customer"),
				}
				for r in doc.items
			],
			"commissions": [
				{
					"item": r.item,
					"price": r.price,
					"commission": r.commission,
					"total_commission": r.total_commission,
					"taxes": r.taxes,
					"commission_total": r.commission_total,
				}
				for r in doc.commissions
			],
		}
		return doc.name, response

	return run_idempotent(client_request_id, "invoice.create", idem_payload, _create)


@frappe.whitelist(allow_guest=True, methods=["POST"])
@mobile_api
def update_invoice(name: str | None = None, data: dict | None = None):
	set_cors_headers("POST, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()

	meta = _request_meta()
	name = name or meta["name"]
	if not name:
		frappe.throw("Missing invoice name")
	payload = _parse_payload(data)
	base_modified = meta["base_modified"]
	client_request_id = meta["client_request_id"] or payload.get("client_request_id")

	def _do():
		doc = frappe.get_doc(DOCTYPE, name)
		if not doc.has_permission("write"):
			frappe.throw("Not permitted", frappe.PermissionError)
		if not _invoice_is_editable(doc):
			frappe.throw(_("Only draft invoices can be updated"), frappe.ValidationError)

		# Optimistic concurrency — fresh path only; a replay returns the stored result.
		if base_modified and cstr(doc.modified) != cstr(base_modified):
			raise StaleDocumentError(
				_("This invoice was changed on the server. Reload the latest data and try again."),
				current=_details_dict(doc),
			)

		if payload.get("posting_date"):
			doc.posting_date = payload.get("posting_date")
		if payload.get("supplier"):
			supplier = cstr(payload.get("supplier")).strip()
			_require_link_access("Supplier", supplier)
			doc.supplier = supplier
			doc.supplier_name = frappe.db.get_value("Supplier", supplier, "supplier_name") or supplier
		if payload.get("customer"):
			customer = cstr(payload.get("customer")).strip()
			_require_link_access("Customer", customer)
			doc.customer = customer
			doc.customer_name = frappe.db.get_value("Customer", customer, "customer_name") or customer

		if isinstance(payload.get("items"), list):
			doc.set("items", [])
			normalized_items = [_normalized_item(it) for it in payload["items"]]
			if not normalized_items:
				frappe.throw(_("At least one item is required"), frappe.ValidationError)
			for it in normalized_items:
				row = doc.append("items", {})
				row.item_code = it["item_code"]
				row.item_name = it["item_name"]
				row.qty = it["qty"]
				row.price = it["price"]
				row.total = it["total"]
				row.customer = it["customer"]
			grand_total = sum(item["total"] for item in normalized_items)
			commission_rate, tax_rate = _invoice_rates()
			total_commission = grand_total * commission_rate / 100.0
			doc.grand_total = grand_total
			doc.total_commissions_and_taxes = total_commission + (total_commission * tax_rate / 100.0)

		doc.save(ignore_permissions=False)  # no commit — run_idempotent owns the txn
		return doc.name, {
			"name": cstr(doc.name),
			"modified": cstr(doc.modified),
			"grand_total": float(doc.get("grand_total") or 0),
			"total_commissions_and_taxes": float(doc.get("total_commissions_and_taxes") or 0),
		}

	return run_idempotent(client_request_id, "invoice.update", {"name": name, "data": payload}, _do)


@frappe.whitelist(allow_guest=True, methods=["POST"])
@mobile_api
def submit_invoice(name: str | None = None):
	set_cors_headers("POST, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()

	meta = _request_meta()
	name = name or meta["name"]
	if not name:
		frappe.throw("Missing invoice name")

	def _do():
		doc = frappe.get_doc(DOCTYPE, name)
		if not doc.has_permission("submit"):
			frappe.throw("Not permitted", frappe.PermissionError)
		if doc.docstatus != 0:
			frappe.throw("Only draft invoices can be submitted")
		doc.submit()  # no commit
		return doc.name, {"name": cstr(doc.name), "docstatus": doc.docstatus, "modified": cstr(doc.modified)}

	return run_idempotent(meta["client_request_id"], "invoice.submit", {"name": name}, _do)


@frappe.whitelist(allow_guest=True, methods=["POST"])
@mobile_api
def delete_invoice(name: str | None = None):
	set_cors_headers("POST, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()

	meta = _request_meta()
	name = name or meta["name"]
	if not name:
		frappe.throw("Missing invoice name")

	def _do():
		doc = frappe.get_doc(DOCTYPE, name)
		if not doc.has_permission("delete"):
			frappe.throw("Not permitted", frappe.PermissionError)
		frappe.delete_doc(DOCTYPE, name, ignore_permissions=False)  # no commit
		return name, {"deleted": True, "name": cstr(name)}

	# Replaying the deleting request id returns {deleted:true}; a *fresh* id
	# against an already-gone doc still raises DoesNotExistError -> 404.
	return run_idempotent(meta["client_request_id"], "invoice.delete", {"name": name}, _do)
