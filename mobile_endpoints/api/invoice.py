import json

import frappe
from frappe.utils import cint, cstr, flt, nowtime

from mobile_endpoints.api._envelope import StaleDocumentError, mobile_api
from mobile_endpoints.api._idempotency import lookup as _idem_lookup
from mobile_endpoints.api._idempotency import run_idempotent

DOCTYPE = "Invoice Form"


# --- helpers -------------------------------------------------------------------

def _read_body() -> dict:
	"""Return the request body as a dict, tolerating every shape the client has
	used: a raw JSON object, `{"data": {...}}`, or `{"data": "<json string>"}`.
	"""
	body = {}
	if frappe.request and (frappe.request.method or "").upper() == "POST":
		try:
			raw = frappe.request.get_data(as_text=True) or "{}"
			body = frappe.parse_json(raw) if raw.strip() else {}
		except Exception:
			body = {}
	if not isinstance(body, dict) or not body:
		body = dict(frappe.form_dict or {})

	data = body.get("data", body)
	if isinstance(data, str):
		try:
			data = json.loads(data or "{}")
		except Exception:
			data = {}
	if not isinstance(data, dict):
		data = {}
	return {
		"client_request_id": body.get("client_request_id"),
		"data": data,
		"base_modified": body.get("base_modified"),
		"name": body.get("name") or data.get("name"),
	}


def _details_dict(doc) -> dict:
	status_map = {0: "draft", 1: "submitted", 2: "cancelled"}
	status = status_map.get(doc.docstatus or 0, "draft")
	is_locked = bool(getattr(doc, "lock_update", False))
	items = []
	for it in getattr(doc, "items", []):
		display = cstr(getattr(it, "item_name", "") or getattr(it, "item_code", ""))
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
		"supplierName": cstr(getattr(doc, "supplier_name", "")),
		"supplierCode": cstr(getattr(doc, "supplier", "")),
		"date": cstr(getattr(doc, "posting_date", "")),
		"posting_date": cstr(getattr(doc, "posting_date", "")),
		"posting_time": cstr(getattr(doc, "posting_time", "")),
		"amount": flt(getattr(doc, "grand_total", 0) or 0),
		"status": status,
		"is_locked": is_locked,
		"items": items,
		"tax": flt(getattr(doc, "total_commissions_and_taxes", 0) or 0),
		"customer": cstr(getattr(doc, "customer", "")),
		"customer_name": cstr(getattr(doc, "customer", "")),
		"modified": cstr(getattr(doc, "modified", "")),
		"permission": {
			"can_update": True,
			"can_delete": True,
			"can_submit": True,
			"locked": is_locked,
		},
	}


# --- reads -----------------------------------------------------------------

@frappe.whitelist(methods=["GET"])
@mobile_api
def get_invoices(
	start_date: str | None = None,
	end_date: str | None = None,
	supplier: str | None = None,
	page: int | str = 1,
	page_size: int | str = 20,
	search: str | None = None,
):
	if not frappe.has_permission(doctype=DOCTYPE, ptype="read"):
		frappe.throw("Not permitted", frappe.PermissionError)

	page = max(1, cint(page))
	page_size = max(1, min(100, cint(page_size)))
	start = (page - 1) * page_size

	filters = []
	if start_date:
		filters.append(["posting_date", ">=", cstr(start_date)])
	if end_date:
		filters.append(["posting_date", "<=", cstr(end_date)])
	if supplier:
		filters.append(["supplier", "=", cstr(supplier)])

	rows = frappe.get_all(
		DOCTYPE,
		fields=["name", "posting_date", "supplier", "supplier_name", "grand_total"],
		filters=filters,
		order_by="posting_date desc, creation desc",
		start=start,
		page_length=page_size,
		ignore_permissions=False,
	)
	if search:
		s = cstr(search).strip().lower()
		rows = [r for r in rows if s in cstr(r.name).lower() or s in cstr(r.get("supplier_name") or "").lower()]

	total_count = frappe.db.count(DOCTYPE, filters=filters)
	invoices = [{
		"id": r.name,
		"invoiceNumber": r.name,
		"supplierId": r.supplier or "",
		"supplierName": r.supplier_name or "",
		"supplierCode": r.supplier or "",
		"date": cstr(r.posting_date),
		"amount": flt(r.grand_total or 0),
		"permission": {"can_update": True, "can_delete": True, "can_submit": True, "locked": False},
	} for r in rows]

	has_more = (start + len(invoices)) < total_count
	return {
		"invoices": invoices,
		"page": page,
		"page_size": page_size,
		"total_count": total_count,
		"has_more": has_more,
	}


@frappe.whitelist(methods=["GET"])
@mobile_api
def get_invoice_details(name: str):
	if not name:
		frappe.throw("Missing invoice name")
	doc = frappe.get_doc(DOCTYPE, name)
	if not doc.has_permission("read"):
		frappe.throw("Not permitted", frappe.PermissionError)
	return _details_dict(doc)


@frappe.whitelist(methods=["GET"])
@mobile_api
def get_invoice_by_request_id(client_request_id: str):
	"""Called by the client after a create POST times out, to discover whether
	the invoice was actually created."""
	return _idem_lookup(client_request_id, "invoice.create")


# --- writes --------------------------------------------------------------------

@frappe.whitelist(methods=["POST"])
@mobile_api
def create_invoice_form():
	body = _read_body()
	data = body["data"]
	client_request_id = body["client_request_id"]

	posting_date = data.get("posting_date")
	supplier = data.get("supplier")
	if not posting_date or not supplier:
		frappe.throw("Missing required fields: posting_date, supplier")

	supplier_name = data.get("supplier_name") or ""
	items = data.get("items") or []
	if not items:
		frappe.throw("At least one item is required")

	commission_rate = flt(data.get("commission_rate") or 5)
	tax_rate = flt(data.get("tax_rate") or 15)
	pamper_commission = flt(data.get("pamper_commission") or 0)

	# Server is the source of truth for totals.
	grand_total = 0.0
	for it in items:
		qty = flt(it.get("qty") or it.get("quantity") or 0)
		price = flt(it.get("price") or 0)
		if not it.get("item_code") and it.get("item_name"):
			it["item_code"] = it["item_name"]
		line_total = flt(it.get("total")) or (qty * price)
		it["total"] = line_total
		grand_total += line_total

	total_commission = (grand_total * commission_rate) / 100.0
	taxes_on_commission = (total_commission * tax_rate) / 100.0
	total_commissions_and_taxes = total_commission + taxes_on_commission

	def _create():
		doc = frappe.get_doc({
			"doctype": DOCTYPE,
			"posting_date": posting_date,
			"posting_time": nowtime(),
			"is_draft": 1,
			"lock_update": 1,
			"supplier": supplier,
			"supplier_name": supplier_name,
			"pamper_commission": pamper_commission,
			"grand_total": grand_total,
			"total_commissions_and_taxes": total_commissions_and_taxes,
			"items": [],
			"commissions": [],
		})
		for it in items:
			doc.append("items", {
				"item_code": it.get("item_code"),
				"item_name": it.get("item_name") or it.get("item_code"),
				"qty": flt(it.get("qty") or it.get("quantity") or 0),
				"price": flt(it.get("price") or 0),
				"total": flt(it.get("total") or 0),
				"customer": it.get("customer") or "",
			})
		doc.insert(ignore_permissions=True)
		# NOTE: no commit here — run_idempotent() owns the transaction so the
		# key reservation and this insert commit atomically.

		response = {
			"name": doc.name,
			"posting_date": doc.posting_date,
			"posting_time": doc.get("posting_time"),
			"supplier": doc.supplier,
			"supplier_name": doc.supplier_name,
			"grand_total": doc.get("grand_total"),
			"total_commissions_and_taxes": doc.get("total_commissions_and_taxes"),
			"pamper_commission": doc.get("pamper_commission"),
			"modified": cstr(doc.modified),
			"doctype": doc.doctype,
			"items": [{
				"item_code": r.item_code,
				"item_name": r.item_name,
				"qty": r.qty,
				"price": r.price,
				"total": r.total,
				"customer": r.get("customer"),
			} for r in doc.items],
			"commissions": [{
				"item": r.item,
				"price": r.price,
				"commission": r.commission,
				"total_commission": r.total_commission,
				"taxes": r.taxes,
				"commission_total": r.commission_total,
			} for r in doc.commissions],
		}
		return doc.name, response

	return run_idempotent(client_request_id, "invoice.create", data, _create)


@frappe.whitelist(methods=["POST"])
@mobile_api
def update_invoice(name: str | None = None, data: dict | str | None = None, base_modified: str | None = None):
	body = _read_body()
	name = name or body["name"]
	if not name:
		frappe.throw("Missing invoice name")
	payload = data if isinstance(data, dict) else body["data"]
	if isinstance(payload, str):
		payload = json.loads(payload or "{}")
	payload = payload or {}
	base_modified = base_modified or body.get("base_modified")
	client_request_id = body["client_request_id"]

	def _do():
		doc = frappe.get_doc(DOCTYPE, name)
		if not doc.has_permission("write"):
			frappe.throw("Not permitted", frappe.PermissionError)

		# Optimistic concurrency — checked only on the fresh path; a replay of
		# the same client_request_id returns the stored result untouched.
		if base_modified and cstr(doc.modified) != cstr(base_modified):
			raise StaleDocumentError(
				frappe._("This invoice was changed on the server. Reload the latest data and try again."),
				current=_details_dict(doc),
			)

		if payload.get("posting_date"):
			doc.posting_date = payload.get("posting_date")
		if payload.get("supplier"):
			doc.supplier = payload.get("supplier")
		if payload.get("supplier_name"):
			doc.supplier_name = payload.get("supplier_name")

		if isinstance(payload.get("items"), list):
			doc.set("items", [])
			grand_total = 0.0
			for it in payload["items"]:
				qty = flt(it.get("qty") or it.get("quantity") or 0)
				price = flt(it.get("price") or 0)
				line_total = flt(it.get("total")) or (qty * price)
				grand_total += line_total
				row = doc.append("items", {})
				row.item_code = it.get("item_code") or it.get("item_name") or None
				row.item_name = it.get("item_name") or it.get("item_code") or None
				row.qty = qty
				row.price = price
				row.total = line_total
				row.customer = it.get("customer") or it.get("customerId") or ""
			doc.grand_total = grand_total
			commission_rate = flt(payload.get("commission_rate") or 5)
			tax_rate = flt(payload.get("tax_rate") or 15)
			total_commission = (grand_total * commission_rate) / 100.0
			doc.total_commissions_and_taxes = total_commission + (total_commission * tax_rate) / 100.0

		doc.save(ignore_permissions=False)  # no commit — run_idempotent owns it
		return doc.name, {
			"name": cstr(doc.name),
			"modified": cstr(doc.modified),
			"grand_total": doc.get("grand_total"),
			"total_commissions_and_taxes": doc.get("total_commissions_and_taxes"),
		}

	return run_idempotent(client_request_id, "invoice.update", {"name": name, "data": payload}, _do)


@frappe.whitelist(methods=["POST"])
@mobile_api
def submit_invoice(name: str | None = None):
	body = _read_body()
	name = name or body["name"]
	if not name:
		frappe.throw("Missing invoice name")
	client_request_id = body["client_request_id"]

	def _do():
		doc = frappe.get_doc(DOCTYPE, name)
		if not doc.has_permission("submit"):
			frappe.throw("Not permitted", frappe.PermissionError)
		if doc.docstatus != 0:
			frappe.throw("Only draft invoices can be submitted")
		doc.submit()  # no commit
		return doc.name, {
			"name": cstr(doc.name),
			"docstatus": doc.docstatus,
			"modified": cstr(doc.modified),
		}

	return run_idempotent(client_request_id, "invoice.submit", {"name": name}, _do)


@frappe.whitelist(methods=["POST"])
@mobile_api
def delete_invoice(name: str | None = None):
	body = _read_body()
	name = name or body["name"]
	if not name:
		frappe.throw("Missing invoice name")
	client_request_id = body["client_request_id"]

	def _do():
		doc = frappe.get_doc(DOCTYPE, name)
		if not doc.has_permission("delete"):
			frappe.throw("Not permitted", frappe.PermissionError)
		frappe.delete_doc(DOCTYPE, name, ignore_permissions=False)  # no commit
		return name, {"deleted": True, "name": cstr(name)}

	# A replay of this exact client_request_id returns {"deleted": true} even
	# though the doc is gone; a fresh id against an already-deleted doc still
	# raises DoesNotExistError -> 404 (never a false "success").
	return run_idempotent(client_request_id, "invoice.delete", {"name": name}, _do)
