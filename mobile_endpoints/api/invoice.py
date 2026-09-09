import json

import frappe
from frappe import _
from frappe.utils import cint, cstr, flt, get_url, now_datetime, nowtime
from frappe.utils.file_manager import save_file

from mobile_endpoints.api.security import (
	document_permissions,
	require_authenticated_user,
	require_doctype_permission,
	set_cors_headers,
)


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
	"""Read financial rates from site config; clients cannot override them."""
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
	if qty <= 0:
		frappe.throw(
			_("Quantity must be greater than zero for item {0}").format(item_code), frappe.ValidationError
		)
	if price < 0:
		frappe.throw(_("Price must not be negative for item {0}").format(item_code), frappe.ValidationError)
	_require_link_access("Item", item_code)
	if customer:
		_require_link_access("Customer", customer)
	return {
		"item_code": item_code,
		"item_name": cstr(frappe.db.get_value("Item", item_code, "item_name") or item_code),
		"qty": qty,
		"price": price,
		"total": qty * price,
		"customer": customer,
	}


def _get_party_display(doctype: str, party: str, party_name: str | None) -> str:
	stored_name = cstr(party_name or "")
	if stored_name:
		return _display_name(party, stored_name)
	fetched_name = _get_party_name(doctype, party)
	return _display_name(party, fetched_name)


@frappe.whitelist(allow_guest=True, methods=["GET"])
def get_invoice_references(limit: int | str = 200):
	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()

	limit = max(1, min(1000, cint(limit)))

	suppliers = frappe.get_list(
		"Supplier",
		filters={"disabled": 0},
		fields=["name", "supplier_name"],
		order_by="modified desc",
		limit_page_length=limit,
	)
	customers = frappe.get_list(
		"Customer",
		filters={"disabled": 0},
		fields=["name", "customer_name"],
		order_by="modified desc",
		limit_page_length=limit,
	)
	items = frappe.get_list(
		"Item",
		filters={"disabled": 0},
		fields=["name", "item_name"],
		order_by="modified desc",
		limit_page_length=limit,
	)

	return {
		"suppliers": [
			{
				"code": cstr(row.name),
				"name": cstr(row.supplier_name or row.name),
				"display": _display_name(row.name, row.supplier_name or row.name),
			}
			for row in suppliers
		],
		"customers": [
			{
				"code": cstr(row.name),
				"name": cstr(row.customer_name or row.name),
				"display": _display_name(row.name, row.customer_name or row.name),
			}
			for row in customers
		],
		"items": [
			{
				"code": cstr(row.name),
				"name": cstr(row.item_name or row.name),
				"display": _display_name(row.name, row.item_name or row.name),
			}
			for row in items
		],
	}


@frappe.whitelist(allow_guest=True, methods=["GET"])
def get_invoices(
	start_date: str | None = None,
	end_date: str | None = None,
	supplier: str | None = None,
	status: str | None = None,
	page: int | str = 1,
	page_size: int | str = 20,
	search: str | None = None,
):
	"""
	Returns minimal invoice list for the mobile app.

	Query params:
	  - start_date (YYYY-MM-DD)
	  - end_date (YYYY-MM-DD)
	  - supplier (supplier code or exact name stored in 'supplier')
	  - status (draft/submitted/cancelled/pending)
	  - page (1-based)
	  - page_size
	  - search (optional text search on name/supplier_name)
	"""
	doctype = "Invoice Form"

	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()

	# Permission check (read)
	if not frappe.has_permission(doctype=doctype, ptype="read"):
		frappe.throw("Not permitted", frappe.PermissionError)

	page = max(1, cint(page))
	page_size = max(1, min(100, cint(page_size)))
	start = (page - 1) * page_size

	filters = []

	# Date filtering on posting_date
	if start_date:
		filters.append(["posting_date", ">=", cstr(start_date)])
	if end_date:
		filters.append(["posting_date", "<=", cstr(end_date)])

	# Supplier filter (matches stored 'supplier' field value)
	if supplier:
		filters.append(["supplier", "=", cstr(supplier)])

	meta = frappe.get_meta(doctype)

	# Status filter
	if status:
		normalized = cstr(status).strip().lower()
		status_map = {"draft": 0, "submitted": 1, "cancelled": 2}
		if normalized in status_map:
			filters.append(["docstatus", "=", status_map[normalized]])
		elif normalized == "pending":
			# Try to match workflow/status fields when available
			if meta.has_field("status"):
				filters.append(["status", "=", "Pending"])
			elif meta.has_field("workflow_state"):
				filters.append(["workflow_state", "=", "Pending"])
			else:
				filters.append(["docstatus", "=", 0])
		else:
			frappe.throw(_("Unsupported invoice status"), frappe.ValidationError)

	# Minimal fields required by the Vue list page
	fields = [
		"name",  # used for id and invoiceNumber
		"posting_date",  # date
		"supplier",  # supplierId
		"supplier_name",  # supplierName
		"grand_total",  # amount
		"docstatus",  # status
	]
	if meta.has_field("status"):
		fields.append("status")
	if meta.has_field("workflow_state"):
		fields.append("workflow_state")

	order_by = "posting_date desc, creation desc"

	# Optional text search (invoice number or supplier/customer name or code)
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

	# Base query
	rows = frappe.get_list(
		doctype,
		fields=fields,
		filters=filters,
		or_filters=or_filters,
		order_by=order_by,
		start=start,
		page_length=page_size,
	)

	# Permission-aware count without loading every matching document.
	count_rows = frappe.get_list(
		doctype,
		fields=["count(name) as total_count"],
		filters=filters,
		or_filters=or_filters,
		limit_page_length=1,
	)
	total_count = cint(count_rows[0].total_count) if count_rows else 0

	# Shape response for the mobile app
	status_map = {0: "draft", 1: "submitted", 2: "cancelled"}
	invoices = []
	for r in rows:
		status_value = status_map.get(cint(r.docstatus or 0), "draft")
		if status_value == "draft":
			doc_status = cstr(getattr(r, "status", "")) or cstr(getattr(r, "workflow_state", ""))
			if doc_status.lower() == "pending":
				status_value = "pending"

		supplier_display = _get_party_display("Supplier", r.supplier, r.supplier_name)
		doc = frappe.get_doc(doctype, r.name)
		permissions = document_permissions(doc)
		invoices.append(
			{
				"id": r.name,  # string id for routing
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
			}
		)

	has_more = (start + len(invoices)) < total_count

	return {
		"invoices": invoices,
		"page": page,
		"page_size": page_size,
		"total_count": total_count,
		"has_more": has_more,
	}


@frappe.whitelist(allow_guest=True, methods=["GET"])
def get_invoice_details(name: str | None = None):
	doctype = "Invoice Form"
	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()
	if not name:
		frappe.throw(_("Missing invoice name"), frappe.ValidationError)

	doc = frappe.get_doc(doctype, name)
	if not doc.has_permission("read"):
		frappe.throw("Not permitted", frappe.PermissionError)

	status_map = {0: "draft", 1: "submitted", 2: "cancelled"}
	status = status_map.get(doc.docstatus or 0, "draft")
	is_locked = bool(getattr(doc, "lock_update", False))

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
		items.append(
			{
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
			}
		)

	supplier_display = _get_party_display(
		"Supplier", getattr(doc, "supplier", ""), getattr(doc, "supplier_name", "")
	)
	customer_display = _get_party_display(
		"Customer", getattr(doc, "customer", ""), getattr(doc, "customer_name", "")
	)

	permissions = document_permissions(doc)
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
		# ADD THESE for defaults/selects:
		"customer": cstr(getattr(doc, "customer", "")),
		"customer_name": customer_display,
		"customer_code": cstr(getattr(doc, "customer", "")),
		"customer_raw_name": cstr(getattr(doc, "customer_name", "")),
		"permissions": permissions,
		"permission": {
			"can_update": permissions["update"],
			"can_delete": permissions["delete"],
			"can_submit": permissions["submit"],
			"locked": permissions["locked"],
		},
	}


@frappe.whitelist(allow_guest=True, methods=["POST"])
def update_invoice(name: str | None = None, data: dict | None = None):
	"""
	Update minimal fields for 'Invoice Form'.
	Expects JSON body or dict with fields like:
	  - posting_date, supplier, items (list of { item_code/item_name, qty, price, total, customer })
	"""
	set_cors_headers("POST, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()

	if not name:
		frappe.throw("Missing invoice name")
	doctype = "Invoice Form"
	doc = frappe.get_doc(doctype, name)
	if not doc.has_permission("write"):
		frappe.throw("Not permitted", frappe.PermissionError)
	if int(doc.docstatus or 0) != 0:
		frappe.throw(_("Only draft invoices can be updated"), frappe.ValidationError)

	payload = _parse_payload(data)
	# Map safe fields
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
	# Replace items if provided
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
	doc.save(ignore_permissions=False)
	return {
		"name": cstr(doc.name),
		"grand_total": float(doc.get("grand_total") or 0),
		"total_commissions_and_taxes": float(doc.get("total_commissions_and_taxes") or 0),
	}


@frappe.whitelist(allow_guest=True, methods=["POST"])
def submit_invoice(name: str | None = None):
	"""
	Submit the invoice (docstatus = 1).
	"""
	set_cors_headers("POST, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()

	if not name:
		frappe.throw("Missing invoice name")
	doctype = "Invoice Form"
	doc = frappe.get_doc(doctype, name)
	if not doc.has_permission("submit"):
		frappe.throw("Not permitted", frappe.PermissionError)
	if doc.docstatus != 0:
		frappe.throw("Only draft invoices can be submitted")

	doc.submit()
	return {"name": cstr(doc.name), "docstatus": doc.docstatus}


@frappe.whitelist(allow_guest=True, methods=["POST"])
def delete_invoice(name: str | None = None):
	"""
	Delete the invoice document.
	"""
	set_cors_headers("POST, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()

	if not name:
		frappe.throw("Missing invoice name")
	doctype = "Invoice Form"
	doc = frappe.get_doc(doctype, name)
	if not doc.has_permission("delete"):
		frappe.throw("Not permitted", frappe.PermissionError)
	frappe.delete_doc(doctype, name, ignore_permissions=False)
	return {"deleted": True}


@frappe.whitelist(allow_guest=True, methods=["POST"])
def print_invoice(name: str | None = None, print_format: str | None = None):
	set_cors_headers("POST, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()

	if not name:
		frappe.throw("Missing invoice name")

	doctype = "Invoice Form"
	doc = frappe.get_doc(doctype, name)
	if not doc.has_permission("read"):
		frappe.throw("Not permitted", frappe.PermissionError)

	pdf_content = frappe.get_print(
		doctype,
		name,
		print_format=print_format or None,
		as_pdf=True,
	)
	timestamp = now_datetime().strftime("%Y%m%d%H%M%S")
	filename = f"{name}-{timestamp}.pdf"
	file_doc = save_file(filename, pdf_content, doctype, name, is_private=1)
	file_url = file_doc.file_url or ""
	return {
		"file_url": f"{get_url()}{file_url}" if file_url and not file_url.startswith("http") else file_url
	}


@frappe.whitelist(allow_guest=True, methods=["POST"])
def create_invoice_form():
	"""
	Payload:
	{
	  "posting_date": "2025-08-13",
	  "supplier": ",0000232",
	  "supplier_name": "مزرعة ...",
	  "items": [
	    {"item_code": "اسود", "item_name": "اسود", "qty": 5324, "price": 4534, "total": 24139016, "customer": "ابوسعيد ..."}
	  ]
	}
	Totals, commission, and tax are calculated by the server.
	"""
	set_cors_headers("POST, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()
	require_doctype_permission("Invoice Form", "create")

	data = _parse_payload()

	# Required
	posting_date = data.get("posting_date")
	supplier = cstr(data.get("supplier")).strip()
	if not posting_date or not supplier:
		frappe.throw("Missing required fields: posting_date, supplier")

	# Optional/defaults
	_require_link_access("Supplier", supplier)
	supplier_name = frappe.db.get_value("Supplier", supplier, "supplier_name") or supplier
	customer = cstr(data.get("customer")).strip()
	if customer:
		_require_link_access("Customer", customer)
	customer_name = frappe.db.get_value("Customer", customer, "customer_name") or customer if customer else ""
	items = data.get("items") or []
	commission_rate, tax_rate = _invoice_rates()
	pamper_commission = 0.0

	if not items:
		frappe.throw("At least one item is required")

	# Compute totals safely
	normalized_items = [_normalized_item(item) for item in items]
	grand_total = sum(item["total"] for item in normalized_items)

	total_commission = (grand_total * commission_rate) / 100.0
	taxes_on_commission = (total_commission * tax_rate) / 100.0
	total_commissions_and_taxes = total_commission + taxes_on_commission

	# Create document
	doc = frappe.get_doc(
		{
			"doctype": "Invoice Form",
			"posting_date": posting_date,
			"posting_time": nowtime(),
			"is_draft": 1,
			"lock_update": 1,
			"supplier": supplier,
			"supplier_name": supplier_name,
			"customer": customer,
			"customer_name": customer_name,
			"pamper_commission": pamper_commission,
			"grand_total": grand_total,
			"total_commissions_and_taxes": total_commissions_and_taxes,
			"items": [],
			"commissions": [],
		}
	)

	# Items table
	for it in normalized_items:
		doc.append(
			"items",
			{
				"item_code": it["item_code"],
				"item_name": it["item_name"],
				"qty": it["qty"],
				"price": it["price"],
				"total": it["total"],
				"customer": it["customer"],
			},
		)

	# If your doctype has pamper_commissions child table, populate as needed
	# for now, we leave it empty to match your example when zero

	doc.insert(ignore_permissions=False)
	# If you want to immediately submit:
	# doc.submit()

	return {
		"name": doc.name,
		"posting_date": doc.posting_date,
		"supplier": doc.supplier,
		"supplier_name": doc.supplier_name,
		"customer": doc.get("customer"),
		"customer_name": doc.get("customer_name"),
		"grand_total": doc.get("grand_total"),
		"total_commissions_and_taxes": doc.get("total_commissions_and_taxes"),
		"pamper_commission": doc.get("pamper_commission"),
		"doctype": doc.doctype,
		"items": [
			{
				"item_code": r.item_code,
				"item_name": r.item_name,
				"qty": r.qty,
				"price": r.price,
				"total": r.total,
				"commission": r.get("commission"),
				"customer": r.get("customer"),
				"couple_customer": r.get("couple_customer"),
				"has_commission_invoice": r.get("has_commission_invoice"),
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
