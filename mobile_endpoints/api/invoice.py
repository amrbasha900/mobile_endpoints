import frappe
from frappe.utils import cstr, cint

@frappe.whitelist(methods=["GET"])
def get_invoices(
    start_date: str | None = None,
    end_date: str | None = None,
    supplier: str | None = None,
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
      - page (1-based)
      - page_size
      - search (optional text search on name/supplier_name)
    """
    doctype = "Invoice Form"

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

    # Minimal fields required by the Vue list page
    fields = [
        "name",             # used for id and invoiceNumber
        "posting_date",     # date
        "supplier",         # supplierId
        "supplier_name",    # supplierName
        "grand_total",      # amount
    ]

    order_by = "posting_date desc, creation desc"

    # Base query
    rows = frappe.get_all(
        doctype,
        fields=fields,
        filters=filters,
        order_by=order_by,
        start=start,
        page_length=page_size,
        ignore_permissions=False,
    )

    # Optional simple search (post-filter on retrieved page or expand query if needed)
    if search:
        s = cstr(search).strip().lower()
        rows = [
            r for r in rows
            if s in cstr(r.name).lower() or s in cstr(r.get("supplier_name") or "").lower()
        ]

    # Total count (approx; respects basic doc permissions but not shared granularities)
    total_count = frappe.db.count(doctype, filters=filters)

    # Shape response for the mobile app
    invoices = []
    for r in rows:
        invoices.append({
            "id": r.name,                               # string id for routing
            "invoiceNumber": r.name,
            "supplierId": r.supplier or "",
            "supplierName": r.supplier_name or "",
            "date": cstr(r.posting_date),
            "amount": float(r.grand_total or 0),
            "permission": {
                "can_update": True,
                "can_delete": True,
                "can_submit": True,
                "locked": False,
            },
        })

    has_more = (start + len(invoices)) < total_count

    return {
        "invoices": invoices,
        "page": page,
        "page_size": page_size,
        "total_count": total_count,
        "has_more": has_more,
    }


@frappe.whitelist(methods=["GET"])
def get_invoice_details(name: str):
    doctype = "Invoice Form"
    if not name:
        frappe.throw("Missing invoice name")

    doc = frappe.get_doc(doctype, name)
    if not doc.has_permission("read"):
        frappe.throw("Not permitted", frappe.PermissionError)

    status_map = {0: "draft", 1: "submitted", 2: "cancelled"}
    status = status_map.get(doc.docstatus or 0, "draft")
    is_locked = bool(getattr(doc, "lock_update", False))

    items = []
    for it in getattr(doc, "items", []):
        items.append({
            "id": cstr(getattr(it, "name", "")),
            "name": cstr(getattr(it, "item_name", "") or getattr(it, "item_code", "")),
            "quantity": float(getattr(it, "qty", 0) or 0),
            "price": float(getattr(it, "price", 0) or 0),
            "total": float(getattr(it, "total", 0) or 0),
            "customerId": cstr(getattr(it, "customer", "")),
            "customerName": cstr(getattr(it, "customer", "")),
        })

    return {
        "id": cstr(getattr(doc, "name", name)),
        "invoiceNumber": cstr(getattr(doc, "name", name)),
        "supplierId": cstr(getattr(doc, "supplier", "")),
        "supplierName": cstr(getattr(doc, "supplier_name", "")),  # FIX
        "date": cstr(getattr(doc, "posting_date", "")),
        "amount": float(getattr(doc, "grand_total", 0) or 0),
        "status": status,
        "is_locked": is_locked,
        "items": items,
        "tax": float(getattr(doc, "total_commissions_and_taxes", 0) or 0),
        "payments": [],
        "notes": cstr(getattr(doc, "remarks", "")),
        # ADD THESE for defaults/selects:
        "customer": cstr(getattr(doc, "customer", "")),
        "customer_name": cstr(getattr(doc, "customer", "")),
        "permission": {
            "can_update": True,
            "can_delete": True,
            "can_submit": True,
            "locked": is_locked,
        },
    }



@frappe.whitelist(methods=["POST"])
def update_invoice(name: str, data: dict | None = None):
    """
    Update minimal fields for 'Invoice Form'.
    Expects JSON body or dict with fields like:
      - posting_date, supplier, items (list of { item_code/item_name, qty, price, total, customer })
    """
    if not name:
        frappe.throw("Missing invoice name")
    doctype = "Invoice Form"
    doc = frappe.get_doc(doctype, name)
    if not doc.has_permission("write"):
        frappe.throw("Not permitted", frappe.PermissionError)

    payload = data or frappe.form_dict or {}
    # Map safe fields
    if payload.get("posting_date"):
        doc.posting_date = payload.get("posting_date")
    if payload.get("supplier"):
        doc.supplier = payload.get("supplier")
    if payload.get("supplier_name"):
        doc.supplier_name = payload.get("supplier_name")
    # Replace items if provided
    if isinstance(payload.get("items"), list):
        doc.set("items", [])
        for it in payload["items"]:
            row = doc.append("items", {})
            row.item_code = it.get("item_code") or None
            row.item_name = it.get("item_name") or None
            row.qty = it.get("qty") or it.get("quantity") or 0
            row.price = it.get("price") or 0
            row.total = it.get("total") or (row.qty * row.price)
            row.customer = it.get("customer") or it.get("customerId") or ""
    doc.save(ignore_permissions=False)
    frappe.db.commit()
    return {"name": cstr(doc.name)}

@frappe.whitelist(methods=["POST"])
def submit_invoice(name: str):
    """
    Submit the invoice (docstatus = 1).
    """
    if not name:
        frappe.throw("Missing invoice name")
    doctype = "Invoice Form"
    doc = frappe.get_doc(doctype, name)
    if not doc.has_permission("submit"):
        frappe.throw("Not permitted", frappe.PermissionError)
    if doc.docstatus != 0:
        frappe.throw("Only draft invoices can be submitted")

    doc.submit()
    frappe.db.commit()
    return {"name": cstr(doc.name), "docstatus": doc.docstatus}

@frappe.whitelist(methods=["POST"])
def delete_invoice(name: str):
    """
    Delete the invoice document.
    """
    if not name:
        frappe.throw("Missing invoice name")
    doctype = "Invoice Form"
    doc = frappe.get_doc(doctype, name)
    if not doc.has_permission("delete"):
        frappe.throw("Not permitted", frappe.PermissionError)
    frappe.delete_doc(doctype, name, ignore_permissions=False)
    frappe.db.commit()
    return {"deleted": True}

import json
from frappe.utils import nowtime, flt

@frappe.whitelist(methods=["POST"])
def create_invoice_form():
    """
    Payload:
    {
      "posting_date": "2025-08-13",
      "supplier": ",0000232",
      "supplier_name": "مزرعة ...",
      "items": [
        {"item_code": "اسود", "item_name": "اسود", "qty": 5324, "price": 4534, "total": 24139016, "customer": "ابوسعيد ..."}
      ],
      "pamper_commission": 0,         # optional
      "commission_rate": 5,           # optional, default 5
      "tax_rate": 15                  # optional, default 15
    }
    """
    data = frappe.form_dict.get("data")
    if isinstance(data, str):
        data = json.loads(data or "{}")
    data = data or {}

    # Required
    posting_date = data.get("posting_date")
    supplier = data.get("supplier")
    if not posting_date or not supplier:
        frappe.throw("Missing required fields: posting_date, supplier")

    # Optional/defaults
    supplier_name = data.get("supplier_name") or ""
    items = data.get("items") or []
    commission_rate = flt(data.get("commission_rate") or 5)
    tax_rate = flt(data.get("tax_rate") or 15)
    pamper_commission = flt(data.get("pamper_commission") or 0)

    if not items:
        frappe.throw("At least one item is required")

    # Compute totals safely
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

    # Create document
    doc = frappe.get_doc({
        "doctype": "Invoice Form",
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

    # Items table
    for it in items:
        doc.append("items", {
            "item_code": it.get("item_code"),
            "item_name": it.get("item_name") or it.get("item_code"),
            "qty": flt(it.get("qty") or it.get("quantity") or 0),
            "price": flt(it.get("price") or 0),
            "total": flt(it.get("total") or 0),
            "customer": it.get("customer") or "",
        })

    
    # If your doctype has pamper_commissions child table, populate as needed
    # for now, we leave it empty to match your example when zero

    doc.insert(ignore_permissions=True)
    # If you want to immediately submit:
    # doc.submit()

    return {
        "name": doc.name,
        "posting_date": doc.posting_date,
        "supplier": doc.supplier,
        "supplier_name": doc.supplier_name,
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
            } for r in doc.items
        ],
        "commissions": [
            {
                "item": r.item,
                "price": r.price,
                "commission": r.commission,
                "total_commission": r.total_commission,
                "taxes": r.taxes,
                "commission_total": r.commission_total,
            } for r in doc.commissions
        ],
    }