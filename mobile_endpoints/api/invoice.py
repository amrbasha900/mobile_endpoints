import frappe
from frappe.utils import cstr, cint, get_url
from frappe.utils.password import get_decrypted_password
from frappe.utils.file_manager import save_file
from frappe.utils import now_datetime


def _set_cors_headers(methods: str) -> None:
    headers = frappe.local.response.setdefault("headers", {})
    origin = ""
    if frappe.local.request:
        origin = frappe.local.request.headers.get("Origin") or ""
    headers["Access-Control-Allow-Origin"] = origin or "*"
    headers["Vary"] = "Origin"
    headers["Access-Control-Allow-Credentials"] = "true"
    headers["Access-Control-Allow-Methods"] = methods
    headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"


def _authenticate_token() -> bool:
    if not frappe.local.request:
        return False
    auth = frappe.local.request.headers.get("Authorization") or ""
    if not auth.lower().startswith("token "):
        return False
    token = auth[6:].strip()
    if ":" not in token:
        return False
    api_key, api_secret = token.split(":", 1)
    user = frappe.db.get_value("User", {"api_key": api_key}, "name")
    if not user:
        return False
    try:
        stored_secret = get_decrypted_password("User", user, "api_secret")
    except Exception:
        return False
    if stored_secret != api_secret:
        return False
    frappe.set_user(user)
    return True


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
    fetched_name = _get_party_name(doctype, party)
    return _display_name(party, fetched_name)


@frappe.whitelist(methods=["GET"])
def get_invoice_references(limit: int | str = 200):
    _set_cors_headers("GET, OPTIONS")
    if frappe.local.request and frappe.local.request.method == "OPTIONS":
        return {}

    token_ok = _authenticate_token()
    user = frappe.session.user
    if (not user or user == "Guest") and not token_ok:
        return {"suppliers": [], "customers": [], "items": []}

    limit = max(1, min(1000, cint(limit)))

    suppliers = frappe.get_all(
        "Supplier",
        fields=["name", "supplier_name"],
        order_by="modified desc",
        limit_page_length=limit,
    )
    customers = frappe.get_all(
        "Customer",
        fields=["name", "customer_name"],
        order_by="modified desc",
        limit_page_length=limit,
    )
    items = frappe.get_all(
        "Item",
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

@frappe.whitelist(methods=["GET"])
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

    _set_cors_headers("GET, OPTIONS")
    if frappe.local.request and frappe.local.request.method == "OPTIONS":
        return {}

    token_ok = _authenticate_token()
    user = frappe.session.user
    if (not user or user == "Guest") and not token_ok:
        return {
            "invoices": [],
            "page": 1,
            "page_size": 0,
            "total_count": 0,
            "has_more": False,
        }

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

    # Status filter
    if status:
        normalized = cstr(status).strip().lower()
        status_map = {"draft": 0, "submitted": 1, "cancelled": 2}
        if normalized in status_map:
            filters.append(["docstatus", "=", status_map[normalized]])
        elif normalized == "pending":
            # Try to match workflow/status fields when available
            meta = frappe.get_meta(doctype)
            if meta.has_field("status"):
                filters.append(["status", "=", "Pending"])
            elif meta.has_field("workflow_state"):
                filters.append(["workflow_state", "=", "Pending"])

    # Minimal fields required by the Vue list page
    fields = [
        "name",             # used for id and invoiceNumber
        "posting_date",     # date
        "supplier",         # supplierId
        "supplier_name",    # supplierName
        "grand_total",      # amount
        "docstatus",        # status
        "status",
        "workflow_state",
    ]

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
            meta = frappe.get_meta(doctype)
            if meta.has_field("customer"):
                or_filters.append(["customer", "like", f"%{s}%"])
            if meta.has_field("customer_name"):
                or_filters.append(["customer_name", "like", f"%{s}%"])

    # Base query
    rows = frappe.get_all(
        doctype,
        fields=fields,
        filters=filters,
        or_filters=or_filters,
        order_by=order_by,
        start=start,
        page_length=page_size,
        ignore_permissions=False,
    )

    # Total count
    if or_filters:
        total_count = len(
            frappe.get_all(
                doctype,
                fields=["name"],
                filters=filters,
                or_filters=or_filters,
                ignore_permissions=False,
            )
        )
    else:
        total_count = frappe.db.count(doctype, filters=filters)

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
        invoices.append({
            "id": r.name,                               # string id for routing
            "invoiceNumber": r.name,
            "supplierId": r.supplier or "",
            "supplierName": supplier_display,
            "supplierCode": r.supplier or "",
            "supplierRawName": r.supplier_name or "",
            "date": cstr(r.posting_date),
            "amount": float(r.grand_total or 0),
            "status": status_value,
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

    _set_cors_headers("GET, OPTIONS")
    if frappe.local.request and frappe.local.request.method == "OPTIONS":
        return {}

    token_ok = _authenticate_token()
    user = frappe.session.user
    if (not user or user == "Guest") and not token_ok:
        return {}

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
    _set_cors_headers("POST, OPTIONS")
    if frappe.local.request and frappe.local.request.method == "OPTIONS":
        return {}

    token_ok = _authenticate_token()
    user = frappe.session.user
    if (not user or user == "Guest") and not token_ok:
        frappe.throw("Not permitted", frappe.PermissionError)

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
    if payload.get("customer"):
        doc.customer = payload.get("customer")
    if payload.get("customer_name"):
        doc.customer_name = payload.get("customer_name")
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
    return {
        "name": cstr(doc.name),
        "grand_total": float(doc.get("grand_total") or 0),
        "total_commissions_and_taxes": float(doc.get("total_commissions_and_taxes") or 0),
    }

@frappe.whitelist(methods=["POST"])
def submit_invoice(name: str):
    """
    Submit the invoice (docstatus = 1).
    """
    _set_cors_headers("POST, OPTIONS")
    if frappe.local.request and frappe.local.request.method == "OPTIONS":
        return {}

    token_ok = _authenticate_token()
    user = frappe.session.user
    if (not user or user == "Guest") and not token_ok:
        frappe.throw("Not permitted", frappe.PermissionError)

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
    _set_cors_headers("POST, OPTIONS")
    if frappe.local.request and frappe.local.request.method == "OPTIONS":
        return {}

    token_ok = _authenticate_token()
    user = frappe.session.user
    if (not user or user == "Guest") and not token_ok:
        frappe.throw("Not permitted", frappe.PermissionError)

    if not name:
        frappe.throw("Missing invoice name")
    doctype = "Invoice Form"
    doc = frappe.get_doc(doctype, name)
    if not doc.has_permission("delete"):
        frappe.throw("Not permitted", frappe.PermissionError)
    frappe.delete_doc(doctype, name, ignore_permissions=False)
    frappe.db.commit()
    return {"deleted": True}


@frappe.whitelist(methods=["POST"])
def print_invoice(name: str, print_format: str | None = None):
    _set_cors_headers("POST, OPTIONS")
    if frappe.local.request and frappe.local.request.method == "OPTIONS":
        return {}

    token_ok = _authenticate_token()
    user = frappe.session.user
    if (not user or user == "Guest") and not token_ok:
        frappe.throw("Not permitted", frappe.PermissionError)

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
    file_doc = save_file(filename, pdf_content, doctype, name, is_private=0)
    file_url = file_doc.file_url or ""
    return {"file_url": f"{get_url()}{file_url}" if file_url and not file_url.startswith("http") else file_url}

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
    _set_cors_headers("POST, OPTIONS")
    if frappe.local.request and frappe.local.request.method == "OPTIONS":
        return {}

    token_ok = _authenticate_token()
    user = frappe.session.user
    if (not user or user == "Guest") and not token_ok:
        frappe.throw("Not permitted", frappe.PermissionError)

    data = frappe.form_dict.get("data")
    if isinstance(data, str):
        data = json.loads(data or "{}")
    if not data and frappe.request and frappe.request.data:
        try:
            data = json.loads(frappe.request.data)
        except Exception:
            data = {}
    data = data or {}

    # Required
    posting_date = data.get("posting_date")
    supplier = data.get("supplier")
    if not posting_date or not supplier:
        frappe.throw("Missing required fields: posting_date, supplier")

    # Optional/defaults
    supplier_name = data.get("supplier_name") or ""
    customer = data.get("customer") or ""
    customer_name = data.get("customer_name") or ""
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
        "customer": customer,
        "customer_name": customer_name,
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