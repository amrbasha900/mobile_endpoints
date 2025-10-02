import frappe
from frappe.utils import cint, cstr

@frappe.whitelist(methods=["GET"])
def get_supplier(page: int | str = 1, page_size: int | str = 100, search: str | None = None):
    """
    Returns farmer suppliers for the mobile dropdown.

    - Always filters suppliers where is_farmer = 1
    - Optional search on supplier_name or name
    - Pagination using page_size + 1 to compute has_more
    """
    doctype = "Supplier"
    if not frappe.has_permission(doctype=doctype, ptype="read"):
        frappe.throw("Not permitted", frappe.PermissionError)

    page = max(1, cint(page))
    page_size = max(1, min(200, cint(page_size)))
    start = (page - 1) * page_size

    base_filters = [["is_farmer", "=", 1]]

    or_filters = None
    if search:
        s = f"%{cstr(search).strip()}%"
        or_filters = [
            ["Supplier", "supplier_name", "like", s],
            ["Supplier", "name", "like", s],
        ]

    fields = ["name as id", "supplier_name as name"]

    # Fetch one extra row to determine has_more without needing a separate count
    rows = frappe.get_all(
        doctype,
        fields=fields,
        filters=base_filters,
        or_filters=or_filters,
        order_by="supplier_name asc, name asc",
        start=start,
        page_length=page_size + 1,
    )

    has_more = len(rows) > page_size
    if has_more:
        rows = rows[:page_size]

    suppliers = [
        {
            "id": r.get("id") or r.get("name"),
            "name": r.get("name") or r.get("supplier_name") or r.get("id"),
        }
        for r in rows
    ]

    return {
        "suppliers": suppliers,
        "page": page,
        "page_size": page_size,
        "has_more": has_more,
    }

@frappe.whitelist(methods=["GET"])
def get_customer(page: int | str = 1, page_size: int | str = 20, search: str | None = None):
    doctype = "Customer"
    if not frappe.has_permission(doctype=doctype, ptype="read"):
        frappe.throw("Not permitted", frappe.PermissionError)

    page = max(1, cint(page))
    page_size = max(1, min(200, cint(page_size)))
    start = (page - 1) * page_size

    base_filters = []
    or_filters = None
    if search:
        s = f"%{cstr(search).strip()}%"
        or_filters = [["Customer", "customer_name", "like", s], ["Customer", "name", "like", s]]

    fields = ["name as id", "customer_name as name"]
    rows = frappe.get_all(
        doctype,
        fields=fields,
        filters=base_filters,
        or_filters=or_filters,
        order_by="customer_name asc, name asc",
        start=start,
        page_length=page_size + 1,
    )
    has_more = len(rows) > page_size
    if has_more:
        rows = rows[:page_size]

    customers = [{"id": r.get("id") or r.get("name"), "name": r.get("name") or r.get("customer_name") or r.get("id")} for r in rows]
    return {"customers": customers, "page": page, "page_size": page_size, "has_more": has_more}


@frappe.whitelist(methods=["GET"])
def get_items(page: int | str = 1, page_size: int | str = 20, search: str | None = None):
    doctype = "Item"
    if not frappe.has_permission(doctype=doctype, ptype="read"):
        frappe.throw("Not permitted", frappe.PermissionError)

    page = max(1, cint(page))
    page_size = max(1, min(200, cint(page_size)))
    start = (page - 1) * page_size

    base_filters = [["disabled", "=", 0]]
    or_filters = None
    if search:
        s = f"%{cstr(search).strip()}%"
        or_filters = [["Item", "item_name", "like", s], ["Item", "name", "like", s], ["Item", "item_code", "like", s]]

    fields = ["name as id", "item_name as name"]
    rows = frappe.get_all(
        doctype,
        fields=fields,
        filters=base_filters,
        or_filters=or_filters,
        order_by="item_name asc, name asc",
        start=start,
        page_length=page_size + 1,
    )
    has_more = len(rows) > page_size
    if has_more:
        rows = rows[:page_size]

    # If you have a standard price list, you can fetch prices here as needed
    items = [{"id": r.get("id") or r.get("name"), "name": r.get("name") or r.get("id"), "price": 0} for r in rows]
    return {"items": items, "page": page, "page_size": page_size, "has_more": has_more}