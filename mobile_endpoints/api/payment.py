from typing import Any

import frappe
from frappe import _
from frappe.utils import cint, cstr, flt

from mobile_endpoints.api.security import (
	require_authenticated_user,
	require_doctype_permission,
	set_cors_headers,
)

# --- helpers ---------------------------------------------------------------

MANDATORY_PARENT_FIELDS = {"posting_date", "company"}
MANDATORY_DETAIL_FIELDS = {"payment_type", "party_type", "party", "amount"}
PARTY_NAME_FIELDS = {
	"Customer": "customer_name",
	"Supplier": "supplier_name",
	"Employee": "employee_name",
	"Shareholder": "title",
}


def _display_name(code: str | None, name: str | None) -> str:
	code = cstr(code or "").strip()
	name = cstr(name or "").strip()
	if not code and not name:
		return ""
	if not name or name == code:
		return code or name
	return f"{name} ({code})"


def _get_default_company() -> str:
	company = cstr(frappe.defaults.get_user_default("company") or "")
	if company:
		return company
	company = cstr(frappe.defaults.get_global_default("company") or "")
	if company:
		return company
	company = cstr(frappe.db.get_single_value("Global Defaults", "default_company") or "")
	if company:
		return company
	return cstr(frappe.db.get_value("Company", {}, "name") or "")


def _ensure_fields(required: set[str], data: dict[str, Any], title: str) -> None:
	missing = sorted(field for field in required if not data.get(field))
	if missing:
		frappe.throw(
			_("Missing required fields: {0}").format(", ".join(missing)),
			title=title,
		)


def _extract_payload() -> dict[str, Any]:
	if frappe.request and frappe.request.method == "POST":
		try:
			payload = frappe.parse_json(frappe.request.get_data(as_text=True) or "{}")
		except (TypeError, ValueError):
			frappe.throw(_("Unable to parse JSON body"), title=_("Invalid Request"))
	else:
		payload = frappe.form_dict or {}
	if not isinstance(payload, dict):
		frappe.throw(_("JSON body must be an object"), frappe.ValidationError)
	return payload


def _payment_detail(data: dict[str, Any]) -> dict[str, Any]:
	detail = data.get("detail")
	if detail is None:
		details = data.get("collection_and_payment_details") or []
		if not isinstance(details, list):
			frappe.throw(_("Payment details must be a list"), frappe.ValidationError)
		detail = details[0] if details else None
	if not isinstance(detail, dict):
		frappe.throw(_("At least one payment detail is required"), frappe.ValidationError)
	return detail


# --- API: create -----------------------------------------------------------


@frappe.whitelist(allow_guest=True, methods=["POST"])
def create_collection_payment():
	"""
	POST /api/method/mobile_endpoints.api.payment.create_collection_payment

	Expected payload:
	{
	  "posting_date": "2025-12-26",
	  "company": "My Company",
	  "pamper_collection_and_payment": 0,  # ignored, always forced to 1
	  "detail": {
	    "payment_type": "Pay",
	    "party_type": "Customer",
	    "party": "1020013",
	    "party_name": "ابو صالح",
	    "amount": 41,
	    "mode_of_payment": "بنك الراجحي -93427 - ( 3 )"
	  }
	}
	"""
	set_cors_headers("POST, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()
	require_doctype_permission("Collection and Payment", "create")

	data = _extract_payload()
	if not data.get("company"):
		data["company"] = _get_default_company()
	_ensure_fields(MANDATORY_PARENT_FIELDS, data, _("Parent Validation Error"))

	detail = _payment_detail(data)
	_ensure_fields(MANDATORY_DETAIL_FIELDS, detail, _("Child Validation Error"))
	amount = flt(detail.get("amount"))
	if amount <= 0:
		frappe.throw(_("Amount must be greater than zero"), frappe.ValidationError)

	company = cstr(data["company"]).strip()
	if not frappe.db.exists("Company", company):
		frappe.throw(_("Invalid company"), frappe.ValidationError)
	require_doctype_permission("Company", "read", company)

	payment_type = cstr(detail.get("payment_type")).strip().title()
	if payment_type not in {"Pay", "Receive"}:
		frappe.throw(_("Unsupported payment type"), frappe.ValidationError)
	party_type = cstr(detail.get("party_type")).strip()
	if party_type not in PARTY_NAME_FIELDS:
		frappe.throw(_("Unsupported party type"), frappe.ValidationError)
	party = cstr(detail.get("party")).strip()
	if not frappe.db.exists(party_type, party):
		frappe.throw(_("Invalid party"), frappe.ValidationError)
	require_doctype_permission(party_type, "read", party)
	party_name = cstr(frappe.db.get_value(party_type, party, PARTY_NAME_FIELDS[party_type]) or party)

	mode_of_payment = cstr(detail.get("mode_of_payment")).strip()
	if mode_of_payment:
		if not frappe.db.exists("Mode of Payment", mode_of_payment):
			frappe.throw(_("Invalid mode of payment"), frappe.ValidationError)
		require_doctype_permission("Mode of Payment", "read", mode_of_payment)

	doc = frappe.new_doc("Collection and Payment")
	parent_values = {
		"posting_date": data["posting_date"],
		"company": company,
		"pamper_collection_and_payment": 1,
	}
	if doc.meta.has_field("pamper_collection"):
		parent_values["pamper_collection"] = 1
	doc.update(parent_values)

	doc.append(
		"collection_and_payment_details",
		{
			"payment_type": payment_type,
			"party_type": party_type,
			"party": party,
			"party_name": party_name,
			"amount": amount,
			"mode_of_payment": mode_of_payment or None,
			"description": cstr(detail.get("description")),
			"is_pamper": 1,
		},
	)

	doc.insert(ignore_permissions=False)

	return {
		"success": True,
		"message": _("Collection payment created"),
		"name": doc.name,
		"posting_date": doc.posting_date,
	}


# --- API: list -------------------------------------------------------------


@frappe.whitelist(allow_guest=True, methods=["GET"])
def list_collection_payments(page: int = 1, page_size: int = 20):
	"""
	GET /api/method/mobile_endpoints.api.payment.list_collection_payments?page=1&page_size=20
	Returns only documents where pamper_collection_and_payment = 1.
	"""
	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()
	require_doctype_permission("Collection and Payment", "read")
	page = max(1, cint(page))
	page_size = min(100, max(1, cint(page_size)))
	start = (page - 1) * page_size

	parents = frappe.get_list(
		"Collection and Payment",
		filters={"pamper_collection_and_payment": 1},
		fields=["name", "posting_date", "company", "owner", "creation", "status"],
		order_by="creation desc",
		limit_start=start,
		limit_page_length=page_size + 1,
	)

	if not parents:
		return {"payments": [], "has_more": False}

	has_more = len(parents) > page_size
	parents = parents[:page_size]
	parent_names = [p["name"] for p in parents]
	child_rows = frappe.get_all(
		"Collection and Payment Details",
		filters={"parent": ("in", parent_names)},
		fields=[
			"parent",
			"payment_type",
			"party_type",
			"party",
			"party_name",
			"amount",
			"mode_of_payment",
			"description",
		],
		order_by="idx asc",
	)

	first_row_map: dict[str, dict[str, Any]] = {}
	for row in child_rows:
		first_row_map.setdefault(row["parent"], row)

	results = []
	for parent in parents:
		row = first_row_map.get(parent["name"])
		if not row:
			continue
		results.append(
			{
				"name": parent["name"],
				"posting_date": parent["posting_date"],
				"company": parent["company"],
				"status": parent.get("status"),
				"payment_type": row["payment_type"],
				"party_type": row["party_type"],
				"party": row["party"],
				"party_name": row["party_name"],
				"amount": row["amount"],
				"mode_of_payment": row["mode_of_payment"],
				"description": row["description"],
			}
		)

	return {"payments": results, "has_more": has_more}


@frappe.whitelist(allow_guest=True, methods=["GET"])
def list_mode_of_payments():
	"""Return enabled Mode of Payment values for mobile UI."""
	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()
	require_doctype_permission("Mode of Payment", "read")

	modes = frappe.get_list(
		"Mode of Payment", filters={"enabled": 1}, fields=["name", "type"], order_by="modified desc"
	)
	return {"modes": modes}


@frappe.whitelist(allow_guest=True, methods=["GET"])
def get_party_references(limit: int | str = 200):
	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()

	limit = max(1, min(1000, cint(limit)))

	employees = frappe.get_list(
		"Employee",
		fields=["name", "employee_name"],
		order_by="modified desc",
		limit_page_length=limit,
	)
	shareholders = frappe.get_list(
		"Shareholder",
		fields=["name", "title"],
		order_by="modified desc",
		limit_page_length=limit,
	)

	return {
		"employees": [
			{
				"code": row["name"],
				"name": row.get("employee_name") or row["name"],
				"display": _display_name(row["name"], row.get("employee_name")),
			}
			for row in employees
		],
		"shareholders": [
			{
				"code": row["name"],
				"name": row.get("title") or row["name"],
				"display": _display_name(row["name"], row.get("title")),
			}
			for row in shareholders
		],
	}


@frappe.whitelist(allow_guest=True, methods=["GET"])
def get_today_cashflow():
	"""
	GET /api/method/mobile_endpoints.api.payment.get_today_cashflow
	Returns hourly inflow/outflow for today from Collection and Payment
	where pamper_collection_and_payment = 1.
	"""
	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()
	require_doctype_permission("Collection and Payment", "read")

	import datetime

	from frappe.utils import today

	today_str = today()

	parents = frappe.get_list(
		"Collection and Payment",
		filters={
			"pamper_collection_and_payment": 1,
			"posting_date": today_str,
			"docstatus": ("!=", 2),
		},
		fields=["name", "creation", "status"],
		limit_page_length=0,
	)

	if not parents:
		return {"labels": [], "inflow": [], "outflow": [], "total_inflow": 0, "total_outflow": 0, "net": 0}

	parent_names = [p["name"] for p in parents]
	creation_map = {p["name"]: p["creation"] for p in parents}

	child_rows = frappe.get_all(
		"Collection and Payment Details",
		filters={"parent": ("in", parent_names)},
		fields=["parent", "payment_type", "amount"],
		order_by="idx asc",
	)

	rows_by_parent: dict[str, list[dict[str, Any]]] = {}
	for row in child_rows:
		rows_by_parent.setdefault(row["parent"], []).append(row)

	hourly_inflow: dict[int, float] = {}
	hourly_outflow: dict[int, float] = {}
	total_inflow = 0.0
	total_outflow = 0.0

	for parent in parents:
		if cstr(parent.get("status")).strip().lower() in {"cancelled", "canceled"}:
			continue
		creation = creation_map.get(parent["name"])
		if isinstance(creation, str):
			try:
				creation = datetime.datetime.strptime(creation, "%Y-%m-%d %H:%M:%S.%f")
			except ValueError:
				try:
					creation = datetime.datetime.strptime(creation, "%Y-%m-%d %H:%M:%S")
				except ValueError:
					continue
		hour = creation.hour if creation else 0
		for row in rows_by_parent.get(parent["name"], []):
			amount = flt(row.get("amount", 0))
			payment_type = cstr(row.get("payment_type", "")).strip().lower()
			if payment_type == "pay":
				hourly_outflow[hour] = hourly_outflow.get(hour, 0) + amount
				total_outflow += amount
			elif payment_type == "receive":
				hourly_inflow[hour] = hourly_inflow.get(hour, 0) + amount
				total_inflow += amount

	all_hours = sorted(set(list(hourly_inflow.keys()) + list(hourly_outflow.keys())))

	if not all_hours:
		return {"labels": [], "inflow": [], "outflow": [], "total_inflow": 0, "total_outflow": 0, "net": 0}

	labels = [f"{h:02d}:00" for h in all_hours]
	inflow_values = [hourly_inflow.get(h, 0) for h in all_hours]
	outflow_values = [hourly_outflow.get(h, 0) for h in all_hours]

	return {
		"labels": labels,
		"inflow": inflow_values,
		"outflow": outflow_values,
		"total_inflow": total_inflow,
		"total_outflow": total_outflow,
		"net": total_inflow - total_outflow,
	}
