from typing import Any, Dict

import frappe
from frappe import _
from frappe.utils import cint, cstr

from mobile_endpoints.api._envelope import mobile_api
from mobile_endpoints.api._idempotency import lookup as _idem_lookup
from mobile_endpoints.api._idempotency import run_idempotent
from mobile_endpoints.api.user import resolve_company

# --- helpers ---------------------------------------------------------------

MANDATORY_PARENT_FIELDS = {"posting_date"}
MANDATORY_DETAIL_FIELDS = {"payment_type", "party_type", "party", "party_name", "amount"}


def _ensure_fields(required: set[str], data: Dict[str, Any], title: str) -> None:
	missing = [field for field in required if not data.get(field)]
	if missing:
		frappe.throw(_("Missing required fields: {0}").format(", ".join(missing)), title=title)


def _extract_payload() -> Dict[str, Any]:
	if frappe.request and frappe.request.method == "POST":
		try:
			parsed = frappe.parse_json(frappe.request.get_data(as_text=True) or "{}")
			if isinstance(parsed, dict):
				return parsed
		except Exception:
			frappe.throw(_("Unable to parse JSON body"), title=_("Invalid Request"))
	return dict(frappe.form_dict or {})


# --- API: create ---------------------------------------------------------------

@frappe.whitelist(methods=["POST"])
@mobile_api
def create_collection_payment():
	"""POST mobile_endpoints.api.payment.create_collection_payment

	Body may include a `client_request_id` (UUID). Replaying the same id returns
	the original payment instead of creating a duplicate.
	"""
	data = _extract_payload()
	client_request_id = data.get("client_request_id")

	_ensure_fields(MANDATORY_PARENT_FIELDS, data, _("Parent Validation Error"))
	# Explicit company (permission-checked) -> user/global default -> the single
	# permitted company; otherwise CompanyError -> 422 with fields.company.
	company = resolve_company(data.get("company"))

	detail = data.get("detail") or (data.get("collection_and_payment_details") or [{}])[0]
	if not detail:
		frappe.throw(_("At least one payment detail is required"), title=_("Child Validation Error"))
	_ensure_fields(MANDATORY_DETAIL_FIELDS, detail, _("Child Validation Error"))

	# Idempotency hash covers the resolved company, not the raw request id.
	idem_payload = {
		"posting_date": data.get("posting_date"),
		"company": company,
		"detail": {k: detail.get(k) for k in sorted(MANDATORY_DETAIL_FIELDS | {"mode_of_payment", "description"})},
	}

	def _create():
		doc = frappe.new_doc("Collection and Payment")
		doc.update({
			"posting_date": data["posting_date"],
			"company": company,
			"pamper_collection_and_payment": 1,
			"pamper_collection": 1 if doc.meta.has_field("pamper_collection") else None,
		})
		doc.append("collection_and_payment_details", {
			"payment_type": detail["payment_type"],
			"party_type": detail["party_type"],
			"party": detail["party"],
			"party_name": detail["party_name"],
			"amount": detail["amount"],
			"mode_of_payment": detail.get("mode_of_payment"),
			"description": detail.get("description"),
			"is_pamper": 1,
		})
		doc.insert(ignore_permissions=False)  # no commit — run_idempotent owns it
		return doc.name, {
			"name": doc.name,
			"posting_date": cstr(doc.posting_date),
			"company": company,
			"modified": cstr(doc.modified),
			"message": _("Collection payment created"),
		}

	return run_idempotent(client_request_id, "payment.create", idem_payload, _create)


@frappe.whitelist(methods=["GET"])
@mobile_api
def get_payment_by_request_id(client_request_id: str):
	"""Called by the client after a create POST times out."""
	return _idem_lookup(client_request_id, "payment.create")


# --- API: list ---------------------------------------------------------------

@frappe.whitelist()
@mobile_api
def list_collection_payments(page: int = 1, page_size: int = 20):
	page = max(1, cint(page))
	page_size = min(100, max(1, cint(page_size)))
	start = (page - 1) * page_size

	parents = frappe.get_all(
		"Collection and Payment",
		filters={"pamper_collection_and_payment": 1},
		fields=["name", "posting_date", "company", "owner", "creation"],
		order_by="creation desc",
		limit_start=start,
		limit_page_length=page_size,
	)
	if not parents:
		return {"payments": [], "has_more": False}

	parent_names = [p["name"] for p in parents]
	child_rows = frappe.get_all(
		"Collection and Payment Details",
		filters={"parent": ("in", parent_names)},
		fields=["parent", "payment_type", "party_type", "party", "party_name", "amount", "mode_of_payment", "description"],
		order_by="idx asc",
	)
	first_row_map: Dict[str, Dict[str, Any]] = {}
	for row in child_rows:
		first_row_map.setdefault(row["parent"], row)

	results = []
	for parent in parents:
		row = first_row_map.get(parent["name"])
		if not row:
			continue
		results.append({
			"name": parent["name"],
			"posting_date": parent["posting_date"],
			"company": parent["company"],
			"payment_type": row["payment_type"],
			"party_type": row["party_type"],
			"party": row["party"],
			"party_name": row["party_name"],
			"amount": row["amount"],
			"mode_of_payment": row["mode_of_payment"],
			"description": row["description"],
		})

	has_more = len(parents) == page_size
	return {"payments": results, "has_more": has_more}


@frappe.whitelist()
@mobile_api
def list_mode_of_payments():
	modes = frappe.get_all(
		"Mode of Payment",
		filters={"enabled": 1},
		fields=["name", "type"],
		order_by="modified desc",
	)
	return {"modes": modes}
