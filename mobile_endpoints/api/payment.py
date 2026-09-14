from typing import Any

import frappe
from frappe import _
from frappe.utils import cint, cstr, flt

from mobile_endpoints.api._dates import resolve_period, site_timezone
from mobile_endpoints.api._envelope import mobile_api, ok
from mobile_endpoints.api._idempotency import lookup as _idem_lookup
from mobile_endpoints.api._idempotency import run_idempotent
from mobile_endpoints.api.security import (
	require_authenticated_user,
	require_doctype_permission,
	set_cors_headers,
)
from mobile_endpoints.api.user import resolve_company

# --- helpers ---------------------------------------------------------------

# `company` is resolved by resolve_company() (BR-06), not required in the body.
MANDATORY_PARENT_FIELDS = {"posting_date"}
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


# --- API: create ---------------------------------------------------------------


@frappe.whitelist(allow_guest=True, methods=["POST"])
@mobile_api
def create_collection_payment():
	"""
	POST /api/method/mobile_endpoints.api.payment.create_collection_payment

	Body may include a `client_request_id` (UUID); replaying the same id returns
	the original payment instead of creating a duplicate. `company` is optional —
	it is resolved from the explicit value, then the user/global default, then the
	single permitted company (BR-06); otherwise a 422 with `fields.company`.
	"""
	set_cors_headers("POST, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()
	require_doctype_permission("Collection and Payment", "create")

	data = _extract_payload()
	client_request_id = data.get("client_request_id")

	_ensure_fields(MANDATORY_PARENT_FIELDS, data, _("Parent Validation Error"))

	# Explicit company (permission-checked) -> user/global default -> the single
	# permitted company; otherwise CompanyError -> 422 with fields.company.
	company = resolve_company(data.get("company"))

	detail = _payment_detail(data)
	_ensure_fields(MANDATORY_DETAIL_FIELDS, detail, _("Child Validation Error"))
	amount = flt(detail.get("amount"))
	if amount <= 0:
		frappe.throw(_("Amount must be greater than zero"), frappe.ValidationError)

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
	# Party name is always taken from the server, never the client payload.
	party_name = cstr(frappe.db.get_value(party_type, party, PARTY_NAME_FIELDS[party_type]) or party)

	mode_of_payment = cstr(detail.get("mode_of_payment")).strip()
	if mode_of_payment:
		if not frappe.db.exists("Mode of Payment", mode_of_payment):
			frappe.throw(_("Invalid mode of payment"), frappe.ValidationError)
		require_doctype_permission("Mode of Payment", "read", mode_of_payment)

	description = cstr(detail.get("description"))

	# Idempotency hash covers the resolved (server-side) values, not the raw id.
	idem_payload = {
		"posting_date": data.get("posting_date"),
		"company": company,
		"detail": {
			"payment_type": payment_type,
			"party_type": party_type,
			"party": party,
			"amount": amount,
			"mode_of_payment": mode_of_payment,
			"description": description,
		},
	}

	def _create():
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
				"description": description,
				"is_pamper": 1,
			},
		)

		doc.insert(ignore_permissions=False)  # no commit — run_idempotent owns the txn
		return doc.name, {
			"name": doc.name,
			"posting_date": cstr(doc.posting_date),
			"company": company,
			"modified": cstr(doc.modified),
			"message": _("Collection payment created"),
		}

	return run_idempotent(client_request_id, "payment.create", idem_payload, _create)


@frappe.whitelist(allow_guest=True, methods=["GET"])
@mobile_api
def get_payment_by_request_id(client_request_id: str | None = None):
	"""Called by the client after a create POST times out."""
	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}
	require_authenticated_user()
	return _idem_lookup(client_request_id, "payment.create")


# --- API: list -------------------------------------------------------------


def _normalize_payment_status(value) -> str:
	"""Mirrors the deployed client's own TransactionsPage normalizeStatus():
	Approved/Paid -> approved, Rejected -> rejected, everything else
	(including blank/unset) -> pending. Not inventing a new vocabulary --
	just moving the existing client-side classification onto the server so
	the summary agrees with what a user already sees on screen."""
	normalized = cstr(value).strip().lower()
	if normalized in {"approved", "paid"}:
		return "approved"
	if normalized == "rejected":
		return "rejected"
	return "pending"


def _status_row_filter(status: str) -> list:
	"""Row-level SQL condition for one status bucket. `not in` is used (not a
	`!=`/exclusion built from _normalize_payment_status's blank->pending rule)
	because Frappe's query builder is documented to treat `!=`/`not in`
	filters as NULL-inclusive (`(status NOT IN (...) OR status IS NULL)`) --
	unlike a bare SQL `!=`/`NOT IN`, which would silently drop blank-status
	rows from "pending". This specific NULL-inclusive behavior is the one
	piece of this change that could not be verified without a live bench --
	see TestPaymentFilters.test_pending_status_filter_includes_blank_status
	in test_reliability.py, which must pass on the real bench before this is
	trusted for the "pending" bucket."""
	if status == "approved":
		return ["status", "in", ["Approved", "Paid"]]
	if status == "rejected":
		return ["status", "=", "Rejected"]
	return ["status", "not in", ["Approved", "Paid", "Rejected"]]


@frappe.whitelist(allow_guest=True, methods=["GET"])
@mobile_api
def list_collection_payments(
	page: int = 1,
	page_size: int = 20,
	start_date: str | None = None,
	end_date: str | None = None,
	from_date: str | None = None,
	to_date: str | None = None,
	company: str | None = None,
	search: str | None = None,
	party_type: str | None = None,
	party: str | None = None,
	payment_type: str | None = None,
	status: str | None = None,
):
	"""
	GET /api/method/mobile_endpoints.api.payment.list_collection_payments
	Returns only documents where pamper_collection_and_payment = 1.
	`from_date`/`to_date` are canonical (`start_date`/`end_date` kept as
	aliases); neither given -> defaults to "today" in the site timezone.

	`party_type`/`party`/`payment_type`/`search` filter on the CHILD
	"Collection and Payment Details" table via frappe.get_list's child-table
	filter form (`[child_doctype, fieldname, operator, value]`) applied to
	the PARENT doctype query -- the join and the permission-query condition
	execute as ONE query, so a child-row match can never surface a parent the
	caller isn't authorized to see. This is the one part of this change that
	could not be verified without a live bench (see the module docstring's
	"Request-harness policy" and TestPaymentFilters below); no unrestricted
	child-table scan is used anywhere in this function.
	"""
	set_cors_headers("GET, OPTIONS")
	if frappe.local.request and frappe.local.request.method == "OPTIONS":
		return {}

	require_authenticated_user()
	require_doctype_permission("Collection and Payment", "read")

	page = max(1, cint(page))
	page_size = min(100, max(1, cint(page_size)))
	start = (page - 1) * page_size

	resolved_from, resolved_to = resolve_period(from_date or start_date, to_date or end_date)

	# Shared by rows AND the summary below: date/company/search/party/
	# payment_type -- only STATUS is excluded from base_filters (applied
	# separately, below, to `filters` for rows only), so a status card never
	# hides the others and a status-filtered list still reports accurate
	# counts for every OTHER status.
	base_filters = [
		["pamper_collection_and_payment", "=", 1],
		["posting_date", ">=", resolved_from],
		["posting_date", "<=", resolved_to],
	]
	if company:
		base_filters.append(["company", "=", cstr(company)])

	if party_type is not None:
		party_type = cstr(party_type).strip()
		if party_type not in PARTY_NAME_FIELDS:
			frappe.throw(_("Unsupported party type"), frappe.ValidationError)
		base_filters.append(["Collection and Payment Details", "party_type", "=", party_type])

	if party:
		base_filters.append(["Collection and Payment Details", "party", "=", cstr(party)])

	if payment_type is not None:
		normalized_payment_type = cstr(payment_type).strip().title()
		if normalized_payment_type not in {"Pay", "Receive"}:
			frappe.throw(_("Unsupported payment type"), frappe.ValidationError)
		base_filters.append(["Collection and Payment Details", "payment_type", "=", normalized_payment_type])

	or_filters = None
	s = cstr(search).strip() if search else ""
	if s:
		# Free-text party search -- name and identifier, matching the
		# deployed client's own search semantics for "who this payment is
		# with". Amount/date substring matching is intentionally NOT
		# replicated here: date now has a dedicated, more precise range
		# filter (from_date/to_date) and amount-substring matching against a
		# decimal column has no safe equivalent in frappe.get_list's filter
		# DSL -- see the increment's commit message for this scope decision.
		or_filters = [
			["Collection and Payment Details", "party_name", "like", f"%{s}%"],
			["Collection and Payment Details", "party", "like", f"%{s}%"],
		]

	filters = list(base_filters)
	if status:
		normalized_status = _normalize_payment_status(status)
		filters.append(_status_row_filter(normalized_status))

	meta = frappe.get_meta("Collection and Payment")
	has_currency_field = meta.has_field("currency")

	parents = frappe.get_list(
		"Collection and Payment",
		filters=filters,
		or_filters=or_filters,
		fields=["name", "posting_date", "company", "owner", "creation", "status"],
		order_by="creation desc",
		limit_start=start,
		limit_page_length=page_size + 1,
	)

	has_more = len(parents) > page_size
	parents = parents[:page_size]
	parent_names = [p["name"] for p in parents]

	child_rows = []
	if parent_names:
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

	# Assumes (as the pre-existing code already did) one relevant detail row
	# per parent -- create_collection_payment() always inserts exactly one.
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

	# --- summary -------------------------------------------------------
	# Every authorized record matching the SAME date/company/search/party/
	# payment_type filters as the rows above (base_filters + or_filters,
	# deliberately NOT `filters`, which also carries the active status
	# filter) -- the whole filtered set, not just this page, and never
	# narrowed to just the status card currently selected. Cancelled
	# (docstatus=2) parents are excluded entirely (never counted, never
	# included in financial totals). Permission-aware throughout:
	# frappe.get_list for the parent scope, never get_all/ignore_permissions;
	# the one frappe.get_all below is scoped to that already-vetted parent
	# set (child table rows carry no permissions of their own in Frappe).
	summary_fields = ["name", "status", "docstatus"]
	if has_currency_field:
		summary_fields.append("currency")
	summary_parents = frappe.get_list(
		"Collection and Payment",
		filters=base_filters + [["docstatus", "!=", 2]],
		or_filters=or_filters,
		fields=summary_fields,
		limit_page_length=0,
	)

	total_count = len(summary_parents)
	approved_count = 0
	rejected_count = 0
	approved_names: list[str] = []
	currency_by_name: dict[str, str] = {}
	for p in summary_parents:
		bucket = _normalize_payment_status(p.get("status"))
		if bucket == "approved":
			approved_count += 1
			approved_names.append(p["name"])
			if has_currency_field:
				currency_by_name[p["name"]] = cstr(p.get("currency")) or "default"
		elif bucket == "rejected":
			rejected_count += 1
	pending_count = total_count - approved_count - rejected_count

	# Financial totals: approved transactions only, decimal-safe (flt at
	# currency precision), grouped by currency if this doctype tracks one --
	# never silently summed across mismatched currencies.
	totals_by_currency: dict[str, dict[str, float]] = {}
	if approved_names:
		summary_child_rows = frappe.get_all(
			"Collection and Payment Details",
			filters={"parent": ("in", approved_names)},
			fields=["parent", "payment_type", "amount"],
		)
		for row in summary_child_rows:
			currency_key = currency_by_name.get(row["parent"], "default") if has_currency_field else "default"
			bucket = totals_by_currency.setdefault(currency_key, {"inflow": 0.0, "outflow": 0.0})
			amount = flt(row.get("amount", 0), 2)
			payment_type = cstr(row.get("payment_type", "")).strip().lower()
			if payment_type == "pay":
				bucket["outflow"] = flt(bucket["outflow"] + amount, 2)
			elif payment_type == "receive":
				bucket["inflow"] = flt(bucket["inflow"] + amount, 2)

	by_currency = {
		currency: {
			"inflow": vals["inflow"],
			"outflow": vals["outflow"],
			"net": flt(vals["inflow"] - vals["outflow"], 2),
		}
		for currency, vals in totals_by_currency.items()
	}
	if len(by_currency) <= 1:
		only = next(iter(by_currency.values()), {"inflow": 0.0, "outflow": 0.0, "net": 0.0})
		totals = {**only, "basis": "approved"}
	else:
		# Multiple currencies among the authorized, approved results -- a
		# single combined figure would be misleading. The client must show
		# `totals_by_currency` separately or require a currency filter.
		totals = {"basis": "approved", "mixed_currencies": True}

	summary = {
		"total": total_count,
		"approved": approved_count,
		"pending": pending_count,
		"rejected": rejected_count,
		"totals": totals,
	}
	if has_currency_field:
		summary["totals_by_currency"] = by_currency

	data = {
		"payments": results,
		"has_more": has_more,
		"summary": summary,
		"period": {"from_date": resolved_from, "to_date": resolved_to, "timezone": site_timezone()},
	}
	return ok(data, meta={"total_count": total_count})


@frappe.whitelist(allow_guest=True, methods=["GET"])
@mobile_api
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
@mobile_api
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
@mobile_api
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
