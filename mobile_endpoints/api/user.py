import frappe

from mobile_endpoints.api._envelope import CompanyError, mobile_api


@frappe.whitelist()
@mobile_api
def get_user_default_company():
    return {"default_company": _default_company()}


@frappe.whitelist(methods=["GET"])
@mobile_api
def list_companies():
    """Companies this user may post against, plus the resolved default.

    - one company  -> the client auto-selects it (no picker);
    - many         -> the client shows a picker;
    - none         -> the client shows the 'no company' error.
    """
    companies = frappe.get_list(
        "Company", fields=["name"], pluck="name", order_by="name asc", ignore_permissions=False
    )
    default = _default_company()
    if default not in companies:
        default = companies[0] if len(companies) == 1 else ""
    return {
        "companies": [{"id": c, "name": c} for c in companies],
        "default": default or "",
    }


def _default_company() -> str:
    default = frappe.defaults.get_user_default("Company") or frappe.defaults.get_global_default("Company")
    if default and frappe.has_permission("Company", "read", default):
        return default
    return ""


def resolve_company(explicit) -> str:
    """Explicit company (permission-checked) -> user/global default ->
    the single permitted company. Anything else raises CompanyError (422)."""
    explicit = (explicit or "").strip()
    if explicit:
        if not frappe.has_permission("Company", ptype="read", doc=explicit):
            raise CompanyError(frappe._("You do not have access to the selected company."))
        return explicit

    default = _default_company()
    if default:
        return default

    permitted = frappe.get_list("Company", pluck="name", ignore_permissions=False)
    if len(permitted) == 1:
        return permitted[0]
    if not permitted:
        raise CompanyError(frappe._("No company is available for your account."))
    raise CompanyError(frappe._("Select a company for this payment."))
