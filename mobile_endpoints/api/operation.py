"""Generic 'did my write land?' check, used by the mobile client after a POST
timeout. Replaces the per-domain get_*_by_request_id helpers (kept as thin
wrappers for the deployed client during rollout).
"""

import frappe
from frappe import _

from mobile_endpoints.api._envelope import ERR_VALIDATION, fail, mobile_api
from mobile_endpoints.api._idempotency import lookup
from mobile_endpoints.api.security import require_authenticated_user, set_cors_headers

ALLOWED_SCOPES = {
    "invoice.create",
    "invoice.update",
    "invoice.submit",
    "invoice.delete",
    "payment.create",
}


@frappe.whitelist(allow_guest=True, methods=["GET"])
@mobile_api
def get_operation_status(client_request_id: str | None = None, scope: str | None = None):
    """Returns {found, status: "processing"|"done", name?, result?} for the
    caller's own request id only (the lookup key is derived from the session
    user, so it can never surface another user's result)."""
    set_cors_headers("GET, OPTIONS")
    if frappe.local.request and frappe.local.request.method == "OPTIONS":
        return {}

    require_authenticated_user()

    if scope not in ALLOWED_SCOPES:
        return fail(
            ERR_VALIDATION,
            _("Unknown operation scope."),
            fields={"scope": "invalid"},
            http_status=422,
        )
    return lookup(client_request_id, scope)
