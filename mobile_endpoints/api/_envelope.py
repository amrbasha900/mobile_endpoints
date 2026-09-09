"""Unified response envelope for the mobile API.

Success:
    {"success": true, "data": {...}, "meta": {"request_id": "..."}}
Error:
    {"success": false,
     "error": {"code": "...", "message": "...", "fields": {}},
     "meta": {"request_id": "..."}}

For backward compatibility with the currently deployed mobile client, `ok()`
also mirrors the top-level keys of `data` onto the envelope, so a client that
still reads `resp.message.name` keeps working during rollout.
"""

import functools

import frappe
from frappe import _

# --- documented error codes ------------------------------------------------
ERR_NOT_AUTHENTICATED = "not_authenticated"
ERR_PERMISSION_DENIED = "permission_denied"
ERR_NOT_FOUND = "not_found"
ERR_VALIDATION = "validation_error"
ERR_CONFLICT = "conflict"
ERR_IDEMPOTENCY_CONFLICT = "idempotency_conflict"
ERR_RATE_LIMITED = "rate_limited"
ERR_SERVER = "server_error"


class StaleDocumentError(frappe.ValidationError):
    """Raised when an update's `base_modified` no longer matches the server.
    Carry the current server state on `.current` so the client can reload."""

    def __init__(self, message, current=None):
        super().__init__(message)
        self.current = current


class CompanyError(frappe.ValidationError):
    """Company could not be resolved / is not permitted for this user."""

    def __init__(self, message, field="company"):
        super().__init__(message)
        self.field = field


def request_id() -> str:
    rid = getattr(frappe.local, "mobile_request_id", None)
    if not rid:
        rid = frappe.generate_hash(length=16)
        frappe.local.mobile_request_id = rid
    return rid


def _set_status(http_status: int) -> None:
    try:
        if http_status and int(http_status) != 200:
            frappe.local.response["http_status_code"] = int(http_status)
    except Exception:
        pass


def ok(data=None, http_status: int = 200):
    payload = {
        "success": True,
        "data": data if data is not None else {},
        "meta": {"request_id": request_id()},
    }
    if isinstance(data, dict):
        for key, value in data.items():
            payload.setdefault(key, value)
    _set_status(http_status)
    return payload


def fail(code: str, message: str, fields: dict | None = None, http_status: int = 400, data=None):
    _set_status(http_status)
    env = {
        "success": False,
        "error": {"code": code, "message": message, "fields": fields or {}},
        "meta": {"request_id": request_id()},
    }
    if data is not None:
        env["data"] = data
    return env


def _first_message(exc: Exception) -> str:
    for entry in (frappe.local.message_log or []):
        try:
            text = entry.get("message") if isinstance(entry, dict) else str(entry)
        except Exception:
            text = str(entry)
        if text:
            return frappe.utils.strip_html_tags(str(text))
    return str(exc) or _("Request could not be completed.")


def mobile_api(fn):
    """Wrap a whitelisted handler so every outcome is a unified envelope.

    - a handler may `return _envelope.fail(...)` directly — passed through;
    - a plain dict return is wrapped with `ok(...)`;
    - `StaleDocumentError`  -> 409 `conflict` (with current state in `data`);
    - `CompanyError`        -> 422 `validation_error` (with `fields`);
    - `frappe.PermissionError` -> 403 `permission_denied`;
    - `frappe.DoesNotExistError` -> 404 `not_found`;
    - `IdempotencyConflict` -> 409 `idempotency_conflict`;
    - any other `frappe.ValidationError` (incl. `frappe.throw`) -> 422;
    - anything else -> 500 (traceback logged, message sanitised).
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        from mobile_endpoints.api._idempotency import IdempotencyConflict

        try:
            result = fn(*args, **kwargs)
        except StaleDocumentError as exc:
            frappe.db.rollback()
            return fail(
                ERR_CONFLICT,
                str(exc) or _("This record was changed on the server. Reload and try again."),
                fields={"server_modified": ""},
                http_status=409,
                data=getattr(exc, "current", None),
            )
        except CompanyError as exc:
            frappe.db.rollback()
            return fail(
                ERR_VALIDATION,
                str(exc) or _("A company is required."),
                fields={getattr(exc, "field", "company"): "invalid"},
                http_status=422,
            )
        except frappe.AuthenticationError as exc:
            frappe.db.rollback()
            return fail(ERR_NOT_AUTHENTICATED, str(exc) or _("Authentication required"), http_status=401)
        except frappe.PermissionError as exc:
            frappe.db.rollback()
            return fail(ERR_PERMISSION_DENIED, str(exc) or _("Not permitted"), http_status=403)
        except frappe.DoesNotExistError as exc:
            frappe.db.rollback()
            return fail(ERR_NOT_FOUND, str(exc) or _("Document not found"), http_status=404)
        except IdempotencyConflict as exc:
            frappe.db.rollback()
            return fail(ERR_IDEMPOTENCY_CONFLICT, str(exc), http_status=409)
        except frappe.ValidationError as exc:
            frappe.db.rollback()
            return fail(ERR_VALIDATION, _first_message(exc), http_status=422)
        except Exception:
            frappe.db.rollback()
            frappe.log_error(frappe.get_traceback(), f"mobile_api:{getattr(fn, '__name__', 'handler')}")
            return fail(ERR_SERVER, _("Unexpected server error. Please try again."), http_status=500)

        if isinstance(result, dict) and "success" in result:
            return result
        return ok(result)

    return wrapper
