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

    - a handler may `return _envelope.fail(...)` directly for expected errors
      (validation / 409) — it is passed through untouched;
    - a plain dict return is wrapped with `ok(...)`;
    - `frappe.PermissionError` -> 403 `permission_denied`;
    - `frappe.DoesNotExistError` -> 404 `not_found`;
    - `IdempotencyConflict` -> 409 `idempotency_conflict`;
    - any other `frappe.ValidationError` (incl. `frappe.throw`) -> 422;
    - anything else -> 500 (traceback logged, message sanitised).
    """

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        # Local import to avoid a circular import at module load.
        from mobile_endpoints.api._idempotency import IdempotencyConflict

        try:
            result = fn(*args, **kwargs)
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
