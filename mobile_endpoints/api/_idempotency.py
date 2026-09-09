"""Server-side idempotency for money-creating POSTs.

A `client_request_id` (UUID from the mobile app) is recorded in the
`Mobile Request Log` doctype. Replaying the same id returns the stored result
instead of creating a second document. Replaying the same id with a *different*
payload raises `IdempotencyConflict` (HTTP 409).
"""

import hashlib
import json

import frappe

DOCTYPE = "Mobile Request Log"


class IdempotencyConflict(frappe.ValidationError):
    pass


def _hash_payload(payload) -> str:
    canonical = json.dumps(payload or {}, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _stored(key: str):
    return frappe.db.get_value(
        DOCTYPE,
        {"client_request_id": key},
        ["name", "request_hash", "response_json", "status", "docname"],
        as_dict=True,
    )


def run_idempotent(client_request_id, scope: str, payload: dict, fn):
    """`fn()` must return `(docname, response_dict)` and perform its own commit.

    Returns `response_dict` (freshly created or replayed).
    """
    key = (str(client_request_id).strip() if client_request_id else "")
    if not key:
        # Legacy caller without a key: run once, no dedup.
        _docname, response = fn()
        return response

    request_hash = _hash_payload(payload)

    existing = _stored(key)
    if existing:
        if existing.request_hash and existing.request_hash != request_hash:
            raise IdempotencyConflict(
                frappe._("This request id was already used with a different payload.")
            )
        if existing.status == "done" and existing.response_json:
            return json.loads(existing.response_json)
        raise IdempotencyConflict(
            frappe._("A request with this id is still being processed. Please retry shortly.")
        )

    # Claim the key. The unique index on `client_request_id` breaks the race
    # if two requests arrive together.
    log = frappe.get_doc(
        {
            "doctype": DOCTYPE,
            "client_request_id": key,
            "scope": scope,
            "user": frappe.session.user,
            "request_hash": request_hash,
            "status": "processing",
        }
    )
    try:
        log.insert(ignore_permissions=True)
        frappe.db.commit()
    except Exception:
        frappe.db.rollback()
        if frappe.db.exists(DOCTYPE, {"client_request_id": key}):
            replay = _stored(key)
            if replay and replay.status == "done" and replay.response_json:
                return json.loads(replay.response_json)
            raise IdempotencyConflict(
                frappe._("A request with this id is still being processed. Please retry shortly.")
            )
        raise

    docname, response = fn()

    log.reload()
    log.docname = docname or ""
    log.response_json = json.dumps(response, default=str, ensure_ascii=False)
    log.status = "done"
    log.save(ignore_permissions=True)
    frappe.db.commit()
    return response


def lookup(client_request_id: str, scope: str | None = None):
    """Used by the client after a POST timeout to discover whether the write
    landed. Returns `{found, status, name?, result?}`."""
    key = (str(client_request_id).strip() if client_request_id else "")
    if not key:
        return {"found": False}
    filters = {"client_request_id": key}
    if scope:
        filters["scope"] = scope
    row = frappe.db.get_value(
        DOCTYPE, filters, ["docname", "status", "response_json"], as_dict=True
    )
    if not row:
        return {"found": False}
    if row.status == "done" and row.response_json:
        return {
            "found": True,
            "status": "done",
            "name": row.docname,
            "result": json.loads(row.response_json),
        }
    return {"found": True, "status": row.status or "processing"}
