"""Server-side idempotency for money-affecting POSTs.

A `client_request_id` (UUID from the mobile app) is recorded in the
`Mobile Request Log` doctype, scoped by **user + operation**. Replaying the same
id (same user, same scope) returns the stored result instead of repeating the
write. Replaying with a different payload -> `IdempotencyConflict` (HTTP 409).

Transaction model: `run_idempotent()` owns the transaction. The key reservation
row and the created document commit together in one `frappe.db.commit()`; on any
failure everything is rolled back, so a retry with the same key starts clean and
a failed operation never leaves a "done" log.
"""

import hashlib
import json

import frappe

DOCTYPE = "Mobile Request Log"
RETENTION_DAYS = 30


class IdempotencyConflict(frappe.ValidationError):
    pass


def _hash_payload(payload) -> str:
    canonical = json.dumps(payload or {}, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _composite(user: str, scope: str, key: str) -> str:
    """Deterministic primary key, scoped by user + operation. Hashing keeps it a
    fixed 64 chars regardless of the user's email length."""
    raw = f"{user}\x00{scope}\x00{key}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _stored(composite: str):
    return frappe.db.get_value(
        DOCTYPE,
        {"name": composite},
        ["name", "request_hash", "response_json", "status", "docname", "user"],
        as_dict=True,
    )


def run_idempotent(client_request_id, scope: str, payload: dict, fn):
    """`fn()` must return `(docname, response_dict)` and MUST NOT commit."""
    user = frappe.session.user
    key = (str(client_request_id).strip() if client_request_id else "")

    if not key:
        # Legacy caller without a key: run once, no dedup. We still own the commit.
        _docname, response = fn()
        frappe.db.commit()
        return response

    composite = _composite(user, scope, key)
    request_hash = _hash_payload(payload)

    existing = _stored(composite)
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

    log = frappe.get_doc(
        {
            "doctype": DOCTYPE,
            "name": composite,
            "composite_key": composite,
            "client_request_id": key,
            "scope": scope,
            "user": user,
            "request_hash": request_hash,
            "status": "processing",
        }
    )
    try:
        # Reserve the key. The primary-key/unique constraint (and the row lock it
        # takes until commit) is what serialises concurrent duplicates.
        log.insert(ignore_permissions=True)
        docname, response = fn()  # no commit inside
        frappe.db.set_value(
            DOCTYPE,
            composite,
            {
                "docname": docname or "",
                "response_json": json.dumps(response, default=str, ensure_ascii=False),
                "status": "done",
            },
            update_modified=False,
        )
        frappe.db.commit()
        return response
    except IdempotencyConflict:
        frappe.db.rollback()
        raise
    except Exception:
        frappe.db.rollback()
        # A concurrent request may have won the reservation and finished.
        replay = _stored(composite)
        if replay and replay.status == "done" and replay.response_json:
            return json.loads(replay.response_json)
        raise


def lookup(client_request_id: str, scope: str):
    """Post-timeout check: did this exact (user, scope, request id) operation
    land? A user can only ever see their own request ids — the composite key is
    derived from `frappe.session.user`."""
    user = frappe.session.user
    key = (str(client_request_id).strip() if client_request_id else "")
    if not key or not scope:
        return {"found": False}
    composite = _composite(user, scope, key)
    row = frappe.db.get_value(
        DOCTYPE, {"name": composite}, ["docname", "status", "response_json"], as_dict=True
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


def cleanup_old_logs():
    """Scheduled daily. Idempotency only needs to cover realistic retry windows;
    drop anything older than RETENTION_DAYS. Rows hold only a payload hash, the
    stored response and the owning user — never tokens or auth headers."""
    cutoff = frappe.utils.add_days(frappe.utils.now_datetime(), -RETENTION_DAYS)
    frappe.db.delete(DOCTYPE, {"creation": ["<", cutoff]})
    frappe.db.commit()
