"""Per-user print preferences and secure PDF rendering.

Exactly two documents are printable, and the client names them by a fixed
*kind*, never by DocType. Generic DocType printing is not offered: a client
that can name a DocType can print anything the session can read, which is a far
larger surface than this feature needs.

## Where format authorisation comes from

Not from Frappe's own `Print Format` permissions. In 15.86.0 that DocType
grants `read` to System Manager only (a Desk User gets `select`), so there is
no per-record isolation to inherit, and granting `read` globally would let
every user enumerate every format on the site — a change to the platform to
serve one feature.

Authorisation is therefore owned by this app, in `Mobile Print Format Access`:
one row grants one principal (a User, or a Role) the use of one print format
for one document kind. The allowed set for the current user is the union of
their direct rules and the rules of the roles they actually hold, de-duplicated.

**Deny by default.** No matching rule means an empty list, never "all formats".
Disabling a rule, deleting it, or removing the role from the user takes effect
on the next call, because nothing is cached. There is no System Manager bypass:
an administrator manages the rules from Desk but still needs a rule to print.

Policy rows and `Print Format` metadata are read with `frappe.db` helpers,
because this table *is* the app's own authorisation source and reading it
through the caller's permissions would be circular. That is never used to reach
business data: access to `Invoice Form` and `Collection and Payment` stays
subject to `has_permission("read")` on the document itself, and
`ignore_permissions` appears nowhere.

## Where the preference lives

`frappe.defaults.set_user_default` / `get_user_default`, under scrubbed,
app-prefixed keys. Verified safe for this purpose: `is_a_user_permission_key()`
treats a key as a User Permission only when `key != frappe.scrub(key)`, and
these keys are already scrubbed, so they are stored as ordinary per-user
defaults and cannot be confused with a permission rule. The value is always
written for `frappe.session.user`; no caller may name another user.
"""

import frappe
from frappe import _

from mobile_endpoints.api._envelope import FieldValidationError, mobile_api
from mobile_endpoints.api._idempotency import run_idempotent
from mobile_endpoints.api.security import require_authenticated_user, set_cors_headers

# The only documents this app prints. The client sends a key of this map.
PRINTABLE_DOCUMENTS = {
    "invoice": "Invoice Form",
    "payment": "Collection and Payment",
}

# Per-user preference keys. Scrubbed on purpose — see the module docstring.
PREFERENCE_KEYS = {
    "invoice": "pamper_print_format_invoice",
    "payment": "pamper_print_format_payment",
}

IDEMPOTENCY_SCOPE = "printing.settings.update"

# A generated PDF is held in memory and streamed; nothing is persisted.
MAX_PDF_BYTES = 20 * 1024 * 1024


def _require_kind(value: object, field: str = "document_kind") -> str:
    """Resolve a document kind, or refuse. Anything outside the allowlist is a
    422 naming the field — never an attempt to treat it as a DocType."""
    kind = (str(value).strip().lower() if value is not None else "")
    if kind not in PRINTABLE_DOCUMENTS:
        raise FieldValidationError(
            _("Unsupported document. Expected one of: {0}").format(
                ", ".join(sorted(PRINTABLE_DOCUMENTS))
            ),
            field=field,
        )
    return kind


POLICY_DOCTYPE = "Mobile Print Format Access"


def _policy_formats(kind: str) -> list[str]:
    """Print formats the current user is allowed to use for `kind`.

    Union of rules naming the user directly and rules naming a role they
    actually hold right now, de-duplicated and ordered for a stable UI.
    `frappe.get_roles` is read live, so losing a role removes the format on the
    very next call.
    """
    user = frappe.session.user
    roles = frappe.get_roles(user)

    names: set[str] = set()
    for row in frappe.db.get_all(
        POLICY_DOCTYPE,
        filters={"enabled": 1, "document_kind": kind, "principal_type": "User", "user": user},
        fields=["print_format"],
    ):
        if row.get("print_format"):
            names.add(row["print_format"])

    if roles:
        for row in frappe.db.get_all(
            POLICY_DOCTYPE,
            filters={
                "enabled": 1,
                "document_kind": kind,
                "principal_type": "Role",
                "role": ["in", roles],
            },
            fields=["print_format"],
        ):
            if row.get("print_format"):
                names.add(row["print_format"])

    if not names:
        # Deny by default. Nothing is substituted for an empty policy.
        return []

    # A rule can outlive the format it names, or the format can be disabled or
    # rebound to another DocType after the rule was written. Re-checked here
    # rather than trusted, so a stale rule cannot widen access.
    doctype = PRINTABLE_DOCUMENTS[kind]
    usable = frappe.db.get_all(
        "Print Format",
        filters={
            "name": ["in", sorted(names)],
            "doc_type": doctype,
            "disabled": 0,
            "raw_printing": 0,
        },
        fields=["name"],
        order_by="name asc",
    )
    return [row["name"] for row in usable if row.get("name")]


def _doctype_default(doctype: str) -> str | None:
    """The DocType's own default print format, if it has one.

    This is a global default (`DocType.default_print_format`), not a per-user
    one; it is only ever used as a fallback and only when the user is allowed
    to use it.
    """
    value = frappe.db.get_value("DocType", doctype, "default_print_format")
    return value or None


def _saved_preference(kind: str) -> str | None:
    value = frappe.defaults.get_user_default(PREFERENCE_KEYS[kind])
    if isinstance(value, (list, tuple)):
        # Defensive: a list shape means the key was written as a multi-value
        # default. Not a usable preference.
        return None
    value = (str(value).strip() if value else "")
    return value or None


def _resolve(kind: str) -> dict:
    """The documented resolution policy, in order:

    1. the saved preference, if it still exists and is still allowed;
    2. the DocType's default, if it exists and is allowed;
    3. the only allowed format, when there is exactly one;
    4. otherwise nothing, and the client must ask the user to choose.

    A fallback is never written back during a read — a GET that quietly saves
    would make a user's stored preference depend on when they happened to open
    the screen.
    """
    doctype = PRINTABLE_DOCUMENTS[kind]
    allowed = _policy_formats(kind)
    saved = _saved_preference(kind)
    # A saved format that was disabled or had its permission withdrawn is
    # reported as stale rather than silently used or silently forgotten.
    saved_is_usable = bool(saved) and saved in allowed

    effective = None
    if saved_is_usable:
        effective = saved
    else:
        fallback = _doctype_default(doctype)
        if fallback and fallback in allowed:
            effective = fallback
        elif len(allowed) == 1:
            effective = allowed[0]

    return {
        "doctype": doctype,
        "formats": [{"id": name, "label": name} for name in allowed],
        "saved": saved,
        "saved_is_stale": bool(saved) and not saved_is_usable,
        "effective": effective,
        "needs_selection": effective is None,
    }


@frappe.whitelist(allow_guest=True, methods=["GET"])
@mobile_api
def get_print_settings():
    """GET mobile_endpoints.api.printing.get_print_settings

    Returns, per document kind: the DocType, the formats this user may choose,
    their saved preference, whether it has gone stale, the effective format,
    and whether a choice is still required. Never returns template HTML or
    Jinja source — only identifiers and labels.
    """
    set_cors_headers("GET, OPTIONS")
    if frappe.local.request and frappe.local.request.method == "OPTIONS":
        return {}

    require_authenticated_user()
    return {"documents": {kind: _resolve(kind) for kind in PRINTABLE_DOCUMENTS}}


def _validate_choice(kind: str, value: object, field: str) -> str | None:
    """A chosen format must be one this user may actually use.

    Re-checked here rather than trusted from the GET: the list the client is
    holding may be minutes old, and permissions may have changed since.
    """
    if value is None or str(value).strip() == "":
        return None
    name = str(value).strip()
    if name not in _policy_formats(kind):
        # Deliberately identical whether the format does not exist, is
        # disabled, belongs to another DocType, or is not readable — telling a
        # caller which would map out the catalogue.
        raise FieldValidationError(_("That print format is not available."), field=field)
    return name


@frappe.whitelist(allow_guest=True, methods=["POST"])
@mobile_api
def update_print_settings(
    invoice_format: str | None = None,
    payment_format: str | None = None,
    client_request_id: str | None = None,
):
    """POST mobile_endpoints.api.printing.update_print_settings

    The user is always `frappe.session.user`; there is no parameter for it, so
    one user cannot write another's preference.

    Both values are validated before either is written, so a request naming one
    good and one bad format changes nothing — a partial save would leave the
    user with a state they never asked for.
    """
    set_cors_headers("POST, OPTIONS")
    if frappe.local.request and frappe.local.request.method == "OPTIONS":
        return {}

    require_authenticated_user()

    invoice_choice = _validate_choice("invoice", invoice_format, "invoice_format")
    payment_choice = _validate_choice("payment", payment_format, "payment_format")

    def _apply():
        for kind, choice in (("invoice", invoice_choice), ("payment", payment_choice)):
            key = PREFERENCE_KEYS[kind]
            if choice is None:
                # An explicit empty value clears the preference, returning the
                # user to the fallback policy.
                frappe.defaults.clear_user_default(key)
            else:
                frappe.defaults.set_user_default(key, choice)
        return None, {"documents": {kind: _resolve(kind) for kind in PRINTABLE_DOCUMENTS}}

    return run_idempotent(
        client_request_id,
        IDEMPOTENCY_SCOPE,
        {"invoice_format": invoice_choice, "payment_format": payment_choice},
        _apply,
    )


# --- binary rendering --------------------------------------------------------
#
# This endpoint is the documented exception to the Phase 02 success envelope:
# a success is `application/pdf` bytes, not JSON. Wrapping a PDF in base64
# inside JSON would inflate it by a third and force the whole document through
# the browser's string heap for no benefit.
#
# Its FAILURES stay structured and redacted, so a client can tell "no
# permission" from "generation failed" without ever receiving a traceback.


def _safe_filename(kind: str, name: str) -> str:
    """A filename safe to put in a header.

    Reduced to a conservative set rather than escaped: a document name can
    contain characters that would let a crafted value break out of the
    Content-Disposition header.
    """
    allowed = []
    for char in str(name):
        allowed.append(char if (char.isalnum() or char in "-_") else "-")
    stem = "".join(allowed).strip("-") or kind
    return f"{stem[:80]}.pdf"


def _pdf_error(code: str, message: str, http_status: int) -> dict:
    """A structured failure for an endpoint whose success is binary."""
    frappe.local.response["http_status_code"] = http_status
    frappe.local.response["type"] = "json"
    return {"success": False, "error": {"code": code, "message": message}}


@frappe.whitelist(allow_guest=True, methods=["POST"])
def render_document_pdf(document_kind: str | None = None, name: str | None = None):
    """POST mobile_endpoints.api.printing.render_document_pdf

    Renders one of the two printable documents using **the caller's own
    effective print format**. The print format is deliberately not a parameter:
    a client that can name one at print time can render any format it can
    guess, which is precisely the choice this feature moved into settings.

    Success: `application/pdf` bytes, `no-store`, `nosniff`, sanitized
    filename. Failure: structured JSON, no traceback.
    """
    set_cors_headers("POST, OPTIONS")
    if frappe.local.request and frappe.local.request.method == "OPTIONS":
        return {}

    try:
        require_authenticated_user()
    except Exception:
        return _pdf_error("not_authenticated", _("Please sign in again."), 401)

    try:
        kind = _require_kind(document_kind)
    except FieldValidationError:
        return _pdf_error("validation_error", _("Unsupported document."), 422)

    doc_name = (str(name).strip() if name else "")
    if not doc_name:
        return _pdf_error("validation_error", _("Missing document name."), 422)

    doctype = PRINTABLE_DOCUMENTS[kind]

    # Read permission on the DOCUMENT, not merely the DocType: a user with
    # list access but no access to this record must not be able to print it.
    if not frappe.has_permission(doctype, "read", doc=doc_name):
        # Same answer for "does not exist" and "not yours": distinguishing them
        # confirms the existence of records a caller cannot see.
        return _pdf_error("not_permitted", _("That document is not available."), 403)

    resolved = _resolve(kind)
    print_format = resolved["effective"]
    if not print_format:
        return _pdf_error(
            "no_print_format",
            _("Choose a print format in settings before printing."),
            409,
        )

    try:
        # In memory. No `File` record, no file URL, nothing to clean up later
        # and nothing that outlives the request.
        content = frappe.get_print(
            doctype,
            doc_name,
            print_format=print_format,
            as_pdf=True,
        )
    except Exception:
        # The generator's own message can carry template internals and file
        # paths, so none of it is forwarded.
        frappe.log_error(
            title="mobile_endpoints:render_document_pdf",
            message=f"kind={kind} format={print_format}",
        )
        return _pdf_error("render_failed", _("The document could not be prepared."), 502)

    if not content:
        return _pdf_error("render_failed", _("The document could not be prepared."), 502)
    if len(content) > MAX_PDF_BYTES:
        return _pdf_error("too_large", _("That document is too large to print."), 413)

    frappe.local.response["type"] = "download"
    frappe.local.response["filename"] = _safe_filename(kind, doc_name)
    frappe.local.response["filecontent"] = content
    frappe.local.response["content_type"] = "application/pdf"
    # Marks this response for `apply_print_response_headers`. A flag rather
    # than a path match: the hook then cannot be fooled by another route that
    # happens to look similar, and it stays correct if the route is renamed.
    frappe.local.pamper_print_response = True

    # NOTE ON SECURITY HEADERS, verified against Frappe 15.86.0:
    # `as_raw()` in frappe/utils/response.py builds a fresh werkzeug Response
    # and sets only the mimetype and Content-Disposition. It does NOT merge
    # `frappe.local.response["headers"]`, so `Cache-Control: no-store` and
    # `X-Content-Type-Options: nosniff` cannot be attached here — setting them
    # would look like protection without being any.
    #
    # `after_request` IS a viable path in this version: `frappe/app.py:147`
    # calls `run_after_request_hooks(request, response)` with the real
    # werkzeug response, before `process_response`. So the headers are applied
    # there — see `apply_print_response_headers` below — scoped to this
    # endpoint by the flag set above, never site-wide.
    return


def apply_print_response_headers(response=None, request=None):
    """`after_request` hook: security headers for the PDF response only.

    Registered in `hooks.py`. Runs for every request, so it does nothing unless
    this request actually produced a PDF — a blanket header change would affect
    the whole site, which is not this feature's business.

    `Content-Security-Policy: sandbox` matters most: it stops a PDF rendered
    inline from running script or navigating, which is the attack a
    same-origin document viewer otherwise invites.
    """
    if response is None:
        return
    if not getattr(frappe.local, "pamper_print_response", False):
        return
    try:
        response.headers["Cache-Control"] = "no-store, private"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "sandbox"
    except Exception:
        # A header failure must never turn a delivered PDF into an error.
        frappe.logger().warning("could not set print response headers")
