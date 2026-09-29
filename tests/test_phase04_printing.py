"""Phase 04 — print policy, preferences and PDF rendering.

Standalone: no bench, no database. Frappe is replaced by a fake whose behaviour
mirrors the parts this module actually relies on — policy rows, Print Format
metadata, roles, user defaults and `get_print`. PDF generation itself is stubbed;
a real render belongs in the bench suite.

The rule under test throughout: **deny by default**. A user may print with a
format only because a rule says so, and the rule is re-checked every time.
"""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace

import pytest

# The module imports `frappe` at import time, so a stand-in must exist first.
if "frappe" not in sys.modules:  # pragma: no cover - import plumbing
    frappe_stub = types.ModuleType("frappe")
    frappe_stub.whitelist = lambda **kwargs: (lambda fn: fn)
    frappe_stub._ = lambda message: message
    frappe_stub.conf = {}
    frappe_stub.local = SimpleNamespace(response={}, request=None, message_log=[])
    frappe_stub.session = SimpleNamespace(user="Guest")
    frappe_stub.ValidationError = type("ValidationError", (Exception,), {})
    frappe_stub.PermissionError = type("PermissionError", (Exception,), {})
    frappe_stub.AuthenticationError = type("AuthenticationError", (Exception,), {})
    frappe_stub.DoesNotExistError = type("DoesNotExistError", (Exception,), {})
    frappe_stub.throw = lambda message, exc=Exception, title=None: (_ for _ in ()).throw(
        exc(message)
    )
    frappe_stub.generate_hash = lambda length=10: "0" * int(length or 10)
    frappe_stub.get_traceback = lambda: "traceback"
    frappe_stub.log_error = lambda *a, **k: None
    frappe_stub.db = SimpleNamespace(rollback=lambda: None, commit=lambda: None)

    frappe_utils = types.ModuleType("frappe.utils")
    frappe_utils.cint = lambda value: int(value or 0)
    frappe_utils.cstr = lambda value: "" if value is None else str(value)
    frappe_utils.get_url = lambda: "https://erp.example.com"
    frappe_utils.now_datetime = lambda: None
    frappe_stub.utils = frappe_utils

    document_mod = types.ModuleType("frappe.model.document")
    document_mod.Document = type("Document", (), {})
    model_mod = types.ModuleType("frappe.model")
    model_mod.document = document_mod
    frappe_stub.model = model_mod

    sys.modules["frappe"] = frappe_stub
    sys.modules["frappe.utils"] = frappe_utils
    sys.modules["frappe.model"] = model_mod
    sys.modules["frappe.model.document"] = document_mod

# Whoever installed the base `frappe` stub first wins — the Phase 02 suite
# installs one without `frappe.model`, and pytest may collect it before this
# file. The controller imports `frappe.model.document`, so the submodule is
# topped up unconditionally rather than only when this file creates the stub.
if "frappe.model.document" not in sys.modules:  # pragma: no cover - plumbing
    _frappe = sys.modules["frappe"]
    _document_mod = types.ModuleType("frappe.model.document")
    _document_mod.Document = type("Document", (), {})
    _model_mod = types.ModuleType("frappe.model")
    _model_mod.document = _document_mod
    _frappe.model = _model_mod
    sys.modules["frappe.model"] = _model_mod
    sys.modules["frappe.model.document"] = _document_mod

from mobile_endpoints.api import printing  # noqa: E402
from mobile_endpoints.api._envelope import FieldValidationError  # noqa: E402

INVOICE_DT = "Invoice Form"
PAYMENT_DT = "Collection and Payment"

USER_A = "a@example.com"
USER_B = "b@example.com"


class FakeDB:
    """Just enough of `frappe.db` for the policy and format lookups."""

    def __init__(self, policy_rows, formats, doctype_defaults=None):
        self.policy_rows = policy_rows
        self.formats = formats
        self.doctype_defaults = doctype_defaults or {}

    def get_all(self, doctype, filters=None, fields=None, order_by=None, **kwargs):
        filters = filters or {}
        if doctype == printing.POLICY_DOCTYPE:
            rows = []
            for row in self.policy_rows:
                if not self._matches(row, filters):
                    continue
                rows.append({"print_format": row["print_format"]})
            return rows
        if doctype == "Print Format":
            wanted = filters.get("name", ["in", []])[1]
            rows = []
            for name in wanted:
                meta = self.formats.get(name)
                if not meta:
                    continue
                if meta.get("doc_type") != filters.get("doc_type"):
                    continue
                if meta.get("disabled"):
                    continue
                if meta.get("raw_printing"):
                    continue
                rows.append({"name": name})
            return sorted(rows, key=lambda r: r["name"])
        return []

    @staticmethod
    def _matches(row, filters):
        for key, expected in filters.items():
            actual = row.get(key)
            if isinstance(expected, list) and expected and expected[0] == "in":
                if actual not in expected[1]:
                    return False
            elif actual != expected:
                return False
        return True

    def get_value(self, doctype, name, fieldname, as_dict=False):
        if doctype == "DocType":
            return self.doctype_defaults.get(name)
        return None


def harness(
    monkeypatch,
    *,
    user=USER_A,
    roles=(),
    policy_rows=(),
    formats=None,
    doctype_defaults=None,
    saved=None,
    can_read_doc=True,
    pdf=b"%PDF-1.4 fake",
    pdf_raises=False,
):
    """A frappe stand-in wired to one scenario."""
    defaults_store = dict(saved or {})
    state = SimpleNamespace(defaults=defaults_store, idempotent_calls=[], printed=[])

    runtime = SimpleNamespace()
    runtime._ = lambda message: message
    runtime.local = SimpleNamespace(response={}, request=None, message_log=[])
    runtime.session = SimpleNamespace(user=user)
    runtime.get_roles = lambda _user=None: list(roles)
    runtime.db = FakeDB(list(policy_rows), formats or {}, doctype_defaults)
    runtime.has_permission = lambda *a, **k: can_read_doc
    runtime.log_error = lambda *a, **k: None
    runtime.logger = lambda: SimpleNamespace(warning=lambda *a, **k: None)
    runtime.ValidationError = Exception
    runtime.PermissionError = type("PermissionError", (Exception,), {})

    def _get_print(doctype, name, print_format=None, as_pdf=False):
        if pdf_raises:
            raise RuntimeError("wkhtmltopdf exploded with /private/path in the message")
        state.printed.append({"doctype": doctype, "name": name, "print_format": print_format})
        return pdf

    runtime.get_print = _get_print
    runtime.defaults = SimpleNamespace(
        get_user_default=lambda key: defaults_store.get(key, ""),
        set_user_default=lambda key, value: defaults_store.__setitem__(key, value),
        clear_user_default=lambda key: defaults_store.pop(key, None),
    )

    monkeypatch.setattr(printing, "frappe", runtime)
    monkeypatch.setattr(printing, "require_authenticated_user", lambda: user)
    monkeypatch.setattr(printing, "set_cors_headers", lambda methods: None)

    def _run_idempotent(client_request_id, scope, payload, fn):
        state.idempotent_calls.append((client_request_id, scope, payload))
        _name, response = fn()
        return response

    monkeypatch.setattr(printing, "run_idempotent", _run_idempotent)
    return state


FORMATS = {
    "Invoice A": {"doc_type": INVOICE_DT, "disabled": 0, "raw_printing": 0},
    "Invoice B": {"doc_type": INVOICE_DT, "disabled": 0, "raw_printing": 0},
    "Invoice Disabled": {"doc_type": INVOICE_DT, "disabled": 1, "raw_printing": 0},
    "Invoice Raw": {"doc_type": INVOICE_DT, "disabled": 0, "raw_printing": 1},
    "Payment A": {"doc_type": PAYMENT_DT, "disabled": 0, "raw_printing": 0},
    "Wrong Doctype": {"doc_type": "Sales Invoice", "disabled": 0, "raw_printing": 0},
}


def _is_field_error(result, field):
    """`@mobile_api` converts FieldValidationError into the Phase 02 envelope,
    so that — not a raised exception — is what a caller actually receives."""
    return (
        result.get("success") is False
        and result.get("error", {}).get("code") == "validation_error"
        and field in (result.get("error", {}).get("fields") or {})
    )


def rule(principal_type, principal, kind, fmt, enabled=1):
    return {
        "principal_type": principal_type,
        "user": principal if principal_type == "User" else None,
        "role": principal if principal_type == "Role" else None,
        "document_kind": kind,
        "print_format": fmt,
        "enabled": enabled,
    }


# --- the allowlist -----------------------------------------------------------


def test_only_two_documents_are_printable():
    assert printing.PRINTABLE_DOCUMENTS == {
        "invoice": INVOICE_DT,
        "payment": PAYMENT_DT,
    }


@pytest.mark.parametrize("bad", ["Sales Invoice", "", None, "user", "../invoice", "invoices"])
def test_any_other_document_kind_is_refused(monkeypatch, bad):
    harness(monkeypatch)
    with pytest.raises(FieldValidationError):
        printing._require_kind(bad)


def test_document_kind_is_case_insensitive_after_trimming(monkeypatch):
    harness(monkeypatch)
    assert printing._require_kind(" Invoice ") == "invoice"


# --- policy resolution -------------------------------------------------------


def test_a_direct_user_rule_grants_the_format(monkeypatch):
    harness(monkeypatch, policy_rows=[rule("User", USER_A, "invoice", "Invoice A")], formats=FORMATS)
    assert printing._policy_formats("invoice") == ["Invoice A"]


def test_a_role_rule_grants_the_format(monkeypatch):
    harness(
        monkeypatch,
        roles=("Accounts User",),
        policy_rows=[rule("Role", "Accounts User", "invoice", "Invoice B")],
        formats=FORMATS,
    )
    assert printing._policy_formats("invoice") == ["Invoice B"]


def test_user_and_role_rules_are_unioned_and_deduplicated(monkeypatch):
    harness(
        monkeypatch,
        roles=("Accounts User",),
        policy_rows=[
            rule("User", USER_A, "invoice", "Invoice A"),
            rule("Role", "Accounts User", "invoice", "Invoice B"),
            # The same format from both sides must appear once.
            rule("Role", "Accounts User", "invoice", "Invoice A"),
        ],
        formats=FORMATS,
    )
    assert printing._policy_formats("invoice") == ["Invoice A", "Invoice B"]


def test_no_rule_means_no_formats(monkeypatch):
    # Deny by default: the catalogue is never revealed as a fallback.
    harness(monkeypatch, policy_rows=[], formats=FORMATS)
    assert printing._policy_formats("invoice") == []


def test_a_disabled_rule_does_not_count(monkeypatch):
    harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A", enabled=0)],
        formats=FORMATS,
    )
    assert printing._policy_formats("invoice") == []


def test_one_user_cannot_use_another_users_rule(monkeypatch):
    harness(
        monkeypatch,
        user=USER_B,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
    )
    assert printing._policy_formats("invoice") == []


def test_losing_the_role_removes_the_format_immediately(monkeypatch):
    # Same rules, but the user no longer holds the role.
    harness(
        monkeypatch,
        roles=(),
        policy_rows=[rule("Role", "Accounts User", "invoice", "Invoice B")],
        formats=FORMATS,
    )
    assert printing._policy_formats("invoice") == []


def test_a_rule_naming_a_disabled_format_grants_nothing(monkeypatch):
    harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice Disabled")],
        formats=FORMATS,
    )
    assert printing._policy_formats("invoice") == []


def test_a_rule_naming_a_raw_printing_format_grants_nothing(monkeypatch):
    harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice Raw")],
        formats=FORMATS,
    )
    assert printing._policy_formats("invoice") == []


def test_a_rule_whose_format_belongs_to_another_doctype_grants_nothing(monkeypatch):
    # A rule can outlive a format being rebound; the check is re-run at read.
    harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Wrong Doctype")],
        formats=FORMATS,
    )
    assert printing._policy_formats("invoice") == []


def test_invoice_and_payment_policies_are_separate(monkeypatch):
    harness(
        monkeypatch,
        policy_rows=[
            rule("User", USER_A, "invoice", "Invoice A"),
            rule("User", USER_A, "payment", "Payment A"),
        ],
        formats=FORMATS,
    )
    assert printing._policy_formats("invoice") == ["Invoice A"]
    assert printing._policy_formats("payment") == ["Payment A"]


# --- preference resolution ---------------------------------------------------


def test_saved_preference_wins_when_still_allowed(monkeypatch):
    harness(
        monkeypatch,
        policy_rows=[
            rule("User", USER_A, "invoice", "Invoice A"),
            rule("User", USER_A, "invoice", "Invoice B"),
        ],
        formats=FORMATS,
        saved={printing.PREFERENCE_KEYS["invoice"]: "Invoice B"},
    )
    resolved = printing._resolve("invoice")
    assert resolved["effective"] == "Invoice B"
    assert resolved["saved"] == "Invoice B"
    assert resolved["saved_is_stale"] is False
    assert resolved["needs_selection"] is False


def test_doctype_default_is_used_only_when_allowed(monkeypatch):
    harness(
        monkeypatch,
        policy_rows=[
            rule("User", USER_A, "invoice", "Invoice A"),
            rule("User", USER_A, "invoice", "Invoice B"),
        ],
        formats=FORMATS,
        doctype_defaults={INVOICE_DT: "Invoice B"},
    )
    assert printing._resolve("invoice")["effective"] == "Invoice B"


def test_a_doctype_default_outside_the_policy_is_ignored(monkeypatch):
    harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
        # The site default is a format this user has no rule for.
        doctype_defaults={INVOICE_DT: "Invoice B"},
    )
    # Falls through to "the only allowed one", never to the disallowed default.
    assert printing._resolve("invoice")["effective"] == "Invoice A"


def test_the_sole_allowed_format_is_used(monkeypatch):
    harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
    )
    resolved = printing._resolve("invoice")
    assert resolved["effective"] == "Invoice A"
    assert resolved["needs_selection"] is False


def test_ambiguous_choice_requires_selection(monkeypatch):
    harness(
        monkeypatch,
        policy_rows=[
            rule("User", USER_A, "invoice", "Invoice A"),
            rule("User", USER_A, "invoice", "Invoice B"),
        ],
        formats=FORMATS,
    )
    resolved = printing._resolve("invoice")
    assert resolved["effective"] is None
    assert resolved["needs_selection"] is True


def test_no_policy_means_no_formats_and_a_required_selection(monkeypatch):
    harness(monkeypatch, policy_rows=[], formats=FORMATS)
    resolved = printing._resolve("invoice")
    assert resolved["formats"] == []
    assert resolved["effective"] is None
    assert resolved["needs_selection"] is True


def test_a_saved_format_that_lost_its_rule_is_reported_stale_and_not_used(monkeypatch):
    harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
        saved={printing.PREFERENCE_KEYS["invoice"]: "Invoice B"},
    )
    resolved = printing._resolve("invoice")
    assert resolved["saved"] == "Invoice B"
    assert resolved["saved_is_stale"] is True
    # It falls back to the one it MAY use, never to the stale choice.
    assert resolved["effective"] == "Invoice A"


def test_reading_settings_never_writes_a_preference(monkeypatch):
    state = harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
    )
    printing.get_print_settings()
    # A GET that saved a fallback would make the stored preference depend on
    # when the user happened to open the screen.
    assert state.defaults == {}


def test_settings_expose_formats_and_never_template_source(monkeypatch):
    harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
    )
    payload = printing.get_print_settings()
    invoice = payload["documents"]["invoice"]
    assert invoice["doctype"] == INVOICE_DT
    assert invoice["formats"] == [{"id": "Invoice A", "label": "Invoice A"}]
    assert set(invoice) == {
        "doctype",
        "formats",
        "saved",
        "saved_is_stale",
        "effective",
        "needs_selection",
    }
    rendered = repr(payload)
    for leak in ("html", "jinja", "css", "raw_commands"):
        assert leak not in rendered.lower()


# --- saving ------------------------------------------------------------------


def test_saving_an_allowed_format_persists_it(monkeypatch):
    state = harness(
        monkeypatch,
        policy_rows=[
            rule("User", USER_A, "invoice", "Invoice A"),
            rule("User", USER_A, "payment", "Payment A"),
        ],
        formats=FORMATS,
    )
    printing.update_print_settings(
        invoice_format="Invoice A", payment_format="Payment A", client_request_id="req-1"
    )
    assert state.defaults[printing.PREFERENCE_KEYS["invoice"]] == "Invoice A"
    assert state.defaults[printing.PREFERENCE_KEYS["payment"]] == "Payment A"


def test_saving_a_format_without_a_rule_is_refused(monkeypatch):
    harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
    )
    result = printing.update_print_settings(invoice_format="Invoice B", client_request_id="req-1")
    assert _is_field_error(result, "invoice_format")


def test_saving_another_users_format_is_refused(monkeypatch):
    harness(
        monkeypatch,
        user=USER_B,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
    )
    result = printing.update_print_settings(invoice_format="Invoice A", client_request_id="req-1")
    assert _is_field_error(result, "invoice_format")


def test_one_bad_value_saves_nothing_at_all(monkeypatch):
    state = harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
    )
    result = printing.update_print_settings(
        invoice_format="Invoice A",   # valid
        payment_format="Payment A",   # no rule for this user
        client_request_id="req-1",
    )
    assert _is_field_error(result, "payment_format")
    # No partial save: the good half must not land either.
    assert state.defaults == {}


def test_an_empty_value_clears_the_preference(monkeypatch):
    state = harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
        saved={printing.PREFERENCE_KEYS["invoice"]: "Invoice A"},
    )
    printing.update_print_settings(invoice_format="", client_request_id="req-1")
    assert printing.PREFERENCE_KEYS["invoice"] not in state.defaults


def test_the_update_goes_through_the_idempotency_ledger(monkeypatch):
    state = harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
    )
    printing.update_print_settings(invoice_format="Invoice A", client_request_id="req-9")
    assert len(state.idempotent_calls) == 1
    request_id, scope, payload = state.idempotent_calls[0]
    assert request_id == "req-9"
    assert scope == printing.IDEMPOTENCY_SCOPE
    # The payload is the validated choice, so a replay hashes identically.
    assert payload == {"invoice_format": "Invoice A", "payment_format": None}


def test_a_replay_with_the_same_key_hashes_the_same_payload(monkeypatch):
    state = harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
    )
    for _ in range(2):
        printing.update_print_settings(invoice_format="Invoice A", client_request_id="req-9")
    assert state.idempotent_calls[0] == state.idempotent_calls[1]


def test_the_update_returns_confirmed_server_state(monkeypatch):
    harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
    )
    result = printing.update_print_settings(invoice_format="Invoice A", client_request_id="r")
    assert result["documents"]["invoice"]["effective"] == "Invoice A"


def test_no_user_parameter_exists_to_target_someone_else(monkeypatch):
    import inspect

    signature = inspect.signature(printing.update_print_settings)
    assert "user" not in signature.parameters
    assert "owner" not in signature.parameters


# --- rendering ---------------------------------------------------------------


def test_rendering_uses_the_resolved_format_and_never_a_parameter(monkeypatch):
    import inspect

    state = harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
    )
    # The signature itself refuses a client-chosen format.
    assert "print_format" not in inspect.signature(printing.render_document_pdf).parameters

    printing.render_document_pdf(document_kind="invoice", name="INV-1")
    assert state.printed == [
        {"doctype": INVOICE_DT, "name": "INV-1", "print_format": "Invoice A"}
    ]


def test_rendering_returns_binary_pdf_not_json(monkeypatch):
    harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
    )
    printing.render_document_pdf(document_kind="invoice", name="INV-1")
    response = printing.frappe.local.response
    assert response["type"] == "download"
    assert response["content_type"] == "application/pdf"
    assert response["filecontent"].startswith(b"%PDF")
    assert response["filename"].endswith(".pdf")


def test_rendering_creates_no_file_record(monkeypatch):
    runtime_state = harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
    )
    printing.render_document_pdf(document_kind="invoice", name="INV-1")
    # `save_file` is not even imported by this module.
    assert not hasattr(printing, "save_file")
    assert "file_url" not in printing.frappe.local.response
    assert runtime_state.printed


def test_rendering_marks_the_response_for_the_header_hook(monkeypatch):
    harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
    )
    printing.render_document_pdf(document_kind="invoice", name="INV-1")
    assert getattr(printing.frappe.local, "pamper_print_response", False) is True


def test_a_document_the_user_cannot_read_is_refused(monkeypatch):
    state = harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
        can_read_doc=False,
    )
    result = printing.render_document_pdf(document_kind="invoice", name="INV-1")
    assert result["success"] is False
    assert result["error"]["code"] == "not_permitted"
    assert printing.frappe.local.response["http_status_code"] == 403
    # Nothing was rendered.
    assert state.printed == []


def test_losing_the_rule_blocks_rendering_even_with_a_saved_choice(monkeypatch):
    state = harness(
        monkeypatch,
        policy_rows=[],  # the rule was deleted
        formats=FORMATS,
        saved={printing.PREFERENCE_KEYS["invoice"]: "Invoice A"},
    )
    result = printing.render_document_pdf(document_kind="invoice", name="INV-1")
    assert result["error"]["code"] == "no_print_format"
    assert state.printed == []


def test_an_unknown_document_kind_is_refused_before_anything_else(monkeypatch):
    state = harness(monkeypatch, policy_rows=[], formats=FORMATS)
    result = printing.render_document_pdf(document_kind="Sales Invoice", name="X")
    assert result["error"]["code"] == "validation_error"
    assert state.printed == []


def test_a_generation_failure_is_redacted(monkeypatch):
    harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
        pdf_raises=True,
    )
    result = printing.render_document_pdf(document_kind="invoice", name="INV-1")
    rendered = repr(result)
    assert result["error"]["code"] == "render_failed"
    # The generator's message named a private path; none of it crosses over.
    assert "wkhtmltopdf" not in rendered
    assert "/private/path" not in rendered
    assert "traceback" not in rendered.lower()


def test_an_oversized_pdf_is_refused(monkeypatch):
    harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
        pdf=b"%PDF" + b"x" * (printing.MAX_PDF_BYTES + 1),
    )
    result = printing.render_document_pdf(document_kind="invoice", name="INV-1")
    assert result["error"]["code"] == "too_large"


def test_the_filename_cannot_break_out_of_a_header(monkeypatch):
    harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "invoice", "Invoice A")],
        formats=FORMATS,
    )
    printing.render_document_pdf(
        document_kind="invoice", name='INV-1"; attack=1\r\nX-Evil: yes'
    )
    filename = printing.frappe.local.response["filename"]
    for char in ('"', "\r", "\n", ";", " "):
        assert char not in filename
    assert filename.endswith(".pdf")


def test_payment_documents_render_with_their_own_format(monkeypatch):
    state = harness(
        monkeypatch,
        policy_rows=[rule("User", USER_A, "payment", "Payment A")],
        formats=FORMATS,
    )
    printing.render_document_pdf(document_kind="payment", name="PMT-1")
    assert state.printed == [
        {"doctype": PAYMENT_DT, "name": "PMT-1", "print_format": "Payment A"}
    ]


# --- the header hook ---------------------------------------------------------


def test_the_hook_sets_headers_only_for_a_print_response(monkeypatch):
    harness(monkeypatch)

    class Response:
        def __init__(self):
            self.headers = {}

    # Not a print response: untouched, because this hook runs site-wide.
    other = Response()
    printing.frappe.local.pamper_print_response = False
    printing.apply_print_response_headers(response=other)
    assert other.headers == {}

    ours = Response()
    printing.frappe.local.pamper_print_response = True
    printing.apply_print_response_headers(response=ours)
    assert ours.headers["Cache-Control"] == "no-store, private"
    assert ours.headers["X-Content-Type-Options"] == "nosniff"
    assert ours.headers["Content-Security-Policy"] == "sandbox"
    assert ours.headers["Pragma"] == "no-cache"


def test_the_hook_survives_a_missing_response(monkeypatch):
    harness(monkeypatch)
    printing.apply_print_response_headers(response=None)  # must not raise


# --- no forbidden primitives -------------------------------------------------


def test_the_module_never_bypasses_permissions():
    import pathlib

    source = pathlib.Path(printing.__file__).read_text()
    # Strip the module docstring and comments: both discuss these primitives by
    # name in order to explain why they are not used.
    body = source.split('"""', 2)[-1]
    code = "\n".join(
        line for line in body.splitlines() if not line.strip().startswith("#")
    )
    assert "ignore_permissions" not in code
    # `frappe.get_list` is deliberately NOT used for Print Format: it requires
    # `read`, which ordinary users do not have.
    assert "get_list" not in code
    assert "save_file" not in code


# --- naming lifecycle --------------------------------------------------------
#
# These check the SHAPE of the fix, not the sequence. A standalone test cannot
# prove Frappe's real ordering — it does not run `Document.insert()` — so the
# proof that `before_naming` fires before the `field:` autoname resolves lives
# in the bench suite (`TestPrintPolicyNamingLifecycle`). What is worth pinning
# here is that the hook exists, that it produces the key, and that one helper
# remains the single source of truth.


def _policy_controller():
    from mobile_endpoints.mobile_endpoints.doctype.mobile_print_format_access import (
        mobile_print_format_access as module,
    )

    return module


def _rule_doc(**overrides):
    """A controller instance with fields set, without Frappe's Document base."""
    module = _policy_controller()
    doc = module.MobilePrintFormatAccess.__new__(module.MobilePrintFormatAccess)
    doc.principal_type = overrides.get("principal_type", "User")
    doc.user = overrides.get("user", USER_A)
    doc.role = overrides.get("role")
    doc.document_kind = overrides.get("document_kind", "invoice")
    doc.print_format = overrides.get("print_format", "Invoice A")
    doc.composite_key = overrides.get("composite_key")
    return doc


def test_the_controller_exposes_a_before_naming_hook():
    module = _policy_controller()
    # The autoname is `field:composite_key`, which Frappe resolves before
    # validate() — so the value has to be built in a pre-naming hook.
    assert hasattr(module.MobilePrintFormatAccess, "before_naming")


def test_before_naming_populates_the_key_without_any_client_value():
    doc = _rule_doc(composite_key=None)
    doc.before_naming()
    assert doc.composite_key == "User::a@example.com::invoice::Invoice A"


def test_validate_recomputes_a_forged_key(monkeypatch):
    module = _policy_controller()
    monkeypatch.setattr(
        module,
        "frappe",
        SimpleNamespace(
            _=lambda m: m,
            throw=lambda msg: (_ for _ in ()).throw(AssertionError(msg)),
            db=SimpleNamespace(
                get_value=lambda *a, **k: SimpleNamespace(
                    name="Invoice A", doc_type=INVOICE_DT, disabled=0, raw_printing=0
                )
            ),
        ),
    )
    doc = _rule_doc(composite_key="User::someone-else@example.com::invoice::Anything")
    doc.validate()
    # The submitted value is discarded rather than trusted.
    assert doc.composite_key == "User::a@example.com::invoice::Invoice A"


def test_the_key_is_built_in_exactly_one_place():
    """No duplicated hashing logic between the two hooks."""
    import inspect

    module = _policy_controller()
    source = inspect.getsource(module.MobilePrintFormatAccess)
    # One definition, called from both hooks.
    assert source.count("def _set_composite_key") == 1
    assert source.count("self._set_composite_key()") == 2
    # The join lives only inside the helper.
    assert source.count('"::".join') == 1


def test_a_role_rule_keys_on_the_role_and_clears_the_user():
    doc = _rule_doc(principal_type="Role", role="Accounts User", user=USER_A)
    doc.before_naming()
    assert doc.composite_key == "Role::Accounts User::invoice::Invoice A"
    assert doc.user is None


class _Refused(Exception):
    """Stands in for `frappe.throw`, which raises rather than returns."""


def _refusing_frappe(monkeypatch):
    module = _policy_controller()
    monkeypatch.setattr(
        module,
        "frappe",
        SimpleNamespace(
            _=lambda m: m,
            throw=lambda msg: (_ for _ in ()).throw(_Refused(msg)),
        ),
    )
    return module


def test_before_naming_refuses_a_missing_principal(monkeypatch):
    _refusing_frappe(monkeypatch)
    with pytest.raises(_Refused, match="user"):
        _rule_doc(user=None).before_naming()


def test_before_naming_refuses_an_unknown_document_kind(monkeypatch):
    _refusing_frappe(monkeypatch)
    with pytest.raises(_Refused, match="Document kind"):
        _rule_doc(document_kind="sales_invoice").before_naming()


def test_before_naming_refuses_an_unknown_principal_type(monkeypatch):
    _refusing_frappe(monkeypatch)
    with pytest.raises(_Refused, match="Principal type"):
        _rule_doc(principal_type="Group").before_naming()
