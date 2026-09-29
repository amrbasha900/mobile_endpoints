"""One rule granting one principal the use of one print format.

## Why this exists rather than Frappe's own permissions

`Print Format` in Frappe 15.86.0 grants `read` to System Manager only; an
ordinary Desk User gets `select`. There is no per-record read isolation to
inherit, and granting `read` on `Print Format` globally would let every user
enumerate every format on the site — a wider change than this feature needs,
made to the platform rather than to the app.

So authorisation for *which formats a user may print with* is owned by this
app. It is deny-by-default: no matching rule means no formats, not all of them.

## No implicit administrator bypass

A System Manager can manage these rules from Desk but still needs an explicit
rule to use a format in the app. An automatic bypass would mean the person most
likely to be testing the feature is the one person who never exercises the real
path.
"""

import frappe
from frappe import _
from frappe.model.document import Document

# The same allowlist the API enforces, restated here so a rule cannot be
# created for a document kind the app does not print.
DOCUMENT_KIND_DOCTYPES = {
    "invoice": "Invoice Form",
    "payment": "Collection and Payment",
}


class MobilePrintFormatAccess(Document):
    def validate(self):
        self._validate_principal()
        self._validate_document_kind()
        self._validate_print_format()
        self._set_composite_key()

    def _validate_principal(self):
        """Exactly one principal, matching the declared type.

        Both filled would be ambiguous — which one grants the access? — and
        neither would grant it to nobody while looking like a real rule.
        """
        if self.principal_type == "User":
            if not self.user:
                frappe.throw(_("Select the user this rule applies to."))
            # Cleared rather than rejected: switching the type in the UI leaves
            # the other field populated, and silently honouring a stale value
            # would be worse than tidying it.
            self.role = None
        elif self.principal_type == "Role":
            if not self.role:
                frappe.throw(_("Select the role this rule applies to."))
            self.user = None
        else:
            frappe.throw(_("Principal type must be User or Role."))

    def _validate_document_kind(self):
        if self.document_kind not in DOCUMENT_KIND_DOCTYPES:
            frappe.throw(
                _("Document kind must be one of: {0}").format(
                    ", ".join(sorted(DOCUMENT_KIND_DOCTYPES))
                )
            )

    def _validate_print_format(self):
        """The format must exist, be usable, and belong to the right DocType.

        Checked at save so a broken rule cannot sit in the table waiting to
        fail at print time, when a user is watching.
        """
        row = frappe.db.get_value(
            "Print Format",
            self.print_format,
            ["name", "doc_type", "disabled", "raw_printing"],
            as_dict=True,
        )
        if not row:
            frappe.throw(_("That print format does not exist."))
        if row.disabled:
            frappe.throw(_("That print format is disabled."))
        if row.raw_printing:
            # Raw formats drive label printers and do not render to PDF.
            frappe.throw(_("Raw printing formats cannot be used for PDF output."))

        expected = DOCUMENT_KIND_DOCTYPES[self.document_kind]
        if row.doc_type != expected:
            frappe.throw(
                _("That print format belongs to {0}, not {1}.").format(row.doc_type, expected)
            )

    def _set_composite_key(self):
        """A stable, unique identity for the rule.

        Separators are chosen so no field value can forge another rule's key:
        `::` cannot appear in a User id, a Role name, a kind or a format name
        in a way that would collide, and the principal type is part of the key.
        """
        principal = self.user if self.principal_type == "User" else self.role
        self.composite_key = "::".join(
            [
                str(self.principal_type or ""),
                str(principal or ""),
                str(self.document_kind or ""),
                str(self.print_format or ""),
            ]
        )
