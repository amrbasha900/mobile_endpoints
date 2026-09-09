"""Reliability contract tests for the mobile API (Phase 02).

Run with:  bench --site <site> run-tests --app mobile_endpoints --module \
    mobile_endpoints.tests.test_reliability

NOTE: these require a Frappe bench + site with the `Invoice Form` and
`Collection and Payment` doctypes installed. They could not be executed in the
environment where this change was authored.
"""

import json
import uuid

import frappe
from frappe.tests.utils import FrappeTestCase

from mobile_endpoints.api import invoice as invoice_api
from mobile_endpoints.api._idempotency import DOCTYPE as LOG_DOCTYPE


def _invoice_body(client_request_id, qty=2, price=50):
	return {
		"client_request_id": client_request_id,
		"data": {
			"posting_date": frappe.utils.today(),
			"supplier": "_Test Supplier",
			"supplier_name": "_Test Supplier",
			"items": [
				{"item_code": "_Test Item", "item_name": "_Test Item", "qty": qty, "price": price},
			],
		},
	}


class TestIdempotentCreate(FrappeTestCase):
	def _post(self, body):
		frappe.local.request = frappe._dict(
			method="POST",
			get_data=lambda as_text=True: json.dumps(body),
		)
		frappe.form_dict = frappe._dict()
		return invoice_api.create_invoice_form()

	def test_replay_returns_same_document(self):
		key = str(uuid.uuid4())
		first = self._post(_invoice_body(key))
		self.assertTrue(first["success"])
		name = first["data"]["name"]

		before = frappe.db.count("Invoice Form")
		second = self._post(_invoice_body(key))
		after = frappe.db.count("Invoice Form")

		self.assertTrue(second["success"])
		self.assertEqual(second["data"]["name"], name)
		self.assertEqual(before, after, "replaying the same client_request_id created a second invoice")

	def test_same_key_different_payload_conflicts(self):
		key = str(uuid.uuid4())
		self._post(_invoice_body(key, qty=2))
		resp = self._post(_invoice_body(key, qty=999))
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "idempotency_conflict")
		self.assertEqual(frappe.local.response.get("http_status_code"), 409)

	def test_missing_key_still_creates(self):
		body = _invoice_body(None)
		body.pop("client_request_id", None)
		resp = self._post(body)
		self.assertTrue(resp["success"])
		self.assertNotIn(
			resp["data"]["name"],
			frappe.get_all(LOG_DOCTYPE, pluck="docname"),
			"a log row was written for a keyless request",
		)


class TestOptimisticConcurrency(FrappeTestCase):
	def test_stale_base_modified_returns_409_with_current_state(self):
		key = str(uuid.uuid4())
		frappe.local.request = frappe._dict(method="POST", get_data=lambda as_text=True: json.dumps(_invoice_body(key)))
		frappe.form_dict = frappe._dict()
		name = invoice_api.create_invoice_form()["data"]["name"]

		resp = invoice_api.update_invoice(
			name=name,
			data={"items": [{"item_code": "_Test Item", "qty": 3, "price": 10}]},
			base_modified="1999-01-01 00:00:00.000000",
		)
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "conflict")
		self.assertEqual(frappe.local.response.get("http_status_code"), 409)
		self.assertIn("items", resp["data"], "409 body must carry the current server state")

	def test_matching_base_modified_updates(self):
		key = str(uuid.uuid4())
		frappe.local.request = frappe._dict(method="POST", get_data=lambda as_text=True: json.dumps(_invoice_body(key)))
		frappe.form_dict = frappe._dict()
		created = invoice_api.create_invoice_form()["data"]
		resp = invoice_api.update_invoice(
			name=created["name"],
			data={"items": [{"item_code": "_Test Item", "qty": 3, "price": 10}]},
			base_modified=created["modified"],
		)
		self.assertTrue(resp["success"])
		self.assertEqual(resp["data"]["grand_total"], 30)


class TestEnvelope(FrappeTestCase):
	def test_permission_error_is_structured_403(self):
		frappe.set_user("Guest")
		try:
			resp = invoice_api.get_invoices()
		finally:
			frappe.set_user("Administrator")
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "permission_denied")
		self.assertEqual(frappe.local.response.get("http_status_code"), 403)

	def test_success_envelope_shape(self):
		resp = invoice_api.get_invoices(page=1, page_size=1)
		self.assertTrue(resp["success"])
		self.assertIn("data", resp)
		self.assertIn("request_id", resp["meta"])
		# legacy mirror for the currently deployed client
		self.assertIn("invoices", resp)
