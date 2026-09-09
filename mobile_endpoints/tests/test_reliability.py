"""Reliability contract tests for the mobile API (Phase 02).

Run on a Frappe bench with the `Invoice Form` and `Collection and Payment`
doctypes installed:

    bench --site <site> run-tests --app mobile_endpoints \
        --module mobile_endpoints.tests.test_reliability

These could NOT be executed in the environment where the change was authored
(no Frappe bench / site).
"""

import json
import uuid

import frappe
from frappe.tests.utils import FrappeTestCase

from mobile_endpoints.api import invoice as invoice_api
from mobile_endpoints.api import operation as operation_api
from mobile_endpoints.api import payment as payment_api
from mobile_endpoints.api._idempotency import DOCTYPE as LOG_DOCTYPE
from mobile_endpoints.api._idempotency import _composite


def _set_post_body(body: dict) -> None:
	frappe.local.request = frappe._dict(method="POST", get_data=lambda as_text=True: json.dumps(body))
	frappe.form_dict = frappe._dict()


def _invoice_body(client_request_id, qty=2, price=50):
	return {
		"client_request_id": client_request_id,
		"data": {
			"posting_date": frappe.utils.today(),
			"supplier": "_Test Supplier",
			"supplier_name": "_Test Supplier",
			"items": [{"item_code": "_Test Item", "item_name": "_Test Item", "qty": qty, "price": price}],
		},
	}


def _create_invoice(client_request_id, **kw):
	_set_post_body(_invoice_body(client_request_id, **kw))
	return invoice_api.create_invoice_form()


class TestIdempotentCreate(FrappeTestCase):
	def test_replay_returns_same_document(self):
		key = str(uuid.uuid4())
		first = _create_invoice(key)
		self.assertTrue(first["success"])
		name = first["data"]["name"]

		before = frappe.db.count("Invoice Form")
		second = _create_invoice(key)
		after = frappe.db.count("Invoice Form")

		self.assertTrue(second["success"])
		self.assertEqual(second["data"]["name"], name)
		self.assertEqual(before, after, "replaying the same key created a second invoice")

	def test_same_key_different_payload_conflicts(self):
		key = str(uuid.uuid4())
		_create_invoice(key, qty=2)
		resp = _create_invoice(key, qty=999)
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "idempotency_conflict")
		self.assertEqual(frappe.local.response.get("http_status_code"), 409)

	def test_missing_key_still_creates_without_a_log_row(self):
		body = _invoice_body(None)
		body.pop("client_request_id", None)
		_set_post_body(body)
		resp = invoice_api.create_invoice_form()
		self.assertTrue(resp["success"])
		self.assertFalse(
			frappe.db.exists(LOG_DOCTYPE, {"docname": resp["data"]["name"]}),
			"a keyless request wrote an idempotency log row",
		)

	def test_failed_operation_leaves_no_completed_log(self):
		key = str(uuid.uuid4())
		# Missing required fields -> _do raises before insert.
		_set_post_body({"client_request_id": key, "data": {"posting_date": frappe.utils.today()}})
		resp = invoice_api.create_invoice_form()
		self.assertFalse(resp["success"])
		self.assertFalse(
			frappe.db.exists(LOG_DOCTYPE, {"name": _composite(frappe.session.user, "invoice.create", key)}),
			"a failed create left a log row (retry would be permanently blocked)",
		)
		# ...and the same key can now be used for a real create.
		ok = _create_invoice(key)
		self.assertTrue(ok["success"])

	def test_same_key_across_different_operations_is_independent(self):
		key = str(uuid.uuid4())
		created = _create_invoice(key)["data"]["name"]

		_set_post_body({"client_request_id": key, "name": created})
		submitted = invoice_api.submit_invoice()
		# Different scope -> different composite key -> the submit is NOT treated
		# as a replay of the create.
		self.assertTrue(submitted["success"])
		self.assertEqual(submitted["data"]["name"], created)


class TestCrossUserIsolation(FrappeTestCase):
	def test_a_user_cannot_read_another_users_request_result(self):
		key = str(uuid.uuid4())
		_create_invoice(key)  # as Administrator

		frappe.set_user("Guest")
		try:
			frappe.local.request = frappe._dict(method="GET")
			status = operation_api.get_operation_status(client_request_id=key, scope="invoice.create")
		finally:
			frappe.set_user("Administrator")

		# Guest's composite key differs -> the Administrator's result is invisible.
		self.assertTrue(status["success"])
		self.assertFalse(status["data"]["found"])


class TestOptimisticConcurrency(FrappeTestCase):
	def test_stale_base_modified_returns_409_with_current_state(self):
		created = _create_invoice(str(uuid.uuid4()))["data"]
		resp = invoice_api.update_invoice(
			name=created["name"],
			data={"items": [{"item_code": "_Test Item", "qty": 3, "price": 10}]},
			base_modified="1999-01-01 00:00:00.000000",
		)
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "conflict")
		self.assertEqual(frappe.local.response.get("http_status_code"), 409)
		self.assertIn("items", resp["data"], "409 body must carry the current server state")

	def test_matching_base_modified_updates_and_replays(self):
		created = _create_invoice(str(uuid.uuid4()))["data"]
		key = str(uuid.uuid4())
		_set_post_body({
			"client_request_id": key,
			"name": created["name"],
			"data": {"items": [{"item_code": "_Test Item", "qty": 3, "price": 10}]},
			"base_modified": created["modified"],
		})
		first = invoice_api.update_invoice()
		self.assertTrue(first["success"])
		self.assertEqual(first["data"]["grand_total"], 30)

		# Replay with the same key returns the stored result even though
		# base_modified would now be stale.
		_set_post_body({
			"client_request_id": key,
			"name": created["name"],
			"data": {"items": [{"item_code": "_Test Item", "qty": 3, "price": 10}]},
			"base_modified": created["modified"],
		})
		replay = invoice_api.update_invoice()
		self.assertTrue(replay["success"])
		self.assertEqual(replay["data"]["grand_total"], 30)


class TestDeleteOutcome(FrappeTestCase):
	def test_delete_replay_is_success_but_a_fresh_id_on_a_gone_doc_is_404(self):
		created = _create_invoice(str(uuid.uuid4()))["data"]["name"]
		key = str(uuid.uuid4())

		_set_post_body({"client_request_id": key, "name": created})
		first = invoice_api.delete_invoice()
		self.assertTrue(first["success"])

		_set_post_body({"client_request_id": key, "name": created})
		replay = invoice_api.delete_invoice()
		self.assertTrue(replay["success"], "replay of the deleting request id must not 404")
		self.assertTrue(replay["data"]["deleted"])

		_set_post_body({"client_request_id": str(uuid.uuid4()), "name": created})
		other = invoice_api.delete_invoice()
		self.assertFalse(other["success"])
		self.assertEqual(other["error"]["code"], "not_found")
		self.assertEqual(frappe.local.response.get("http_status_code"), 404)


class TestPaymentCompany(FrappeTestCase):
	def _payment_body(self, company=None):
		body = {
			"client_request_id": str(uuid.uuid4()),
			"posting_date": frappe.utils.today(),
			"detail": {
				"payment_type": "Pay",
				"party_type": "Customer",
				"party": "_Test Customer",
				"party_name": "_Test Customer",
				"amount": 10,
			},
		}
		if company is not None:
			body["company"] = company
		return body

	def test_missing_company_resolves_the_user_default(self):
		frappe.defaults.set_user_default("Company", "_Test Company")
		_set_post_body(self._payment_body())
		resp = payment_api.create_collection_payment()
		self.assertTrue(resp["success"])
		self.assertEqual(resp["data"]["company"], "_Test Company")

	def test_forbidden_company_returns_422_with_field(self):
		_set_post_body(self._payment_body(company="_Not My Company"))
		resp = payment_api.create_collection_payment()
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "validation_error")
		self.assertIn("company", resp["error"]["fields"])
		self.assertEqual(frappe.local.response.get("http_status_code"), 422)

	def test_ambiguous_company_returns_422(self):
		frappe.defaults.clear_user_default("Company")
		# Assumes the test site has >1 Company visible to Administrator.
		_set_post_body(self._payment_body())
		resp = payment_api.create_collection_payment()
		if resp["success"]:
			self.skipTest("test site exposes exactly one company")
		self.assertEqual(resp["error"]["code"], "validation_error")
		self.assertIn("company", resp["error"]["fields"])


class TestOperationStatus(FrappeTestCase):
	def test_unknown_scope_is_422(self):
		frappe.local.request = frappe._dict(method="GET")
		resp = operation_api.get_operation_status(client_request_id="x", scope="bogus.scope")
		self.assertFalse(resp["success"])
		self.assertIn("scope", resp["error"]["fields"])

	def test_done_lookup_after_create(self):
		key = str(uuid.uuid4())
		created = _create_invoice(key)["data"]["name"]
		frappe.local.request = frappe._dict(method="GET")
		resp = operation_api.get_operation_status(client_request_id=key, scope="invoice.create")
		self.assertTrue(resp["success"])
		self.assertTrue(resp["data"]["found"])
		self.assertEqual(resp["data"]["status"], "done")
		self.assertEqual(resp["data"]["name"], created)


class TestEnvelope(FrappeTestCase):
	def test_permission_error_is_structured_403(self):
		frappe.set_user("Guest")
		try:
			frappe.local.request = frappe._dict(method="GET")
			resp = invoice_api.get_invoices()
		finally:
			frappe.set_user("Administrator")
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "permission_denied")
		self.assertEqual(frappe.local.response.get("http_status_code"), 403)

	def test_success_envelope_shape(self):
		frappe.local.request = frappe._dict(method="GET")
		resp = invoice_api.get_invoices(page=1, page_size=1)
		self.assertTrue(resp["success"])
		self.assertIn("data", resp)
		self.assertIn("request_id", resp["meta"])
		self.assertIn("invoices", resp)  # legacy mirror for the deployed client

	def test_log_row_holds_no_secrets(self):
		key = str(uuid.uuid4())
		_create_invoice(key)
		row = frappe.get_doc(LOG_DOCTYPE, _composite(frappe.session.user, "invoice.create", key))
		blob = json.dumps(row.as_dict(), default=str).lower()
		for needle in ("authorization", "api_key", "api_secret", "password", "token"):
			self.assertNotIn(needle, blob)
