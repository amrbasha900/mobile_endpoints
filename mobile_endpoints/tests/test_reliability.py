"""Reliability contract tests for the mobile API (Phase 02).

Run on a Frappe bench with the `Invoice Form` and `Collection and Payment`
doctypes installed:

    bench --site <site> set-config allow_tests True --parse
    bench --site <site> run-tests --app mobile_endpoints \
        --module mobile_endpoints.tests.test_reliability
    bench --site <site> set-config allow_tests False --parse

These could NOT be executed in the environment where the change was authored
(no Frappe bench / site) -- they were verified against a real bench separately.

Fixture policy
--------------
This suite must be safe to run against a real deployment, not just a
freshly-seeded dev site: it does NOT depend on ERPNext's `_Test *` demo
records (a live site may never have had them loaded), and it does NOT read or
write arbitrary pre-existing / production documents. Master data (Supplier,
Customer, Item) is created under a deterministic `MEP-RELIABILITY-TEST-*` name
so reruns reuse the same fixture instead of accumulating duplicates, and is
left in place between runs (cheap, inert, clearly named). Every *transactional*
document a test creates (Invoice Form, Collection and Payment, and their
`Mobile Request Log` idempotency rows) is tracked and deleted in that test's
tearDown -- `run_idempotent()` commits on success, so these rows are real
commits that a `FrappeTestCase` rollback will NOT undo for us.

A Company is required (creating one has heavy chart-of-accounts side effects,
so the suite reuses whatever is already configured instead of creating one) --
the whole module skips with a clear reason if the site has none.
"""

from __future__ import annotations

import contextlib
import json
import unittest
import uuid
from unittest import mock

import frappe
from frappe.tests.utils import FrappeTestCase

from mobile_endpoints.api import invoice as invoice_api
from mobile_endpoints.api import operation as operation_api
from mobile_endpoints.api import payment as payment_api
from mobile_endpoints.api import security as security_api
from mobile_endpoints.api._idempotency import DOCTYPE as LOG_DOCTYPE
from mobile_endpoints.api._idempotency import _composite

TEST_PREFIX = "MEP-RELIABILITY-TEST"


# --------------------------------------------------------------------------- #
#  request simulation                                                        #
# --------------------------------------------------------------------------- #


def _set_post_body(body: dict) -> None:
	"""Simulate an authenticated POST the way a real non-browser call (native
	app, server-to-server, or this test runner) arrives: `frappe.local.request`
	deliberately has NO `headers` attribute, matching the bare `frappe._dict`
	Frappe leaves behind outside a real werkzeug HTTP cycle. `set_cors_headers`
	must tolerate this -- it previously crashed with
	`AttributeError: 'NoneType' object has no attribute 'get'` because
	`frappe._dict.__getattr__` returns `None` (not a raise) for the missing
	`headers` key, and every endpoint calls it before any of its own logic.
	"""
	frappe.local.request = frappe._dict(method="POST", get_data=lambda as_text=True: json.dumps(body))
	frappe.form_dict = frappe._dict()


def _set_get_request() -> None:
	frappe.local.request = frappe._dict(method="GET")


def _dump(resp) -> str:
	try:
		return json.dumps(resp, default=str, indent=2, ensure_ascii=False)
	except Exception:
		return repr(resp)


def _expect_success(resp, context: str = "") -> dict:
	"""Assert the envelope succeeded and return resp['data']. On failure, raise
	with the FULL envelope so the real cause is visible instead of a secondary
	`KeyError: 'data'` that hides it."""
	if not isinstance(resp, dict) or not resp.get("success"):
		raise AssertionError(f"{context or 'request'} did not succeed:\n{_dump(resp)}")
	if "data" not in resp:
		raise AssertionError(f"{context or 'request'} succeeded but carried no 'data':\n{_dump(resp)}")
	return resp["data"]


def _invoice_body(client_request_id, supplier: str, item_code: str, qty=2, price=50):
	body = {
		"data": {
			"posting_date": frappe.utils.today(),
			"supplier": supplier,
			"items": [{"item_code": item_code, "qty": qty, "price": price}],
		},
	}
	if client_request_id is not None:
		body["client_request_id"] = client_request_id
	return body


def _first_existing(doctype: str, filters=None) -> str | None:
	return frappe.db.get_value(doctype, filters or {}, "name")


def _find_or_create(doctype: str, filters: dict, values: dict):
	"""Reuse a fixture created by a previous run; create it otherwise. This is
	setup data (not the thing under test), so it is inserted with
	ignore_permissions=True regardless of which user the test later runs as."""
	name = frappe.db.get_value(doctype, filters, "name")
	if name:
		return frappe.get_doc(doctype, name)
	doc = frappe.get_doc({"doctype": doctype, **values})
	doc.insert(ignore_permissions=True)
	frappe.db.commit()
	return doc


# --------------------------------------------------------------------------- #
#  shared fixtures                                                           #
# --------------------------------------------------------------------------- #


class ReliabilityTestCase(FrappeTestCase):
	"""Base class: builds self-contained master data once per test run and
	tracks + deletes every transactional document an individual test creates."""

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		frappe.set_user("Administrator")

		company = _first_existing("Company")
		if not company:
			raise unittest.SkipTest(
				"no Company is configured on this site; the reliability suite needs at "
				"least one (it deliberately does not create one -- Company setup has "
				"chart-of-accounts side effects that are out of scope for a test fixture)"
			)
		cls.company = company

		item_group = _first_existing("Item Group", {"name": "All Item Groups"}) or _first_existing("Item Group")
		uom = _first_existing("UOM", {"name": "Nos"}) or _first_existing("UOM")
		supplier_group = _first_existing("Supplier Group")
		customer_group = _first_existing("Customer Group")
		territory = _first_existing("Territory")
		if not item_group or not uom:
			raise unittest.SkipTest("no Item Group / UOM configured on this site")

		cls.supplier = _find_or_create(
			"Supplier",
			{"supplier_name": f"{TEST_PREFIX}-SUPPLIER"},
			{
				"supplier_name": f"{TEST_PREFIX}-SUPPLIER",
				**({"supplier_group": supplier_group} if supplier_group else {}),
			},
		).name
		cls.customer = _find_or_create(
			"Customer",
			{"customer_name": f"{TEST_PREFIX}-CUSTOMER"},
			{
				"customer_name": f"{TEST_PREFIX}-CUSTOMER",
				**({"customer_group": customer_group} if customer_group else {}),
				**({"territory": territory} if territory else {}),
			},
		).name

		item_code = f"{TEST_PREFIX}-ITEM"
		if not frappe.db.exists("Item", item_code):
			frappe.get_doc(
				{
					"doctype": "Item",
					"item_code": item_code,
					"item_name": item_code,
					"item_group": item_group,
					"stock_uom": uom,
					"is_stock_item": 0,
				}
			).insert(ignore_permissions=True)
			frappe.db.commit()
		cls.item_code = item_code

	def setUp(self):
		super().setUp()
		frappe.set_user("Administrator")
		# Each real HTTP request gets a fresh frappe.local; calling these
		# handlers directly, back-to-back, in one test process does not --
		# reset it so one test's http_status_code/headers can't leak into the
		# next test's assertions.
		frappe.local.response = frappe._dict()
		self._docs_to_delete: list[tuple[str, str]] = []

	def tearDown(self):
		for doctype, name in reversed(self._docs_to_delete):
			with contextlib.suppress(Exception):
				frappe.delete_doc(doctype, name, force=True, ignore_permissions=True)
		with contextlib.suppress(Exception):
			frappe.db.commit()
		frappe.set_user("Administrator")
		super().tearDown()

	def track(self, doctype: str, name: str | None) -> None:
		if name:
			self._docs_to_delete.append((doctype, name))

	def track_log(self, scope: str, client_request_id, user: str | None = None) -> None:
		if client_request_id:
			self.track(LOG_DOCTYPE, _composite(user or frappe.session.user, scope, client_request_id))

	# -- convenience wrappers: call the real endpoint AND register cleanup --

	def create_invoice(self, client_request_id, **kw) -> dict:
		_set_post_body(_invoice_body(client_request_id, self.supplier, self.item_code, **kw))
		resp = invoice_api.create_invoice_form()
		if resp.get("success"):
			self.track("Invoice Form", resp["data"].get("name"))
			self.track_log("invoice.create", client_request_id)
		return resp

	def create_invoice_ok(self, client_request_id, **kw) -> dict:
		return _expect_success(self.create_invoice(client_request_id, **kw), "create_invoice_form")


# --------------------------------------------------------------------------- #
#  idempotency / concurrency                                                 #
# --------------------------------------------------------------------------- #


class TestIdempotentCreate(ReliabilityTestCase):
	def test_replay_returns_same_document(self):
		key = str(uuid.uuid4())
		first = self.create_invoice_ok(key)
		name = first["name"]

		before = frappe.db.count("Invoice Form")
		second = _expect_success(self.create_invoice(key), "create_invoice_form (replay)")
		after = frappe.db.count("Invoice Form")

		self.assertEqual(second["name"], name)
		self.assertEqual(before, after, "replaying the same key created a second invoice")

	def test_same_key_different_payload_conflicts(self):
		key = str(uuid.uuid4())
		self.create_invoice_ok(key, qty=2)
		resp = self.create_invoice(key, qty=999)
		self.assertFalse(resp["success"], f"expected a conflict, got:\n{_dump(resp)}")
		self.assertEqual(resp["error"]["code"], "idempotency_conflict")
		self.assertEqual(frappe.local.response.get("http_status_code"), 409)

	def test_missing_key_still_creates_without_a_log_row(self):
		resp = self.create_invoice(None)
		data = _expect_success(resp, "create_invoice_form (keyless)")
		self.assertFalse(
			frappe.db.exists(LOG_DOCTYPE, {"docname": data["name"]}),
			"a keyless request wrote an idempotency log row",
		)

	def test_failed_operation_leaves_no_completed_log(self):
		key = str(uuid.uuid4())
		# Missing required fields (no supplier, no items) -> _do raises before insert.
		_set_post_body({"client_request_id": key, "data": {"posting_date": frappe.utils.today()}})
		resp = invoice_api.create_invoice_form()
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "validation_error")
		self.assertEqual(frappe.local.response.get("http_status_code"), 422)
		self.assertFalse(
			frappe.db.exists(LOG_DOCTYPE, {"name": _composite(frappe.session.user, "invoice.create", key)}),
			"a failed create left a log row (retry would be permanently blocked)",
		)
		# ...and the same key can now be used for a real create.
		self.create_invoice_ok(key)

	def test_same_key_across_different_operations_is_independent(self):
		key = str(uuid.uuid4())
		created = self.create_invoice_ok(key)["name"]

		_set_post_body({"client_request_id": key, "name": created})
		submitted = invoice_api.submit_invoice()
		self.track_log("invoice.submit", key)
		# Different scope -> different composite key -> the submit is NOT treated
		# as a replay of the create.
		data = _expect_success(submitted, "submit_invoice")
		self.assertEqual(data["name"], created)


class TestCrossUserIsolation(ReliabilityTestCase):
	def test_a_user_cannot_read_another_users_request_result(self):
		key = str(uuid.uuid4())
		self.create_invoice_ok(key)  # as Administrator

		frappe.set_user("Guest")
		try:
			_set_get_request()
			status = operation_api.get_operation_status(client_request_id=key, scope="invoice.create")
		finally:
			frappe.set_user("Administrator")

		# Guest's composite key differs -> the Administrator's result is invisible.
		data = _expect_success(status, "get_operation_status (as Guest)")
		self.assertFalse(data["found"])


class TestOptimisticConcurrency(ReliabilityTestCase):
	def test_stale_base_modified_returns_409_with_current_state(self):
		created = self.create_invoice_ok(str(uuid.uuid4()))
		resp = invoice_api.update_invoice(
			name=created["name"],
			data={"items": [{"item_code": self.item_code, "qty": 3, "price": 10}]},
			base_modified="1999-01-01 00:00:00.000000",
		)
		self.assertFalse(resp["success"], f"expected a 409 conflict, got:\n{_dump(resp)}")
		self.assertEqual(resp["error"]["code"], "conflict")
		self.assertEqual(frappe.local.response.get("http_status_code"), 409)
		self.assertIn("items", resp["data"], "409 body must carry the current server state")

	def test_matching_base_modified_updates_and_replays(self):
		created = self.create_invoice_ok(str(uuid.uuid4()))
		key = str(uuid.uuid4())
		update_body = {
			"client_request_id": key,
			"name": created["name"],
			"data": {"items": [{"item_code": self.item_code, "qty": 3, "price": 10}]},
			"base_modified": created["modified"],
		}
		_set_post_body(update_body)
		first = _expect_success(invoice_api.update_invoice(), "update_invoice")
		self.track_log("invoice.update", key)
		self.assertEqual(first["grand_total"], 30)

		# Replay with the same key returns the stored result even though
		# base_modified would now be stale.
		_set_post_body(update_body)
		replay = _expect_success(invoice_api.update_invoice(), "update_invoice (replay)")
		self.assertEqual(replay["grand_total"], 30)


class TestDeleteOutcome(ReliabilityTestCase):
	def test_delete_replay_is_success_but_a_fresh_id_on_a_gone_doc_is_404(self):
		created = self.create_invoice_ok(str(uuid.uuid4()))["name"]
		key = str(uuid.uuid4())

		_set_post_body({"client_request_id": key, "name": created})
		first = _expect_success(invoice_api.delete_invoice(), "delete_invoice")
		self.track_log("invoice.delete", key)
		self.assertTrue(first["deleted"])

		_set_post_body({"client_request_id": key, "name": created})
		replay = _expect_success(invoice_api.delete_invoice(), "delete_invoice (replay)")
		self.assertTrue(replay["deleted"], "replay of the deleting request id must not 404")

		_set_post_body({"client_request_id": str(uuid.uuid4()), "name": created})
		other = invoice_api.delete_invoice()
		self.assertFalse(other["success"])
		self.assertEqual(other["error"]["code"], "not_found")
		self.assertEqual(frappe.local.response.get("http_status_code"), 404)


# --------------------------------------------------------------------------- #
#  payment company resolution (BR-06)                                        #
# --------------------------------------------------------------------------- #


class TestPaymentCompany(ReliabilityTestCase):
	def setUp(self):
		super().setUp()
		# Save/restore Administrator's real default -- these tests must not
		# permanently change a site-wide preference.
		self._prev_default_company = frappe.defaults.get_user_default("company")

	def tearDown(self):
		if self._prev_default_company:
			frappe.defaults.set_user_default("company", self._prev_default_company)
		else:
			frappe.defaults.clear_user_default("company")
		super().tearDown()

	def _payment_body(self, company=None):
		body = {
			"client_request_id": str(uuid.uuid4()),
			"posting_date": frappe.utils.today(),
			"detail": {
				"payment_type": "Pay",
				"party_type": "Customer",
				"party": self.customer,
				"party_name": self.customer,
				"amount": 10,
			},
		}
		if company is not None:
			body["company"] = company
		return body

	def _track_payment(self, resp, client_request_id):
		if resp.get("success"):
			self.track("Collection and Payment", resp["data"].get("name"))
			self.track_log("payment.create", client_request_id)

	def test_missing_company_resolves_the_user_default(self):
		# NB: the resolver reads the lowercase "company" default key
		# (`frappe.defaults.get_user_default("company")`, matching the DocType
		# fieldname) -- setting "Company" here would silently miss it.
		frappe.defaults.set_user_default("company", self.company)
		body = self._payment_body()
		_set_post_body(body)
		resp = payment_api.create_collection_payment()
		self._track_payment(resp, body["client_request_id"])
		data = _expect_success(resp, "create_collection_payment")
		self.assertEqual(data["company"], self.company)

	def test_forbidden_company_returns_422_with_field(self):
		bogus_company = f"{TEST_PREFIX}-NO-SUCH-COMPANY-{uuid.uuid4()}"
		_set_post_body(self._payment_body(company=bogus_company))
		resp = payment_api.create_collection_payment()
		self.assertFalse(resp["success"], f"expected a 422, got:\n{_dump(resp)}")
		self.assertEqual(resp["error"]["code"], "validation_error")
		self.assertIn("company", resp["error"]["fields"])
		self.assertEqual(frappe.local.response.get("http_status_code"), 422)

	def test_ambiguous_company_returns_422(self):
		frappe.defaults.clear_user_default("company")
		# Only meaningful if the site exposes more than one Company to
		# Administrator; otherwise resolve_company() auto-selects the single one.
		if frappe.db.count("Company") < 2:
			self.skipTest("test site does not expose more than one Company")
		body = self._payment_body()
		_set_post_body(body)
		resp = payment_api.create_collection_payment()
		self._track_payment(resp, body["client_request_id"])
		if resp["success"]:
			# A configured Global Defaults default_company still resolves it --
			# that's not something a test may reconfigure on a real site.
			self.skipTest("test site resolves a global default Company despite no user default")
		self.assertEqual(resp["error"]["code"], "validation_error")
		self.assertIn("company", resp["error"]["fields"])
		self.assertEqual(frappe.local.response.get("http_status_code"), 422)


# --------------------------------------------------------------------------- #
#  operation status / envelope                                               #
# --------------------------------------------------------------------------- #


class TestOperationStatus(ReliabilityTestCase):
	def test_unknown_scope_is_422(self):
		_set_get_request()
		resp = operation_api.get_operation_status(client_request_id="x", scope="bogus.scope")
		self.assertFalse(resp["success"])
		self.assertIn("scope", resp["error"]["fields"])
		self.assertEqual(frappe.local.response.get("http_status_code"), 422)

	def test_done_lookup_after_create(self):
		key = str(uuid.uuid4())
		created = self.create_invoice_ok(key)["name"]
		_set_get_request()
		resp = operation_api.get_operation_status(client_request_id=key, scope="invoice.create")
		data = _expect_success(resp, "get_operation_status")
		self.assertTrue(data["found"])
		self.assertEqual(data["status"], "done")
		self.assertEqual(data["name"], created)


class TestEnvelope(ReliabilityTestCase):
	def test_permission_error_is_structured_403(self):
		frappe.set_user("Guest")
		try:
			_set_get_request()
			resp = invoice_api.get_invoices()
		finally:
			frappe.set_user("Administrator")
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "permission_denied")
		self.assertEqual(frappe.local.response.get("http_status_code"), 403)

	def test_success_envelope_shape(self):
		_set_get_request()
		resp = invoice_api.get_invoices(page=1, page_size=1)
		self.assertTrue(resp["success"])
		self.assertIn("data", resp)
		self.assertIn("request_id", resp["meta"])
		self.assertIn("invoices", resp)  # legacy mirror for the deployed client

	def test_unexpected_exception_is_sanitized_500_and_logged(self):
		"""A genuinely unexpected exception (not one of our domain exceptions)
		must never leak internals to the client, but must still be recorded
		server-side via frappe.log_error. The mock does not call through, so
		this does not write a real Error Log row."""

		def _boom(*args, **kwargs):
			raise RuntimeError("simulated unexpected failure")

		_set_get_request()
		with mock.patch.object(frappe, "log_error") as mocked_log_error, mock.patch.object(
			frappe, "get_meta", side_effect=_boom
		):
			resp = invoice_api.get_invoices()

		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "server_error")
		self.assertEqual(frappe.local.response.get("http_status_code"), 500)
		self.assertNotIn("RuntimeError", json.dumps(resp))
		self.assertNotIn("simulated unexpected failure", json.dumps(resp))
		mocked_log_error.assert_called_once()

	def test_log_row_holds_no_secrets(self):
		key = str(uuid.uuid4())
		self.create_invoice_ok(key)
		row = frappe.get_doc(LOG_DOCTYPE, _composite(frappe.session.user, "invoice.create", key))
		blob = json.dumps(row.as_dict(), default=str).lower()
		for needle in ("authorization", "api_key", "api_secret", "password", "token"):
			self.assertNotIn(needle, blob)


# --------------------------------------------------------------------------- #
#  CORS header safety (the real-bench regression)                            #
# --------------------------------------------------------------------------- #


class TestCorsHeaders(FrappeTestCase):
	"""`set_cors_headers` must never crash regardless of what `frappe.local.request`
	looks like -- this is what every other endpoint in this module depends on
	running cleanly before any of its own logic executes."""

	def setUp(self):
		super().setUp()
		frappe.local.response = frappe._dict()
		self._prev_allow_cors = frappe.conf.get("allow_cors")
		frappe.conf["allow_cors"] = ["https://app.pamper.example"]

	def tearDown(self):
		if self._prev_allow_cors is None:
			frappe.conf.pop("allow_cors", None)
		else:
			frappe.conf["allow_cors"] = self._prev_allow_cors
		super().tearDown()

	def test_request_is_none(self):
		frappe.local.request = None
		security_api.set_cors_headers("GET, OPTIONS")  # must not raise
		self.assertNotIn("headers", frappe.local.response)

	def test_request_headers_is_none(self):
		frappe.local.request = frappe._dict(method="GET")  # no "headers" key
		self.assertIsNone(frappe.local.request.headers)
		security_api.set_cors_headers("GET, OPTIONS")  # must not raise
		self.assertNotIn("headers", frappe.local.response)

	def test_origin_missing(self):
		frappe.local.request = frappe._dict(method="GET", headers={})
		security_api.set_cors_headers("GET, OPTIONS")
		self.assertNotIn("headers", frappe.local.response)

	def test_allowed_origin_is_reflected(self):
		frappe.local.request = frappe._dict(method="GET", headers={"Origin": "https://app.pamper.example"})
		security_api.set_cors_headers("GET, OPTIONS")
		headers = frappe.local.response.get("headers") or {}
		self.assertEqual(headers.get("Access-Control-Allow-Origin"), "https://app.pamper.example")

	def test_disallowed_origin_gets_no_header(self):
		frappe.local.request = frappe._dict(method="GET", headers={"Origin": "https://attacker.example"})
		security_api.set_cors_headers("GET, OPTIONS")
		self.assertNotIn("headers", frappe.local.response)
