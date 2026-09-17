"""Reliability contract tests for the mobile API (Phase 02).

Run on a Frappe bench with the `Invoice Form` and `Collection and Payment`
doctypes installed. Use scripts/run_reliability_tests.sh from the repo root
rather than calling `bench run-tests` directly -- on this bench, `bench
run-tests` can print `FAILED (...)` and still exit 0, so the raw shell exit
code is not proof of anything:

    ./scripts/run_reliability_tests.sh <site> [bench_dir]

or manually:

    bench --site <site> set-config allow_tests True --parse
    bench --site <site> run-tests --app mobile_endpoints \
        --module mobile_endpoints.tests.test_reliability
    bench --site <site> set-config allow_tests False --parse

These could NOT be executed in the environment where the change was authored
(no Frappe bench / site) -- they were verified against a real bench separately.

Request-harness policy
-----------------------
`frappe.local.request` is built with a REAL `werkzeug.wrappers.Request` (see
`_build_request`), not a bare `frappe._dict`. Two production code paths read
it differently -- `security.set_cors_headers` via `request.headers.get(...)`,
`invoice._parse_payload` via the `request.data` property, `invoice/payment
._request_meta`/`_extract_payload` via `request.get_data(as_text=True)` -- and
a `frappe._dict` only ever satisfies the last one (its `.headers`/`.data` are
`None`, since `frappe._dict.__getattr__` returns `None` for a missing key
instead of raising). A real Werkzeug request makes `.headers`, `.data`,
`.get_data()`, and `.get_json()` all behave exactly as they do for a real
HTTP call, which is what the production code actually depends on and what
`TestRequestHarness` below proves before anything else here relies on it.

For an endpoint whose signature accepts the JSON body's fields as parameters
(`update_invoice(name, data)`, `submit_invoke(name)`, ...), a real HTTP call
has Frappe's own dispatcher bind those directly as keyword arguments *before*
calling the handler -- calling the Python function with zero arguments and
relying on it to re-parse its own request body is not equivalent, so the
helpers below pass those explicitly, exactly as the dispatcher would, while
still attaching the full raw body to `frappe.local.request` so the endpoint's
own `_request_meta()`/`_extract_payload()` (used for fields that are NOT part
of the signature, like `client_request_id` and `base_modified`) sees the same
thing a real request would carry.

Fixture policy
--------------
This suite must be safe to run against a real deployment, not just a
freshly-seeded dev site: it does NOT depend on ERPNext's `_Test *` demo
records (a live site may never have had them loaded), and it does NOT read or
write arbitrary pre-existing / production documents. Master data (Supplier,
Customer, Item, Role/User, Mode of Payment) is created under a deterministic
`MEP-RELIABILITY-TEST-*` name so reruns reuse the same fixture instead of
accumulating duplicates, and is left in place between runs (cheap, inert,
clearly named). Every *transactional* document a test creates (Invoice Form,
Collection and Payment, and their `Mobile Request Log` idempotency rows) is
tracked and deleted in that test's tearDown -- `run_idempotent()` commits on
success, so these rows are real commits that a `FrappeTestCase` rollback will
NOT undo for us.

A Company is required (creating one has heavy chart-of-accounts side effects,
so the suite reuses whatever is already configured instead of creating one) --
the whole module skips with a clear reason if the site has none. A Mode of
Payment is created the same deterministic/reused way for the payment tests;
if this site's ERP configuration makes even a minimal Mode of Payment
impossible to create (a genuine prerequisite gap, not a mistake in our own
validation), only the payment test class skips, with the underlying error
message included.
"""

from __future__ import annotations

import contextlib
import json
import unittest
import uuid
from unittest import mock

import frappe
import werkzeug.test
import werkzeug.wrappers
from frappe.tests.utils import FrappeTestCase

from mobile_endpoints.api import invoice as invoice_api
from mobile_endpoints.api import operation as operation_api
from mobile_endpoints.api import payment as payment_api
from mobile_endpoints.api import security as security_api
from mobile_endpoints.api import user as user_api
from mobile_endpoints.api._idempotency import DOCTYPE as LOG_DOCTYPE
from mobile_endpoints.api._idempotency import _composite

TEST_PREFIX = "MEP-RELIABILITY-TEST"
TEST_USER_EMAIL = f"{TEST_PREFIX.lower()}-no-access@example.invalid"
TEST_ROLE = f"{TEST_PREFIX}-NO-ACCESS"


# --------------------------------------------------------------------------- #
#  request simulation -- real Werkzeug requests, not a bare frappe._dict      #
# --------------------------------------------------------------------------- #


def _build_request(method: str, body: dict | None = None) -> werkzeug.wrappers.Request:
	data = json.dumps(body).encode("utf-8") if body is not None else b""
	environ = werkzeug.test.EnvironBuilder(method=method, data=data, content_type="application/json").get_environ()
	return werkzeug.wrappers.Request(environ)


def _reset_http_state(request: werkzeug.wrappers.Request) -> None:
	"""Start a fresh direct-call request without rebinding Frappe's proxies.

	``frappe.form_dict`` is a LocalProxy. Assigning to the module attribute
	replaces the proxy process-wide; the request-local value belongs on
	``frappe.local.form_dict`` instead. Direct handler calls also reuse the
	current Local object, so response status, message log and request id must
	be reset just like Frappe does for a real HTTP request.
	"""
	frappe.local.request = request
	frappe.local.form_dict = frappe._dict()
	frappe.local.response = frappe._dict()
	frappe.local.message_log = []
	frappe.local.mobile_request_id = None


def _set_post_body(body: dict) -> None:
	_reset_http_state(_build_request("POST", body))


def _set_get_request() -> None:
	_reset_http_state(_build_request("GET"))


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


def _test_user() -> str:
	"""Return an authenticated System User with a role that grants no API
	document permissions. Only clearly named test fixtures are created or
	repaired; no existing production user's roles are touched."""
	if not frappe.db.exists("Role", TEST_ROLE):
		frappe.get_doc(
			{
				"doctype": "Role",
				"role_name": TEST_ROLE,
				"desk_access": 1,
			}
		).insert(ignore_permissions=True)

	if frappe.db.exists("User", TEST_USER_EMAIL):
		user = frappe.get_doc("User", TEST_USER_EMAIL)
	else:
		user = frappe.get_doc(
			{
				"doctype": "User",
				"email": TEST_USER_EMAIL,
				"first_name": "MEP Reliability No Access",
				"send_welcome_email": 0,
				"enabled": 1,
				"user_type": "System User",
			}
		)

	needs_save = False
	if user.get("user_type") != "System User":
		user.user_type = "System User"
		needs_save = True
	if not user.get("enabled"):
		user.enabled = 1
		needs_save = True
	role_added = TEST_ROLE not in {row.role for row in (user.get("roles") or [])}
	if role_added:
		user.append("roles", {"role": TEST_ROLE})
		needs_save = True
	if user.is_new():
		user.insert(ignore_permissions=True)
	elif needs_save:
		user.save(ignore_permissions=True)
	frappe.db.commit()
	return user.name


# --------------------------------------------------------------------------- #
#  request-harness self-check (item 1) -- run before anything trusts it       #
# --------------------------------------------------------------------------- #


class TestRequestHarness(FrappeTestCase):
	"""Proves _build_request()/_set_post_body()/_set_get_request() actually
	produce a request every production code path can read, BEFORE the
	idempotency/concurrency tests below rely on it."""

	def test_post_json_request_round_trips_the_body(self):
		body = {"posting_date": "2026-01-01", "items": [{"item_code": "X", "qty": 1}], "client_request_id": "abc"}
		form_dict_proxy = frappe.form_dict
		_set_post_body(body)

		self.assertEqual(frappe.request.method, "POST")
		self.assertEqual(frappe.request.headers.get("Content-Type"), "application/json")
		# The three ways production code reads the body must all agree:
		self.assertEqual(frappe.request.get_json(), body)  # operation.py-style
		self.assertEqual(json.loads(frappe.request.get_data(as_text=True)), body)  # _request_meta/_extract_payload
		self.assertEqual(frappe.request.data, json.dumps(body).encode("utf-8"))  # invoice._parse_payload fallback
		self.assertIs(frappe.form_dict, form_dict_proxy, "the frappe.form_dict LocalProxy was rebound")

	def test_get_request_has_real_headers_and_no_body(self):
		frappe.local.message_log = [{"message": "stale"}]
		frappe.local.mobile_request_id = "stale-request-id"
		_set_get_request()
		self.assertEqual(frappe.request.method, "GET")
		# A real Headers mapping, not None -- this is the exact call that
		# crashed set_cors_headers on a bare frappe._dict.
		self.assertIsNone(frappe.request.headers.get("Origin"))
		self.assertEqual(frappe.request.get_data(as_text=True), "")
		self.assertEqual(frappe.local.message_log, [])
		self.assertIsNone(frappe.local.mobile_request_id)


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
		item = _find_or_create(
			"Item",
			{"item_code": item_code},
			{
				"item_code": item_code,
				"item_name": item_code,
				"item_group": item_group,
				"stock_uom": uom,
				"is_stock_item": 0,
				"disabled": 0,
			},
		)
		# ERPNext may name Items from a naming series. The API Link field must
		# receive the actual document name, not the requested item_code.
		cls.item_code = item.name
		cls.other_user = _test_user()

	def setUp(self):
		super().setUp()
		frappe.set_user("Administrator")
		# Each real HTTP request gets a fresh frappe.local; calling these
		# handlers directly, back-to-back, in one test process does not --
		# reset it so one test's http_status_code/headers can't leak into the
		# next test's assertions.
		frappe.local.request = None
		frappe.local.form_dict = frappe._dict()
		frappe.local.response = frappe._dict()
		frappe.local.message_log = []
		frappe.local.mobile_request_id = None
		self._docs_to_delete: list[tuple[str, str]] = []

	def tearDown(self):
		self._cleanup_tracked_docs()
		frappe.set_user("Administrator")
		super().tearDown()

	def track(self, doctype: str, name: str | None) -> None:
		if name:
			self._docs_to_delete.append((doctype, name))

	def track_log(self, scope: str, client_request_id, user: str | None = None) -> None:
		if client_request_id:
			self.track(LOG_DOCTYPE, _composite(user or frappe.session.user, scope, client_request_id))

	@staticmethod
	def _cancel_if_submitted(doctype: str, name: str) -> None:
		"""Frappe refuses to delete a submitted (docstatus=1) document outright
		('Submitted Record cannot be deleted') -- cancel it first. Safe to call
		on a doctype with no docstatus concept, a document that no longer
		exists, or one that is already draft/cancelled."""
		try:
			docstatus = frappe.db.get_value(doctype, name, "docstatus")
		except Exception:
			return
		if docstatus != 1:
			return
		doc = frappe.get_doc(doctype, name)
		doc.flags.ignore_permissions = True
		doc.cancel()
		frappe.db.commit()

	def _cleanup_tracked_docs(self) -> None:
		"""Cancel-then-delete every document this test tracked via track()/
		track_log(), most-recently-tracked first. Idempotent and safe to call
		more than once (e.g. once mid-test for a regression assertion, then
		again from tearDown): each entry is popped as it's processed, a
		missing document is a no-op (delete_doc's default ignore_missing),
		and every step is isolated so one failure can't skip the rest -- this
		must clean up equally well after a failed assertion as after a pass.
		Only ever touches (doctype, name) pairs THIS test itself tracked, so
		it never reaches for unrelated/pre-existing records."""
		while self._docs_to_delete:
			doctype, name = self._docs_to_delete.pop()
			with contextlib.suppress(Exception):
				self._cancel_if_submitted(doctype, name)
			with contextlib.suppress(Exception):
				frappe.delete_doc(doctype, name, force=True, ignore_permissions=True)
		with contextlib.suppress(Exception):
			frappe.db.commit()

	# -- convenience wrappers: call the real endpoint the way a real HTTP
	#    request would (Frappe's dispatcher binds body fields matching the
	#    signature as kwargs) AND register cleanup for whatever they created,
	#    including the Mobile Request Log row for that call --

	def create_invoice(self, client_request_id, qty=2, price=50) -> dict:
		body = {
			"posting_date": frappe.utils.today(),
			"supplier": self.supplier,
			"customer": self.customer,
			"items": [
				{
					"item_code": self.item_code,
					"customer": self.customer,
					"qty": qty,
					"price": price,
				}
			],
		}
		if client_request_id is not None:
			body["client_request_id"] = client_request_id
		# create_invoice_form() takes no parameters -- everything is read from
		# the raw body, exactly like a real POST with no dispatcher-bound args.
		_set_post_body(body)
		resp = invoice_api.create_invoice_form()
		if resp.get("success"):
			self.track("Invoice Form", resp["data"].get("name"))
			self.track_log("invoice.create", client_request_id)
		return resp

	def create_invoice_ok(self, client_request_id, **kw) -> dict:
		return _expect_success(self.create_invoice(client_request_id, **kw), "create_invoice_form")

	def update_invoice(self, name: str, items: list[dict], base_modified: str, client_request_id=None) -> dict:
		# Customer is mandatory on this deployment's Invoice Form child row.
		# Mirror the production client, which sends the selected customer per row.
		normalized_items = [
			{**item, "customer": item.get("customer") or self.customer}
			for item in items
		]
		data = {"items": normalized_items}
		full_body = {"name": name, "data": data, "base_modified": base_modified}
		if client_request_id is not None:
			full_body["client_request_id"] = client_request_id
		_set_post_body(full_body)
		# name/data ARE in update_invoice's signature -- a real dispatched call
		# binds them directly; base_modified/client_request_id are not, and
		# reach the handler only via _request_meta() reading the raw body above.
		resp = invoice_api.update_invoice(name=name, data=data)
		if resp.get("success"):
			self.track_log("invoice.update", client_request_id)
		return resp

	def submit_invoice(self, name: str, client_request_id=None) -> dict:
		body = {"name": name}
		if client_request_id is not None:
			body["client_request_id"] = client_request_id
		_set_post_body(body)
		resp = invoice_api.submit_invoice(name=name)
		if resp.get("success"):
			# The invoice itself is already tracked (as of create_invoice()) --
			# submitting it doesn't create a new document, just a new log row
			# under the "invoice.submit" scope. _cleanup_tracked_docs() cancels
			# the now-submitted Invoice Form before deleting it.
			self.track_log("invoice.submit", client_request_id)
		return resp

	def delete_invoice(self, name: str, client_request_id=None) -> dict:
		body = {"name": name}
		if client_request_id is not None:
			body["client_request_id"] = client_request_id
		_set_post_body(body)
		resp = invoice_api.delete_invoice(name=name)
		if resp.get("success"):
			self.track_log("invoice.delete", client_request_id)
		return resp


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
		_set_post_body({"client_request_id": key, "posting_date": frappe.utils.today()})
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

		submitted = self.submit_invoice(created, client_request_id=key)
		# Different scope -> different composite key -> the submit is NOT treated
		# as a replay of the create.
		data = _expect_success(submitted, "submit_invoice")
		self.assertEqual(data["name"], created)


class TestCleanup(ReliabilityTestCase):
	"""Regression coverage for the stray-submitted-invoice bug: tearDown() used
	to call frappe.delete_doc() straight on a tracked document, and Frappe
	refuses to delete a submitted (docstatus=1) one outright -- the exception
	was swallowed by the per-item contextlib.suppress(Exception), silently
	leaving it behind (e.g. an invoice created and submitted by
	test_same_key_across_different_operations_is_independent above)."""

	def test_cleanup_cancels_and_removes_a_submitted_invoice(self):
		created = self.create_invoice_ok(str(uuid.uuid4()))
		name = created["name"]
		submitted = self.submit_invoice(name, client_request_id=str(uuid.uuid4()))
		_expect_success(submitted, "submit_invoice")
		self.assertEqual(
			frappe.db.get_value("Invoice Form", name, "docstatus"), 1, "setup did not actually submit the invoice"
		)

		# Exercise the exact path tearDown() uses, mid-test, so this test can
		# assert on the outcome itself rather than only trusting tearDown to
		# not raise.
		self._cleanup_tracked_docs()

		self.assertFalse(
			frappe.db.exists("Invoice Form", name), "a submitted invoice survived cleanup (must cancel, then delete)"
		)
		self.assertEqual(
			self._docs_to_delete, [], "cleanup must drain the tracked-docs list so it is safe to call again"
		)
		# Idempotent: calling it again (as tearDown() itself will, right after
		# this test returns) must not raise even though everything is gone.
		self._cleanup_tracked_docs()

	def test_cleanup_only_targets_this_tests_own_tracked_documents(self):
		untouched = self.create_invoice_ok(str(uuid.uuid4()))["name"]
		self._docs_to_delete.clear()  # simulate: never tracked by this test

		mine = self.create_invoice_ok(str(uuid.uuid4()))["name"]
		self._cleanup_tracked_docs()

		self.assertFalse(frappe.db.exists("Invoice Form", mine), "a tracked document survived cleanup")
		self.assertTrue(
			frappe.db.exists("Invoice Form", untouched),
			"cleanup deleted a document this test never tracked -- it must only ever "
			"touch records this test itself created",
		)
		self.track("Invoice Form", untouched)  # let the real tearDown() remove it


class TestCrossUserIsolation(ReliabilityTestCase):
	def test_a_user_cannot_read_another_users_request_result(self):
		key = str(uuid.uuid4())
		self.create_invoice_ok(key)  # as Administrator

		frappe.set_user(self.other_user)
		try:
			_set_get_request()
			status = operation_api.get_operation_status(client_request_id=key, scope="invoice.create")
		finally:
			frappe.set_user("Administrator")

		# A different authenticated user's composite key differs, so the
		# Administrator's result is invisible without weakening the endpoint's
		# Phase 01 authentication requirement.
		data = _expect_success(status, "get_operation_status (as another user)")
		self.assertFalse(data["found"])


class TestOptimisticConcurrency(ReliabilityTestCase):
	def test_stale_base_modified_returns_409_with_current_state(self):
		created = self.create_invoice_ok(str(uuid.uuid4()))
		resp = self.update_invoice(
			name=created["name"],
			items=[{"item_code": self.item_code, "qty": 3, "price": 10}],
			base_modified="1999-01-01 00:00:00.000000",
		)
		self.assertFalse(resp["success"], f"expected a 409 conflict, got:\n{_dump(resp)}")
		self.assertEqual(resp["error"]["code"], "conflict")
		self.assertEqual(frappe.local.response.get("http_status_code"), 409)
		self.assertIn("items", resp["data"], "409 body must carry the current server state")

	def test_matching_base_modified_updates_and_replays(self):
		created = self.create_invoice_ok(str(uuid.uuid4()))
		key = str(uuid.uuid4())
		items = [{"item_code": self.item_code, "qty": 3, "price": 10}]

		first = _expect_success(
			self.update_invoice(created["name"], items, created["modified"], client_request_id=key),
			"update_invoice",
		)
		self.assertEqual(first["grand_total"], 30)

		# Replay with the same key returns the stored result even though
		# base_modified would now be stale.
		replay = _expect_success(
			self.update_invoice(created["name"], items, created["modified"], client_request_id=key),
			"update_invoice (replay)",
		)
		self.assertEqual(replay["grand_total"], 30)


class TestDeleteOutcome(ReliabilityTestCase):
	def test_delete_replay_is_success_but_a_fresh_id_on_a_gone_doc_is_404(self):
		created = self.create_invoice_ok(str(uuid.uuid4()))["name"]
		key = str(uuid.uuid4())

		first = _expect_success(self.delete_invoice(created, client_request_id=key), "delete_invoice")
		self.assertTrue(first["deleted"])

		replay = _expect_success(self.delete_invoice(created, client_request_id=key), "delete_invoice (replay)")
		self.assertTrue(replay["deleted"], "replay of the deleting request id must not 404")

		other = self.delete_invoice(created, client_request_id=str(uuid.uuid4()))
		self.assertFalse(other["success"])
		self.assertEqual(other["error"]["code"], "not_found")
		self.assertEqual(frappe.local.response.get("http_status_code"), 404)


class TestInvoiceEditability(ReliabilityTestCase):
	"""One rule behind get_invoices / get_invoice_details / update_invoice:
	docstatus 0 + write permission. The legacy `lock_update` flag (which this
	app used to stamp on every invoice it created) must not make an otherwise
	editable invoice look locked."""

	def _get_invoices(self, **kw):
		_set_get_request()
		return invoice_api.get_invoices(**kw)

	def _get_details(self, name: str):
		_set_get_request()
		return invoice_api.get_invoice_details(name=name)

	def _row_for(self, name: str, **kw):
		today_str = frappe.utils.today()
		resp = _expect_success(
			self._get_invoices(from_date=today_str, to_date=today_str, page_size=100, **kw),
			"get_invoices",
		)
		return next((row for row in resp["invoices"] if row["invoiceNumber"] == name), None)

	def test_an_invoice_created_by_this_api_is_reported_as_editable(self):
		created = self.create_invoice_ok(str(uuid.uuid4()))

		details = _expect_success(self._get_details(created["name"]), "get_invoice_details")
		self.assertTrue(details["permissions"]["update"], _dump(details["permissions"]))
		self.assertFalse(details["permissions"]["locked"])
		self.assertFalse(details["is_locked"])

		row = self._row_for(created["name"])
		self.assertIsNotNone(row, "the new invoice must appear in the list")
		self.assertTrue(row["permissions"]["update"])
		self.assertFalse(row["permissions"]["locked"])

	def test_update_and_locked_never_contradict_each_other(self):
		created = self.create_invoice_ok(str(uuid.uuid4()))
		for source, perms in (
			("details", _expect_success(self._get_details(created["name"]), "details")["permissions"]),
			("list", self._row_for(created["name"])["permissions"]),
		):
			self.assertNotEqual(
				perms["update"], perms["locked"], f"{source}: update and locked must be opposites"
			)

	def test_a_legacy_pending_invoice_carrying_lock_update_is_still_editable(self):
		"""Existing rows keep the flag (no bulk update); they must follow the
		new rule anyway."""
		created = self.create_invoice_ok(str(uuid.uuid4()))
		# Test-only: put the legacy flag back on, exactly as older rows have it.
		frappe.db.set_value("Invoice Form", created["name"], "lock_update", 1)
		frappe.db.commit()

		details = _expect_success(self._get_details(created["name"]), "get_invoice_details")
		self.assertTrue(details["permissions"]["update"])
		self.assertFalse(details["permissions"]["locked"])

		# ...and the update endpoint agrees: it really can be edited.
		updated = _expect_success(
			self.update_invoice(
				created["name"],
				[{"item_code": self.item_code, "qty": 3, "price": 10}],
				details["modified"],
				client_request_id=str(uuid.uuid4()),
			),
			"update_invoice on a legacy-locked invoice",
		)
		self.assertEqual(updated["grand_total"], 30)

	def test_a_submitted_invoice_is_not_editable_by_anyone(self):
		created = self.create_invoice_ok(str(uuid.uuid4()))
		self.submit_invoice(created["name"], client_request_id=str(uuid.uuid4()))

		details = _expect_success(self._get_details(created["name"]), "get_invoice_details")
		self.assertFalse(details["permissions"]["update"])
		self.assertTrue(details["permissions"]["locked"])

		rejected = self.update_invoice(
			created["name"],
			[{"item_code": self.item_code, "qty": 4, "price": 10}],
			details["modified"],
			client_request_id=str(uuid.uuid4()),
		)
		self.assertFalse(rejected["success"], f"expected a 422, got:\n{_dump(rejected)}")
		self.assertEqual(rejected["error"]["code"], "validation_error")
		self.assertEqual(frappe.local.response.get("http_status_code"), 422)

	def test_a_user_without_write_permission_gets_403_from_update(self):
		created = self.create_invoice_ok(str(uuid.uuid4()))
		frappe.set_user(self.other_user)
		try:
			resp = self.update_invoice(
				created["name"],
				[{"item_code": self.item_code, "qty": 2, "price": 10}],
				created["modified"],
				client_request_id=str(uuid.uuid4()),
			)
		finally:
			frappe.set_user("Administrator")
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "permission_denied")
		self.assertEqual(frappe.local.response.get("http_status_code"), 403)


# --------------------------------------------------------------------------- #
#  invoice list: date-range period + server summary (Phase 02 increment 4)   #
# --------------------------------------------------------------------------- #


class TestInvoicePeriodAndSummary(ReliabilityTestCase):
	def _get_invoices(self, **kw):
		_set_get_request()
		return invoice_api.get_invoices(**kw)

	def test_default_period_is_today_in_the_site_timezone(self):
		resp = _expect_success(self._get_invoices(page_size=1), "get_invoices")
		today_str = frappe.utils.today()
		self.assertEqual(resp["period"]["from_date"], today_str)
		self.assertEqual(resp["period"]["to_date"], today_str)
		self.assertTrue(resp["period"]["timezone"])

	def test_explicit_period_presets_are_honored(self):
		today = frappe.utils.getdate(frappe.utils.today())
		yesterday = frappe.utils.add_days(today, -1)
		last_7 = frappe.utils.add_days(today, -6)
		last_30 = frappe.utils.add_days(today, -29)

		for from_date, to_date in (
			(str(yesterday), str(yesterday)),
			(str(last_7), str(today)),
			(str(last_30), str(today)),
		):
			resp = _expect_success(
				self._get_invoices(from_date=from_date, to_date=to_date, page_size=1), "get_invoices"
			)
			self.assertEqual((resp["period"]["from_date"], resp["period"]["to_date"]), (from_date, to_date))

	def test_invalid_date_is_422(self):
		resp = self._get_invoices(from_date="not-a-date", to_date="2026-01-31")
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "validation_error")
		self.assertEqual(frappe.local.response.get("http_status_code"), 422)

	def test_reversed_date_range_is_422(self):
		resp = self._get_invoices(from_date="2026-02-01", to_date="2026-01-01")
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "validation_error")

	def test_range_wider_than_the_limit_is_422(self):
		resp = self._get_invoices(from_date="2020-01-01", to_date="2026-01-01")
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "validation_error")

	def test_summary_is_identical_across_page_1_and_page_2(self):
		today_str = frappe.utils.today()
		for _i in range(3):
			self.create_invoice_ok(str(uuid.uuid4()))

		page1 = _expect_success(
			self._get_invoices(from_date=today_str, to_date=today_str, page=1, page_size=1), "get_invoices p1"
		)
		page2 = _expect_success(
			self._get_invoices(from_date=today_str, to_date=today_str, page=2, page_size=1), "get_invoices p2"
		)
		self.assertEqual(page1["summary"], page2["summary"])
		# create_invoice_ok() always leaves a real invoice at docstatus=0 with
		# workflow status "Pending" -- the "pending" bucket, not "draft" (which
		# no create-API path can reach; see test_blank_status_invoice_is_
		# counted_as_draft_not_pending for dedicated draft-bucket coverage).
		self.assertGreaterEqual(page1["summary"]["pending"], 3)

	def test_search_and_supplier_filters_affect_rows_and_summary_consistently(self):
		today_str = frappe.utils.today()
		before = _expect_success(
			self._get_invoices(from_date=today_str, to_date=today_str, supplier=self.supplier, page_size=1),
			"get_invoices (before)",
		)
		self.create_invoice_ok(str(uuid.uuid4()))
		after = _expect_success(
			self._get_invoices(from_date=today_str, to_date=today_str, supplier=self.supplier, page_size=1),
			"get_invoices (after)",
		)
		self.assertEqual(after["summary"]["pending"], before["summary"]["pending"] + 1)
		self.assertEqual(after["summary"]["total"], before["summary"]["total"] + 1)

	def test_selected_status_filter_does_not_hide_the_other_status_cards(self):
		today_str = frappe.utils.today()
		self.create_invoice_ok(str(uuid.uuid4()))  # left Pending
		submitted_name = self.create_invoice_ok(str(uuid.uuid4()))["name"]
		self.submit_invoice(submitted_name, client_request_id=str(uuid.uuid4()))

		resp = _expect_success(
			self._get_invoices(from_date=today_str, to_date=today_str, status="submitted", page_size=1),
			"get_invoices (status=submitted)",
		)
		# Even while filtering rows to "submitted", the summary must still
		# report the (non-zero) pending count -- not just the active tab's.
		self.assertGreaterEqual(resp["summary"]["submitted"], 1)
		self.assertGreaterEqual(resp["summary"]["pending"], 1)

	def test_blank_status_invoice_is_counted_as_draft_not_pending(self):
		"""No create-API path leaves an invoice with a blank workflow status --
		create_invoice_form() always sets it to "Pending" -- so the "draft"
		bucket (docstatus=0 with a blank/non-"Pending" status) can only be
		exercised here via a test-only DB update, never by redefining a normal
		Pending invoice as Draft."""
		today_str = frappe.utils.today()
		before = _expect_success(
			self._get_invoices(from_date=today_str, to_date=today_str, page_size=1), "get_invoices (before)"
		)
		name = self.create_invoice_ok(str(uuid.uuid4()))["name"]
		frappe.db.set_value("Invoice Form", name, "status", "")
		frappe.db.commit()

		after = _expect_success(
			self._get_invoices(from_date=today_str, to_date=today_str, page_size=1), "get_invoices (after)"
		)
		self.assertEqual(after["summary"]["draft"], before["summary"]["draft"] + 1)
		self.assertEqual(after["summary"]["pending"], before["summary"]["pending"])
		self.assertEqual(after["summary"]["total"], before["summary"]["total"] + 1)

	def test_cross_user_gets_no_rows_no_counts_not_a_403_disguised_as_zero(self):
		"""A user with zero document permission on Invoice Form must be
		refused outright (403) -- never a "successful" empty/zero summary
		that could be mistaken for "no invoices exist"."""
		self.create_invoice_ok(str(uuid.uuid4()))  # as Administrator

		frappe.set_user(self.other_user)
		try:
			resp = self._get_invoices(page_size=1)
		finally:
			frappe.set_user("Administrator")

		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "permission_denied")
		self.assertEqual(frappe.local.response.get("http_status_code"), 403)


# --------------------------------------------------------------------------- #
#  payment company resolution (BR-06) + idempotency                          #
# --------------------------------------------------------------------------- #


class TestPaymentCompany(ReliabilityTestCase):
	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		try:
			# Referencing an existing enabled mode is read-only and exercises
			# the same configured master data the app uses. Create a clearly
			# named fixture only on a site that has no enabled mode at all.
			existing = frappe.db.get_value("Mode of Payment", {"enabled": 1}, "name")
			cls.mode_of_payment = existing or _find_or_create(
				"Mode of Payment",
				{"mode_of_payment": f"{TEST_PREFIX}-MODE-OF-PAYMENT"},
				{"mode_of_payment": f"{TEST_PREFIX}-MODE-OF-PAYMENT", "type": "Cash", "enabled": 1},
			).name
		except Exception as exc:
			# A genuine ERP prerequisite this suite cannot satisfy on its own
			# (e.g. a mandatory per-company account mapping) -- not a mistake
			# in our own request/validation logic. Skip only this class, with
			# the underlying error so it's actionable.
			raise unittest.SkipTest(
				f"could not create a minimal test Mode of Payment "
				f"('{TEST_PREFIX}-MODE-OF-PAYMENT') on this site: {exc}"
			) from exc

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
				"mode_of_payment": self.mode_of_payment,
			},
		}
		if company is not None:
			body["company"] = company
		return body

	def _create_payment(self, body: dict) -> dict:
		_set_post_body(body)
		resp = payment_api.create_collection_payment()
		if resp.get("success"):
			self.track("Collection and Payment", resp["data"].get("name"))
			self.track_log("payment.create", body["client_request_id"])
		return resp

	@staticmethod
	def _force_status(name: str, status: str) -> None:
		"""Test-only: directly set a workflow status the create API itself
		has no way to reach (it never accepts a client-supplied status).
		Shared by TestPaymentPeriodAndSummary and TestPaymentFilters."""
		frappe.db.set_value("Collection and Payment", name, "status", status)
		frappe.db.commit()

	def test_missing_company_resolves_the_user_default(self):
		# NB: the resolver reads the lowercase "company" default key
		# (`frappe.defaults.get_user_default("company")`, matching the DocType
		# fieldname) -- setting "Company" here would silently miss it.
		frappe.defaults.set_user_default("company", self.company)
		resp = self._create_payment(self._payment_body())
		data = _expect_success(resp, "create_collection_payment")
		self.assertEqual(data["company"], self.company)

	def test_forbidden_company_returns_422_with_field(self):
		bogus_company = f"{TEST_PREFIX}-NO-SUCH-COMPANY-{uuid.uuid4()}"
		resp = self._create_payment(self._payment_body(company=bogus_company))
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
		resp = self._create_payment(self._payment_body())
		if resp["success"]:
			# A configured Global Defaults default_company still resolves it --
			# that's not something a test may reconfigure on a real site.
			self.skipTest("test site resolves a global default Company despite no user default")
		self.assertEqual(resp["error"]["code"], "validation_error")
		self.assertIn("company", resp["error"]["fields"])
		self.assertEqual(frappe.local.response.get("http_status_code"), 422)

	def test_payment_replay_does_not_duplicate(self):
		frappe.defaults.set_user_default("company", self.company)
		body = self._payment_body()

		first = _expect_success(self._create_payment(body), "create_collection_payment")
		before = frappe.db.count("Collection and Payment")

		second = _expect_success(self._create_payment(body), "create_collection_payment (replay)")
		after = frappe.db.count("Collection and Payment")

		self.assertEqual(second["name"], first["name"])
		self.assertEqual(before, after, "replaying the same payment key created a duplicate")


class TestPaymentPeriodAndSummary(TestPaymentCompany):
	"""Inherits TestPaymentCompany's Mode of Payment / company fixtures and
	_payment_body()/_create_payment() helpers -- these are period/summary-
	specific tests only, not a rerun of the company-resolution ones above."""

	def _get_payments(self, **kw):
		_set_get_request()
		return payment_api.list_collection_payments(**kw)

	def test_default_period_is_today_in_the_site_timezone(self):
		resp = _expect_success(self._get_payments(page_size=1), "list_collection_payments")
		today_str = frappe.utils.today()
		self.assertEqual(resp["period"]["from_date"], today_str)
		self.assertEqual(resp["period"]["to_date"], today_str)
		self.assertTrue(resp["period"]["timezone"])

	def test_approved_payment_is_counted_in_totals_with_the_correct_direction(self):
		frappe.defaults.set_user_default("company", self.company)
		pay = _expect_success(self._create_payment(self._payment_body()), "create (Pay)")
		self._force_status(pay["name"], "Approved")

		receive_body = self._payment_body()
		receive_body["detail"]["payment_type"] = "Receive"
		receive_body["detail"]["amount"] = 25
		receive = _expect_success(self._create_payment(receive_body), "create (Receive)")
		self._force_status(receive["name"], "Approved")

		today_str = frappe.utils.today()
		resp = _expect_success(
			self._get_payments(from_date=today_str, to_date=today_str, page_size=1), "list_collection_payments"
		)
		totals = resp["summary"]["totals"]
		self.assertEqual(totals["basis"], "approved")
		self.assertGreaterEqual(totals["outflow"], 10)  # the "Pay" leg
		self.assertGreaterEqual(totals["inflow"], 25)  # the "Receive" leg

	def test_pending_and_rejected_are_excluded_from_financial_totals(self):
		frappe.defaults.set_user_default("company", self.company)
		today_str = frappe.utils.today()

		before = _expect_success(
			self._get_payments(from_date=today_str, to_date=today_str, page_size=1), "list_collection_payments (before)"
		)

		pending_body = self._payment_body()
		pending_body["detail"]["amount"] = 999999  # would obviously skew totals if wrongly included
		pending = _expect_success(self._create_payment(pending_body), "create (left pending)")
		# Deliberately NOT forced to Approved -- whatever the default status
		# is, it must not be "approved" per _normalize_payment_status.

		rejected_body = self._payment_body()
		rejected_body["detail"]["amount"] = 888888
		rejected = _expect_success(self._create_payment(rejected_body), "create (rejected)")
		self._force_status(rejected["name"], "Rejected")

		after = _expect_success(
			self._get_payments(from_date=today_str, to_date=today_str, page_size=1), "list_collection_payments (after)"
		)

		self.assertEqual(after["summary"]["totals"], before["summary"]["totals"])
		self.assertEqual(after["summary"]["pending"], before["summary"]["pending"] + 1)
		self.assertEqual(after["summary"]["rejected"], before["summary"]["rejected"] + 1)
		self.assertEqual(after["summary"]["approved"], before["summary"]["approved"])

	def test_cross_user_gets_403_not_fake_zero_summary(self):
		frappe.defaults.set_user_default("company", self.company)
		self._create_payment(self._payment_body())  # as Administrator

		frappe.set_user(self.other_user)
		try:
			resp = self._get_payments(page_size=1)
		finally:
			frappe.set_user("Administrator")

		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "permission_denied")
		self.assertEqual(frappe.local.response.get("http_status_code"), 403)


class TestPaymentFilters(TestPaymentCompany):
	"""Search / party / company / payment-type filters (Phase 02 increment 5:
	closing the "rows vs counters can disagree" gap for Transactions -- see
	TestInvoicePeriodAndSummary for the equivalent invoice coverage).

	test_cross_user_search_reveals_no_rows_counts_or_totals covers BOTH "a
	child-row match under an unauthorized parent is never returned" and
	"cross-user search cannot reveal rows/counts/totals" via the same
	zero-permission other_user mechanism used elsewhere in this file -- a
	more granular "some records authorized, some not via User Permissions"
	scenario would need this site's actual permission configuration, which
	cannot be fabricated generically here."""

	def _get_payments(self, **kw):
		_set_get_request()
		return payment_api.list_collection_payments(**kw)

	def _create_payment_as_admin(self, **overrides) -> dict:
		frappe.defaults.set_user_default("company", self.company)
		body = self._payment_body()
		body["detail"].update(overrides)
		return _expect_success(self._create_payment(body), "create_collection_payment")

	def test_search_changes_rows_and_summary_consistently(self):
		# party_name is always resolved server-side from the selected party
		# (create_collection_payment ignores whatever the client sends for
		# it) -- so search on the canonical value it actually persisted,
		# not a client-supplied one that production correctly discards.
		today_str = frappe.utils.today()
		matching = self._create_payment_as_admin(party_type="Customer", party=self.customer)
		non_matching = self._create_payment_as_admin(party_type="Supplier", party=self.supplier)

		search_term = frappe.db.get_value(
			"Collection and Payment Details", {"parent": matching["name"]}, "party_name"
		)
		self.assertTrue(search_term, "the created payment must have a persisted party_name to search on")

		resp = _expect_success(
			self._get_payments(from_date=today_str, to_date=today_str, search=search_term, page_size=10),
			"list_collection_payments (search)",
		)
		names = [row["name"] for row in resp["payments"]]
		self.assertIn(matching["name"], names)
		self.assertNotIn(non_matching["name"], names)
		self.assertEqual(resp["summary"]["total"], len(names), "summary must match the searched, not the full, set")

	def test_party_type_and_party_change_rows_and_summary_consistently(self):
		today_str = frappe.utils.today()
		mine = self._create_payment_as_admin(party_type="Customer", party=self.customer, party_name=self.customer)

		resp = _expect_success(
			self._get_payments(
				from_date=today_str, to_date=today_str, party_type="Customer", party=self.customer, page_size=10
			),
			"list_collection_payments (party filter)",
		)
		self.assertTrue(all(row["party"] == self.customer for row in resp["payments"]))
		self.assertGreaterEqual(len(resp["payments"]), 1)
		self.assertIn(mine["name"], [row["name"] for row in resp["payments"]])
		self.assertEqual(resp["summary"]["total"], len(resp["payments"]))

	def test_company_and_payment_type_change_rows_and_summary_consistently(self):
		today_str = frappe.utils.today()
		pay_leg = self._create_payment_as_admin(payment_type="Pay")
		receive_body = self._payment_body()
		receive_body["detail"]["payment_type"] = "Receive"
		frappe.defaults.set_user_default("company", self.company)
		self._create_payment(receive_body)

		resp = _expect_success(
			self._get_payments(
				from_date=today_str, to_date=today_str, company=self.company, payment_type="pay", page_size=10
			),
			"list_collection_payments (payment_type filter)",
		)
		self.assertTrue(all(row["payment_type"] == "Pay" for row in resp["payments"]))
		self.assertIn(pay_leg["name"], [row["name"] for row in resp["payments"]])
		self.assertEqual(resp["summary"]["total"], len(resp["payments"]))

	def test_pagination_does_not_change_the_summary_under_a_filter(self):
		today_str = frappe.utils.today()
		for _i in range(3):
			self._create_payment_as_admin()

		page1 = _expect_success(
			self._get_payments(from_date=today_str, to_date=today_str, company=self.company, page=1, page_size=1),
			"list_collection_payments p1",
		)
		page2 = _expect_success(
			self._get_payments(from_date=today_str, to_date=today_str, company=self.company, page=2, page_size=1),
			"list_collection_payments p2",
		)
		self.assertEqual(page1["summary"], page2["summary"])
		self.assertGreaterEqual(page1["summary"]["total"], 3)

	def test_active_status_filter_is_ignored_only_for_the_summary(self):
		today_str = frappe.utils.today()
		approved = self._create_payment_as_admin()
		self._force_status(approved["name"], "Approved")
		pending = self._create_payment_as_admin()  # left at its default (non-approved) status

		resp = _expect_success(
			self._get_payments(
				from_date=today_str, to_date=today_str, company=self.company, status="pending", page_size=10
			),
			"list_collection_payments (status=pending)",
		)
		row_names = [row["name"] for row in resp["payments"]]
		self.assertIn(pending["name"], row_names)
		self.assertNotIn(approved["name"], row_names, "the pending row filter must exclude the approved payment")
		# But the summary (status-card counts) must still see BOTH -- the
		# active status filter is excluded only from the summary scope, not
		# from the company filter, which must remain applied.
		self.assertGreaterEqual(resp["summary"]["approved"], 1)
		self.assertGreaterEqual(resp["summary"]["pending"], 1)

	def test_cross_user_search_reveals_no_rows_counts_or_totals(self):
		distinct_party_name = f"{TEST_PREFIX}-CROSS-USER-{uuid.uuid4().hex[:8]}"
		self._create_payment_as_admin(party_name=distinct_party_name)

		frappe.set_user(self.other_user)
		try:
			resp = self._get_payments(search=distinct_party_name, page_size=10)
		finally:
			frappe.set_user("Administrator")

		# self.other_user has zero document permission on Collection and
		# Payment -- a search/filter must not weaken that into a 200 with an
		# empty-but-successful envelope (which could be mistaken for "no
		# matches" rather than "not authorized"); it must still be a 403.
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "permission_denied")
		self.assertEqual(frappe.local.response.get("http_status_code"), 403)


class TestPaymentMovementTotals(TestPaymentCompany):
	"""Phase 02 increment 7: movement_totals/approved_totals alongside the
	pre-existing (unchanged) approved-only `totals`."""

	def _get_payments(self, **kw):
		_set_get_request()
		return payment_api.list_collection_payments(**kw)

	def _create_payment_as_admin(self, **overrides) -> dict:
		frappe.defaults.set_user_default("company", self.company)
		body = self._payment_body()
		body["detail"].update(overrides)
		return _expect_success(self._create_payment(body), "create_collection_payment")

	def test_pending_and_approved_are_both_included_in_movement_totals(self):
		today_str = frappe.utils.today()
		pending = self._create_payment_as_admin(payment_type="Receive", amount=40)
		approved = self._create_payment_as_admin(payment_type="Receive", amount=25)
		self._force_status(approved["name"], "Approved")

		resp = _expect_success(
			self._get_payments(from_date=today_str, to_date=today_str, company=self.company, page_size=10),
			"list_collection_payments",
		)
		movement = resp["summary"]["movement_totals"]
		self.assertEqual(movement["basis"], "active_recorded_movements")
		self.assertGreaterEqual(movement["inflow"], 65)  # pending's 40 + approved's 25

	def test_rejected_and_cancelled_are_excluded_from_movement_totals(self):
		today_str = frappe.utils.today()
		before = _expect_success(
			self._get_payments(from_date=today_str, to_date=today_str, company=self.company, page_size=10),
			"list_collection_payments (before)",
		)
		rejected = self._create_payment_as_admin(payment_type="Receive", amount=999999)
		self._force_status(rejected["name"], "Rejected")

		after = _expect_success(
			self._get_payments(from_date=today_str, to_date=today_str, company=self.company, page_size=10),
			"list_collection_payments (after)",
		)
		self.assertEqual(after["summary"]["movement_totals"], before["summary"]["movement_totals"])

	def test_pay_and_receive_direction_in_movement_totals(self):
		today_str = frappe.utils.today()
		before = _expect_success(
			self._get_payments(from_date=today_str, to_date=today_str, company=self.company, page_size=10),
			"list_collection_payments (before)",
		)
		self._create_payment_as_admin(payment_type="Pay", amount=15)
		self._create_payment_as_admin(payment_type="Receive", amount=35)

		after = _expect_success(
			self._get_payments(from_date=today_str, to_date=today_str, company=self.company, page_size=10),
			"list_collection_payments (after)",
		)
		before_m, after_m = before["summary"]["movement_totals"], after["summary"]["movement_totals"]
		self.assertAlmostEqual(after_m.get("outflow", 0) - before_m.get("outflow", 0), 15)
		self.assertAlmostEqual(after_m.get("inflow", 0) - before_m.get("inflow", 0), 35)

	def test_movement_totals_respect_status_search_company_and_party_filters(self):
		today_str = frappe.utils.today()
		mine = self._create_payment_as_admin(
			party_type="Customer", party=self.customer, payment_type="Receive", amount=44
		)
		self._force_status(mine["name"], "Approved")

		resp = _expect_success(
			self._get_payments(
				from_date=today_str,
				to_date=today_str,
				company=self.company,
				party_type="Customer",
				party=self.customer,
				status="approved",
				page_size=10,
			),
			"list_collection_payments (filtered)",
		)
		self.assertGreaterEqual(resp["summary"]["movement_totals"]["inflow"], 44)
		self.assertGreaterEqual(resp["summary"]["approved_totals"]["inflow"], 44)


class TestPaymentDetailsUpdateDelete(TestPaymentCompany):
	"""Phase 02 increment 7: get_collection_payment_details /
	update_collection_payment / delete_collection_payment."""

	def _create_payment_as_admin(self, **overrides) -> dict:
		frappe.defaults.set_user_default("company", self.company)
		body = self._payment_body()
		body["detail"].update(overrides)
		return _expect_success(self._create_payment(body), "create_collection_payment")

	def _get_details(self, name: str):
		_set_get_request()
		return payment_api.get_collection_payment_details(name=name)

	def _full_detail(self, **overrides) -> dict:
		"""`detail` is a COMPLETE replacement on update -- every mandatory field
		(mode_of_payment included) must be sent every time."""
		detail = {
			"payment_type": "Receive",
			"party_type": "Customer",
			"party": self.customer,
			"amount": 10,
			"mode_of_payment": self.mode_of_payment,
			"description": "",
		}
		detail.update(overrides)
		return detail

	def _update(self, name: str, **kw) -> dict:
		body = {"name": name, **kw}
		_set_post_body(body)
		resp = payment_api.update_collection_payment(name=name)
		if resp.get("success"):
			self.track_log("payment.update", kw.get("client_request_id"))
		return resp

	def _delete(self, name: str, client_request_id: str | None = None) -> dict:
		body = {"name": name}
		if client_request_id is not None:
			body["client_request_id"] = client_request_id
		_set_post_body(body)
		resp = payment_api.delete_collection_payment(name=name)
		if resp.get("success"):
			self.track_log("payment.delete", client_request_id)
		return resp

	def test_get_details_returns_canonical_data_and_permissions(self):
		created = self._create_payment_as_admin()
		resp = _expect_success(self._get_details(created["name"]), "get_collection_payment_details")
		self.assertEqual(resp["name"], created["name"])
		self.assertEqual(resp["party"], self.customer)
		self.assertIn("modified", resp)
		self.assertTrue(resp["permissions"]["read"])
		self.assertTrue(resp["permissions"]["update"])  # freshly created -> pending -> editable
		self.assertTrue(resp["permissions"]["delete"])
		self.assertFalse(resp["permissions"]["locked"])

	def test_cross_user_get_details_is_403_not_404(self):
		created = self._create_payment_as_admin()
		frappe.set_user(self.other_user)
		try:
			resp = self._get_details(created["name"])
		finally:
			frappe.set_user("Administrator")
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "permission_denied")
		self.assertEqual(frappe.local.response.get("http_status_code"), 403)

	def test_successful_update_changes_fields_and_returns_confirmed_state(self):
		created = self._create_payment_as_admin(amount=10)
		resp = _expect_success(
			self._update(
				created["name"],
				base_modified=created["modified"],
				client_request_id=str(uuid.uuid4()),
				detail=self._full_detail(amount=77),
			),
			"update_collection_payment",
		)
		self.assertEqual(resp["amount"], 77)
		self.assertEqual(resp["mode_of_payment"], self.mode_of_payment)
		confirmed = _expect_success(self._get_details(created["name"]), "get_collection_payment_details")
		self.assertEqual(confirmed["amount"], 77)
		self.assertEqual(confirmed["mode_of_payment"], self.mode_of_payment)

	def test_update_recomputes_party_name_server_side(self):
		created = self._create_payment_as_admin()
		fabricated = f"NOT-THE-REAL-NAME-{uuid.uuid4().hex[:8]}"
		resp = _expect_success(
			self._update(
				created["name"],
				base_modified=created["modified"],
				client_request_id=str(uuid.uuid4()),
				detail=self._full_detail(amount=12, party_name=fabricated),  # party_name must be ignored
			),
			"update_collection_payment",
		)
		self.assertNotEqual(resp["party_name"], fabricated)

	def test_stale_base_modified_on_update_returns_409_with_current_state(self):
		created = self._create_payment_as_admin()
		resp = self._update(
			created["name"],
			base_modified="1999-01-01 00:00:00.000000",
			client_request_id=str(uuid.uuid4()),
			posting_date=frappe.utils.today(),
			detail=self._full_detail(),
		)
		self.assertFalse(resp["success"], f"expected a 409 conflict, got:\n{_dump(resp)}")
		self.assertEqual(resp["error"]["code"], "conflict")
		self.assertEqual(frappe.local.response.get("http_status_code"), 409)
		self.assertIn("name", resp["data"], "409 body must carry the current server state")

	def test_update_replay_returns_same_result_and_conflicting_payload_is_409(self):
		created = self._create_payment_as_admin()
		key = str(uuid.uuid4())
		first = _expect_success(
			self._update(
				created["name"],
				base_modified=created["modified"],
				client_request_id=key,
				posting_date=frappe.utils.today(),
				detail=self._full_detail(),
			),
			"update_collection_payment",
		)
		replay = _expect_success(
			self._update(
				created["name"],
				base_modified=created["modified"],
				client_request_id=key,
				posting_date=frappe.utils.today(),
				detail=self._full_detail(),
			),
			"update_collection_payment (replay)",
		)
		self.assertEqual(replay["modified"], first["modified"])

		conflict = self._update(
			created["name"],
			base_modified=created["modified"],
			client_request_id=key,
			posting_date=frappe.utils.add_days(frappe.utils.today(), -1),
			detail=self._full_detail(),
		)
		self.assertFalse(conflict["success"])
		self.assertEqual(conflict["error"]["code"], "idempotency_conflict")
		self.assertEqual(frappe.local.response.get("http_status_code"), 409)

	def test_unauthorized_user_update_and_delete_are_403(self):
		created = self._create_payment_as_admin()
		frappe.set_user(self.other_user)
		try:
			update_resp = self._update(
				created["name"],
				client_request_id=str(uuid.uuid4()),
				posting_date=frappe.utils.today(),
				detail=self._full_detail(),
			)
			delete_resp = self._delete(created["name"], client_request_id=str(uuid.uuid4()))
		finally:
			frappe.set_user("Administrator")
		for resp in (update_resp, delete_resp):
			self.assertFalse(resp["success"])
			self.assertEqual(resp["error"]["code"], "permission_denied")
			self.assertEqual(frappe.local.response.get("http_status_code"), 403)

	def test_approved_payment_cannot_be_updated_or_deleted(self):
		created = self._create_payment_as_admin()
		self._force_status(created["name"], "Approved")

		update_resp = self._update(
			created["name"],
			client_request_id=str(uuid.uuid4()),
			posting_date=frappe.utils.today(),
			detail=self._full_detail(),
		)
		self.assertFalse(update_resp["success"])
		self.assertEqual(update_resp["error"]["code"], "validation_error")
		self.assertEqual(frappe.local.response.get("http_status_code"), 422)

		delete_resp = self._delete(created["name"], client_request_id=str(uuid.uuid4()))
		self.assertFalse(delete_resp["success"])
		self.assertEqual(delete_resp["error"]["code"], "validation_error")
		self.assertEqual(frappe.local.response.get("http_status_code"), 422)

		details = _expect_success(self._get_details(created["name"]), "get_collection_payment_details")
		self.assertTrue(details["permissions"]["locked"])

	def test_delete_replay_is_success_but_a_fresh_id_on_a_gone_doc_is_404(self):
		created = self._create_payment_as_admin()
		key = str(uuid.uuid4())

		first = _expect_success(self._delete(created["name"], client_request_id=key), "delete_collection_payment")
		self.assertTrue(first["deleted"])

		replay = _expect_success(
			self._delete(created["name"], client_request_id=key), "delete_collection_payment (replay)"
		)
		self.assertTrue(replay["deleted"], "replay of the deleting request id must not 404")

		other = self._delete(created["name"], client_request_id=str(uuid.uuid4()))
		self.assertFalse(other["success"])
		self.assertEqual(other["error"]["code"], "not_found")
		self.assertEqual(frappe.local.response.get("http_status_code"), 404)

	def test_cross_user_update_and_delete_are_403_not_a_leak(self):
		created = self._create_payment_as_admin()
		frappe.set_user(self.other_user)
		try:
			details_resp = self._get_details(created["name"])
			update_resp = self._update(
				created["name"],
				client_request_id=str(uuid.uuid4()),
				posting_date=frappe.utils.today(),
				detail=self._full_detail(),
			)
			delete_resp = self._delete(created["name"], client_request_id=str(uuid.uuid4()))
		finally:
			frappe.set_user("Administrator")
		for resp in (details_resp, update_resp, delete_resp):
			self.assertFalse(resp["success"])
			self.assertEqual(resp["error"]["code"], "permission_denied")
			self.assertEqual(frappe.local.response.get("http_status_code"), 403)
		# The payment must still exist and be untouched -- confirmed as Administrator.
		still_there = _expect_success(self._get_details(created["name"]), "get_collection_payment_details")
		self.assertEqual(still_there["name"], created["name"])


class TestPaymentModeOfPaymentContract(TestPaymentCompany):
	"""`mode_of_payment` is mandatory on the live "Collection and Payment
	Details" DocType, so it is mandatory in this API's contract too -- for
	create AND update. Before this, omitting it turned into a DocType-level
	save error ("Row #1: Value missing for: Mode of Payment") instead of a
	clean 422."""

	def _get_details(self, name: str):
		_set_get_request()
		return payment_api.get_collection_payment_details(name=name)

	def _full_detail(self, **overrides) -> dict:
		detail = {
			"payment_type": "Receive",
			"party_type": "Customer",
			"party": self.customer,
			"amount": 10,
			"mode_of_payment": self.mode_of_payment,
			"description": "",
		}
		detail.update(overrides)
		return detail

	def _create_payment_as_admin(self, **overrides) -> dict:
		frappe.defaults.set_user_default("company", self.company)
		body = self._payment_body()
		body["detail"].update(overrides)
		return _expect_success(self._create_payment(body), "create_collection_payment")

	def _update(self, name: str, **kw) -> dict:
		body = {"name": name, **kw}
		_set_post_body(body)
		resp = payment_api.update_collection_payment(name=name)
		if resp.get("success"):
			self.track_log("payment.update", kw.get("client_request_id"))
		return resp

	@staticmethod
	def _log_status(scope: str, client_request_id: str):
		return frappe.db.get_value(
			LOG_DOCTYPE, _composite(frappe.session.user, scope, client_request_id), "status"
		)

	def test_create_without_mode_of_payment_is_422_and_creates_nothing(self):
		frappe.defaults.set_user_default("company", self.company)
		before = frappe.db.count("Collection and Payment")

		body = self._payment_body()
		body["detail"].pop("mode_of_payment", None)
		resp = self._create_payment(body)

		self.assertFalse(resp["success"], f"expected a 422, got:\n{_dump(resp)}")
		self.assertEqual(resp["error"]["code"], "validation_error")
		self.assertEqual(frappe.local.response.get("http_status_code"), 422)
		# Names the field so the client can show it inline at that input.
		self.assertIn("mode_of_payment", resp["error"]["fields"])
		self.assertEqual(frappe.db.count("Collection and Payment"), before, "nothing may be created")

	def test_create_with_a_blank_mode_of_payment_is_also_422(self):
		frappe.defaults.set_user_default("company", self.company)
		body = self._payment_body()
		body["detail"]["mode_of_payment"] = ""
		resp = self._create_payment(body)
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "validation_error")

	def test_create_with_an_unknown_mode_of_payment_is_422(self):
		frappe.defaults.set_user_default("company", self.company)
		body = self._payment_body()
		body["detail"]["mode_of_payment"] = f"{TEST_PREFIX}-NO-SUCH-MODE-{uuid.uuid4().hex[:8]}"
		resp = self._create_payment(body)
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "validation_error")
		self.assertEqual(frappe.local.response.get("http_status_code"), 422)

	def test_update_without_mode_of_payment_is_422_and_leaves_the_payment_untouched(self):
		created = self._create_payment_as_admin(amount=10)
		before = _expect_success(self._get_details(created["name"]), "get_collection_payment_details")

		detail = self._full_detail(amount=99)
		detail.pop("mode_of_payment")
		resp = self._update(
			created["name"],
			base_modified=created["modified"],
			client_request_id=str(uuid.uuid4()),
			detail=detail,
		)

		self.assertFalse(resp["success"], f"expected a 422, got:\n{_dump(resp)}")
		self.assertEqual(resp["error"]["code"], "validation_error")
		self.assertEqual(frappe.local.response.get("http_status_code"), 422)
		self.assertIn("mode_of_payment", resp["error"]["fields"])

		after = _expect_success(self._get_details(created["name"]), "get_collection_payment_details")
		self.assertEqual(after["amount"], before["amount"], "a rejected update must change nothing")
		self.assertEqual(after["mode_of_payment"], before["mode_of_payment"])
		self.assertEqual(after["modified"], before["modified"])

	def test_update_with_an_unknown_mode_of_payment_is_422(self):
		created = self._create_payment_as_admin()
		resp = self._update(
			created["name"],
			base_modified=created["modified"],
			client_request_id=str(uuid.uuid4()),
			detail=self._full_detail(
				mode_of_payment=f"{TEST_PREFIX}-NO-SUCH-MODE-{uuid.uuid4().hex[:8]}"
			),
		)
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "validation_error")
		self.assertEqual(frappe.local.response.get("http_status_code"), 422)

	def test_update_with_a_valid_mode_of_payment_succeeds_and_persists_it(self):
		created = self._create_payment_as_admin(amount=10)
		resp = _expect_success(
			self._update(
				created["name"],
				base_modified=created["modified"],
				client_request_id=str(uuid.uuid4()),
				detail=self._full_detail(amount=55),
			),
			"update_collection_payment",
		)
		self.assertEqual(resp["mode_of_payment"], self.mode_of_payment)
		confirmed = _expect_success(self._get_details(created["name"]), "get_collection_payment_details")
		self.assertEqual(confirmed["mode_of_payment"], self.mode_of_payment)
		self.assertEqual(confirmed["amount"], 55)

	def test_a_rejected_update_leaves_no_processing_or_done_request_log(self):
		"""run_idempotent reserves the key, then rolls the whole transaction
		back on failure -- a 422 must not strand a `processing` row that would
		make an honest retry with the same key look like a duplicate."""
		created = self._create_payment_as_admin()
		key = str(uuid.uuid4())

		detail = self._full_detail(amount=42)
		detail.pop("mode_of_payment")
		rejected = self._update(
			created["name"], base_modified=created["modified"], client_request_id=key, detail=detail
		)
		self.assertFalse(rejected["success"])
		self.assertIsNone(
			self._log_status("payment.update", key), "no log row may survive a failed update"
		)

		# The very same key must now work once the payload is complete.
		ok = _expect_success(
			self._update(
				created["name"],
				base_modified=created["modified"],
				client_request_id=key,
				detail=self._full_detail(amount=42),
			),
			"update_collection_payment (same key, fixed payload)",
		)
		self.assertEqual(ok["amount"], 42)
		self.assertEqual(self._log_status("payment.update", key), "done")

	def test_a_rejected_create_leaves_no_request_log_row(self):
		frappe.defaults.set_user_default("company", self.company)
		key = str(uuid.uuid4())
		body = self._payment_body()
		body["client_request_id"] = key
		body["detail"].pop("mode_of_payment", None)

		rejected = self._create_payment(body)
		self.assertFalse(rejected["success"])
		self.assertIsNone(
			self._log_status("payment.create", key), "no log row may survive a failed create"
		)

	def test_replay_and_base_modified_still_work_with_the_required_mode(self):
		created = self._create_payment_as_admin(amount=10)
		key = str(uuid.uuid4())
		detail = self._full_detail(amount=31)

		first = _expect_success(
			self._update(
				created["name"], base_modified=created["modified"], client_request_id=key, detail=detail
			),
			"update_collection_payment",
		)
		# A replay with the same key returns the stored result even though
		# base_modified is now stale.
		replay = _expect_success(
			self._update(
				created["name"], base_modified=created["modified"], client_request_id=key, detail=detail
			),
			"update_collection_payment (replay)",
		)
		self.assertEqual(replay["modified"], first["modified"])
		self.assertEqual(replay["amount"], 31)

		# A genuinely stale write with a FRESH key is still a 409.
		stale = self._update(
			created["name"],
			base_modified="1999-01-01 00:00:00.000000",
			client_request_id=str(uuid.uuid4()),
			detail=self._full_detail(amount=32),
		)
		self.assertFalse(stale["success"])
		self.assertEqual(stale["error"]["code"], "conflict")
		self.assertEqual(frappe.local.response.get("http_status_code"), 409)


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


class TestOAuthDiscoveryContract(ReliabilityTestCase):
	"""get_oauth_config against a real site. Native PKCE itself is VERIFIED
	LIVE by scripts/oauth_pkce_probe.py; these guard the discovery contract
	the clients read before login."""

	def _get_config(self, platform):
		_set_get_request()
		return user_api.get_oauth_config(platform=platform)

	def test_discovery_answers_for_every_allowed_platform(self):
		for platform in ("android", "ios", "web"):
			data = _expect_success(self._get_config(platform), f"get_oauth_config({platform})")
			self.assertEqual(data["platform"], platform)
			self.assertTrue(data["issuer"].startswith("http"))
			self.assertTrue(data["token_endpoint"].endswith("oauth2.get_token"))
			self.assertTrue(data["authorization_endpoint"].endswith("oauth2.authorize"))
			self.assertTrue(data["revoke_endpoint"].endswith("oauth2.revoke_token"))
			self.assertEqual(data["code_challenge_method"], "S256")
			self.assertTrue(data["pkce_required"])
			self.assertEqual(data["scopes_supported"], "openid all")

	def test_an_unsupported_platform_is_422_naming_the_field(self):
		for platform in ("desktop", "", "windows"):
			resp = self._get_config(platform)
			self.assertFalse(resp["success"], f"expected 422 for {platform!r}:\n{_dump(resp)}")
			self.assertEqual(resp["error"]["code"], "validation_error")
			self.assertIn("platform", resp["error"]["fields"])
			self.assertEqual(frappe.local.response.get("http_status_code"), 422)

	def _override_conf(self, **values):
		"""Temporarily override site config IN MEMORY for one test.

		`frappe.conf` is the in-process view; nothing is written to
		site_config.json, and the original values are restored on teardown even
		if the test fails.
		"""
		missing = object()
		for key, value in values.items():
			previous = frappe.conf.get(key, missing)

			def restore(key=key, previous=previous):
				if previous is missing:
					frappe.conf.pop(key, None)
				else:
					frappe.conf[key] = previous

			self.addCleanup(restore)
			frappe.conf[key] = value

	def test_web_never_hands_the_browser_a_client_id(self):
		data = _expect_success(self._get_config("web"), "get_oauth_config(web)")
		self.assertEqual(data["status"], "bff_required")
		self.assertIsNone(data["client_id"])
		self.assertIsNone(data["redirect_uri"])
		self.assertFalse(data["oauth_configured"])
		self.assertFalse(data["oauth_enabled"])

	def test_web_is_bff_required_across_every_configuration(self):
		"""The web answer must not depend on site config at all: the
		architecture guard outranks the runtime kill switch, because the kill
		switch is a rollback for a flow that is allowed to run and web's is not.

		Each row overrides `frappe.conf` in memory only and is restored on
		teardown; site_config.json is never touched.
		"""
		matrix = {
			"flag false": {"pamper_oauth_web_enabled": False},
			"flag true": {"pamper_oauth_web_enabled": True},
			"client id present": {"pamper_oauth_web_client_id": "web-client-id-placeholder"},
			"redirect present": {"pamper_oauth_web_redirect_uri": "https://app.example/callback"},
			"fully configured": {
				"pamper_oauth_web_enabled": True,
				"pamper_oauth_web_client_id": "web-client-id-placeholder",
				"pamper_oauth_web_redirect_uri": "https://app.example/callback",
			},
		}
		for case, overrides in matrix.items():
			with self.subTest(case=case):
				self._override_conf(**overrides)
				resp = self._get_config("web")
				data = _expect_success(resp, f"get_oauth_config(web) [{case}]")
				self.assertEqual(data["status"], "bff_required")
				self.assertIsNone(data["client_id"])
				self.assertIsNone(data["redirect_uri"])
				self.assertFalse(data["oauth_configured"])
				self.assertFalse(data["oauth_enabled"])
				rendered = json.dumps(resp, default=str)
				self.assertNotIn("web-client-id-placeholder", rendered)
				self.assertNotIn("app.example", rendered)

	def test_web_is_bff_required_whether_or_not_legacy_login_is_allowed(self):
		for allowed in (True, False):
			with self.subTest(legacy_login_allowed=allowed):
				self._override_conf(pamper_allow_legacy_api_key_login=allowed)
				data = _expect_success(self._get_config("web"), "get_oauth_config(web)")
				self.assertEqual(data["status"], "bff_required")
				self.assertEqual(data["legacy_login_allowed"], allowed)
				self.assertIsNone(data["client_id"])

	def test_no_secret_ever_appears_in_the_discovery_response(self):
		for platform in ("android", "ios", "web"):
			rendered = json.dumps(self._get_config(platform), default=str).lower()
			self.assertNotIn("secret", rendered)
			self.assertNotIn("api_key", rendered)

	def test_discovery_is_readable_before_login(self):
		"""It is consumed by a Guest on the login screen."""
		frappe.set_user("Guest")
		try:
			resp = self._get_config("android")
		finally:
			frappe.set_user("Administrator")
		self.assertTrue(resp["success"], _dump(resp))

	def test_a_request_cannot_substitute_its_own_redirect_uri(self):
		"""The endpoint takes only `platform`; the redirect URI comes from site
		config. Frappe matches redirect URIs exactly (frappe/oauth.py:29-42), so
		a request-controlled value would be an open-redirect hole."""
		_set_get_request()
		frappe.local.form_dict = frappe._dict(
			{"platform": "android", "redirect_uri": "https://evil.example/steal"}
		)
		resp = user_api.get_oauth_config(platform="android")
		data = _expect_success(resp, "get_oauth_config(android)")
		if data["redirect_uri"]:
			self.assertNotIn("evil.example", data["redirect_uri"])

	def test_configured_platform_reports_ready_with_a_non_cleartext_redirect(self):
		"""Skips unless this site actually has the android client configured —
		it asserts the shape of a READY answer without requiring the fixture."""
		data = _expect_success(self._get_config("android"), "get_oauth_config(android)")
		if data["status"] != "ready":
			self.skipTest(f"android OAuth not configured on this site (status={data['status']})")
		self.assertTrue(data["oauth_configured"])
		self.assertTrue(data["client_id"])
		self.assertFalse(data["redirect_uri"].lower().startswith("http://"))
		self.assertNotIn("*", data["redirect_uri"])

	def test_the_runtime_kill_switch_is_reported_per_native_platform(self):
		"""Server-side rollback: flipping pamper_oauth_<platform>_enabled off
		disables OAuth for every client with no new build. Absent == disabled.

		Android and iOS only — `web` is refused one layer earlier, by
		architecture, so pamper_oauth_web_enabled has no effect on it.
		"""
		for platform in ("android", "ios"):
			data = _expect_success(self._get_config(platform), f"get_oauth_config({platform})")
			self.assertIn("oauth_enabled", data)
			self.assertEqual(
				data["oauth_enabled"],
				bool(frappe.conf.get(f"pamper_oauth_{platform}_enabled", False)),
			)
			if not data["oauth_enabled"]:
				# A disabled platform must hand out nothing a client could start with.
				self.assertEqual(data["status"], "disabled")
				self.assertIsNone(data["client_id"])
				self.assertIsNone(data["redirect_uri"])
				self.assertFalse(data["oauth_configured"])

	def test_the_kill_switch_can_disable_a_configured_native_platform(self):
		"""The other half of the ordering: inside android/ios the kill switch
		comes before configuration, so a configured platform still reports
		`disabled` when it is off."""
		for platform in ("android", "ios"):
			with self.subTest(platform=platform):
				self._override_conf(**{f"pamper_oauth_{platform}_enabled": False})
				data = _expect_success(self._get_config(platform), f"get_oauth_config({platform})")
				self.assertEqual(data["status"], "disabled")
				self.assertFalse(data["oauth_enabled"])
				self.assertIsNone(data["client_id"])
				self.assertIsNone(data["redirect_uri"])

	def test_status_is_one_of_the_documented_values(self):
		allowed = {"disabled", "ready", "not_configured", "misconfigured", "bff_required"}
		for platform in ("android", "ios", "web"):
			data = _expect_success(self._get_config(platform), f"get_oauth_config({platform})")
			self.assertIn(data["status"], allowed)
		# And web's is always the same one.
		web = _expect_success(self._get_config("web"), "get_oauth_config(web)")
		self.assertEqual(web["status"], "bff_required")

	def test_legacy_login_flag_is_reported_and_still_enabled(self):
		"""Phase 03 must not disable legacy login."""
		data = _expect_success(self._get_config("android"), "get_oauth_config(android)")
		self.assertIn("legacy_login_allowed", data)
		self.assertEqual(
			data["legacy_login_allowed"],
			bool(frappe.conf.get("pamper_allow_legacy_api_key_login", False)),
		)


class TestEnvelope(ReliabilityTestCase):
	def test_guest_is_401_not_authenticated(self):
		"""Unauthenticated (Guest) -> AUTH_REQUIRED / 401. get_invoices() is now
		@mobile_api-wrapped, so this used to escape as a raw AuthenticationError
		instead of a structured envelope."""
		frappe.set_user("Guest")
		try:
			_set_get_request()
			resp = invoice_api.get_invoices()
		finally:
			frappe.set_user("Administrator")
		self.assertFalse(resp["success"])
		self.assertEqual(resp["error"]["code"], "not_authenticated")
		self.assertEqual(frappe.local.response.get("http_status_code"), 401)

	def test_authenticated_but_forbidden_is_403_permission_denied(self):
		"""A distinct scenario from the Guest/401 case above: an authenticated
		user who genuinely lacks read permission on Invoice Form."""
		frappe.set_user(self.other_user)
		try:
			has_read = frappe.has_permission(doctype="Invoice Form", ptype="read")
		finally:
			frappe.set_user("Administrator")
		if has_read:
			self.skipTest(
				f"'{self.other_user}' (test-only role) can still read Invoice Form on this "
				"site's permission configuration -- the 403 path cannot be exercised "
				"without reconfiguring real site permissions"
			)

		frappe.set_user(self.other_user)
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
#  CORS header safety (the earlier real-bench regression)                    #
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
