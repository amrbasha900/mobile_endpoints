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

	# -- convenience wrappers: call the real endpoint the way a real HTTP
	#    request would (Frappe's dispatcher binds body fields matching the
	#    signature as kwargs) AND register cleanup --

	def create_invoice(self, client_request_id, qty=2, price=50) -> dict:
		body = {
			"posting_date": frappe.utils.today(),
			"supplier": self.supplier,
			"items": [{"item_code": self.item_code, "qty": qty, "price": price}],
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
		data = {"items": items}
		full_body = {"name": name, "data": data, "base_modified": base_modified}
		if client_request_id is not None:
			full_body["client_request_id"] = client_request_id
		_set_post_body(full_body)
		# name/data ARE in update_invoice's signature -- a real dispatched call
		# binds them directly; base_modified/client_request_id are not, and
		# reach the handler only via _request_meta() reading the raw body above.
		return invoice_api.update_invoice(name=name, data=data)

	def submit_invoice(self, name: str, client_request_id=None) -> dict:
		body = {"name": name}
		if client_request_id is not None:
			body["client_request_id"] = client_request_id
		_set_post_body(body)
		return invoice_api.submit_invoice(name=name)

	def delete_invoice(self, name: str, client_request_id=None) -> dict:
		body = {"name": name}
		if client_request_id is not None:
			body["client_request_id"] = client_request_id
		_set_post_body(body)
		return invoice_api.delete_invoice(name=name)


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
		self.track_log("invoice.submit", key)
		# Different scope -> different composite key -> the submit is NOT treated
		# as a replay of the create.
		data = _expect_success(submitted, "submit_invoice")
		self.assertEqual(data["name"], created)


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
		self.track_log("invoice.update", key)
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
		self.track_log("invoice.delete", key)
		self.assertTrue(first["deleted"])

		replay = _expect_success(self.delete_invoice(created, client_request_id=key), "delete_invoice (replay)")
		self.assertTrue(replay["deleted"], "replay of the deleting request id must not 404")

		other = self.delete_invoice(created, client_request_id=str(uuid.uuid4()))
		self.assertFalse(other["success"])
		self.assertEqual(other["error"]["code"], "not_found")
		self.assertEqual(frappe.local.response.get("http_status_code"), 404)


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
