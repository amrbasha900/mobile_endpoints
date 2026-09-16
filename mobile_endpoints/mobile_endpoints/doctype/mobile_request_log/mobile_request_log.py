# Copyright (c) 2026, mobile_endpoints and contributors
# For license information, please see license.txt

from frappe.model.document import Document


class MobileRequestLog(Document):
	"""Idempotency ledger for money-creating mobile POSTs.

	One row per `client_request_id`. `status` moves processing -> done once the
	underlying document is created and its response is stored in `response_json`.
	"""

	pass
