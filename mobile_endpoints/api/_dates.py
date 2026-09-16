"""Shared date-range resolution/validation for list endpoints that return a
period-scoped summary alongside their rows (invoice list, transaction list).

Both callers accept the same contract: `from_date`/`to_date` as ISO
(YYYY-MM-DD) strings, defaulting to "today" in the site's configured
timezone when neither is given -- this is the one place that default lives,
so both endpoints stay consistent by construction.
"""

from __future__ import annotations

import frappe
from frappe import _
from frappe.utils import cstr, getdate

# Bounded custom-range limit -- protects the server from an unbounded scan
# (e.g. "from_date=2000-01-01") over a busy site's history.
MAX_RANGE_DAYS = 366


class DateRangeError(frappe.ValidationError):
	"""Invalid / reversed / too-wide date range. A `frappe.ValidationError`
	subclass so `@mobile_api` maps it to a 422 like any other validation
	failure -- no special-casing needed in the envelope layer."""


def site_timezone() -> str:
	"""Best-effort site timezone label for the `period.timezone` response
	field. Never raises -- this is informational, not used for filtering
	(`posting_date` is a plain Date field with no time-of-day component)."""
	try:
		return cstr(frappe.utils.get_system_timezone())
	except Exception:
		try:
			return cstr(frappe.db.get_default("time_zone")) or "UTC"
		except Exception:
			return "UTC"


def resolve_period(from_date: str | None, to_date: str | None) -> tuple[str, str]:
	"""Validate an inbound ISO date range and return it as `(from_date,
	to_date)` ISO strings. Defaults to "today" (site timezone, via
	`frappe.utils.today()`) when neither bound is given -- this is the
	server-side source of truth for the "Today" default so it holds
	regardless of which client calls it."""
	today_str = frappe.utils.today()

	if not from_date and not to_date:
		return today_str, today_str

	def _parse(value, label):
		if not value:
			return None
		try:
			return getdate(value)
		except Exception as exc:
			raise DateRangeError(
				_("Invalid {0}: must be an ISO date (YYYY-MM-DD)").format(label)
			) from exc

	start = _parse(from_date, _("from_date")) or getdate(today_str)
	end = _parse(to_date, _("to_date")) or getdate(today_str)

	if start > end:
		raise DateRangeError(_("from_date must not be after to_date"))

	if (end - start).days > MAX_RANGE_DAYS:
		raise DateRangeError(
			_("The selected period is too wide (maximum {0} days)").format(MAX_RANGE_DAYS)
		)

	return cstr(start), cstr(end)
