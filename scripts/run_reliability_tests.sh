#!/usr/bin/env bash
#
# Verification wrapper for mobile_endpoints.tests.test_reliability.
#
# Observed on the real bench: `bench --site <site> run-tests ...` can print
#     FAILED (failures=12, errors=3, skipped=1)
# and still exit 0. Never trust the process exit code alone -- this script
# captures the full output and parses unittest's own summary line instead,
# and guarantees `allow_tests` is reset to False afterwards (via a trap) no
# matter how the run ends: success, failure, or an interrupted script.
#
# Usage:
#   ./scripts/run_reliability_tests.sh <site> [bench_dir]
#
# Examples:
#   ./scripts/run_reliability_tests.sh pos
#   ./scripts/run_reliability_tests.sh pos /home/frappe/frappe-bench
#
# Exit code: 0 only when unittest's final line is exactly `OK` (optionally
# with a parenthetical, e.g. `OK (skipped=1)`) and no traceback was printed
# despite that. Non-zero otherwise -- including when the summary line simply
# cannot be found, which is treated as a failure rather than a pass.

set -uo pipefail

SITE="${1:?usage: run_reliability_tests.sh <site> [bench_dir]}"
BENCH_DIR="${2:-$HOME/frappe-bench}"
LOG_FILE="$(mktemp -t mep_reliability_XXXXXX.log)"

if [[ ! -d "$BENCH_DIR" ]]; then
	echo "FAIL: bench directory not found: $BENCH_DIR" >&2
	echo "      pass it explicitly: $0 $SITE /path/to/frappe-bench" >&2
	exit 1
fi

cleanup() {
	echo >&2
	echo "Resetting allow_tests=False on '$SITE' ..." >&2
	if ! ( cd "$BENCH_DIR" && bench --site "$SITE" set-config allow_tests False --parse ) >&2; then
		echo "WARNING: could not reset allow_tests automatically." >&2
		echo "         Reset it manually: bench --site $SITE set-config allow_tests False --parse" >&2
	fi
}
trap cleanup EXIT

cd "$BENCH_DIR"
bench --site "$SITE" set-config allow_tests True --parse

bench --site "$SITE" run-tests --app mobile_endpoints \
	--module mobile_endpoints.tests.test_reliability 2>&1 | tee "$LOG_FILE"

echo
echo "Full output saved to: $LOG_FILE"

# unittest's own summary is always the LAST thing it prints, flush left, and
# is one of exactly two shapes:
#   OK
#   OK (skipped=3)
#   FAILED (failures=9, errors=8)
#   FAILED (errors=3, skipped=1)
# Anchor strictly on that shape instead of grepping the whole log for the
# substrings "Error"/"FAILED" -- a test named
# test_forbidden_company_returns_422_with_field, or a docstring, would
# otherwise produce a false positive/negative.
SUMMARY_LINE="$(grep -E '^(OK|FAILED)(\s\(.*\))?[[:space:]]*$' "$LOG_FILE" | tail -n1)"

if [[ -z "$SUMMARY_LINE" ]]; then
	echo "FAIL: no unittest summary line (OK / FAILED) found in the output." >&2
	echo "      Treating this as a failure -- inspect $LOG_FILE." >&2
	exit 1
fi

if [[ "$SUMMARY_LINE" == FAILED* ]]; then
	echo "FAIL: unittest reported: $SUMMARY_LINE" >&2
	exit 1
fi

if grep -qE '^Traceback \(most recent call last\):' "$LOG_FILE"; then
	echo "FAIL: a traceback was printed even though the summary said OK -- inspect $LOG_FILE." >&2
	exit 1
fi

echo "PASS: $SUMMARY_LINE"
exit 0
