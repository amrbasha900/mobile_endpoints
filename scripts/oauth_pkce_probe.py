#!/usr/bin/env python3
"""Live OAuth2 + PKCE compatibility probe for a NATIVE (public) client.

Phase 03 increment 1. This answers exactly one question:

    Can Frappe 15.86.0 complete an Authorization Code + PKCE (S256) exchange
    for a native app when the token request carries NO Frappe session cookie
    and NO client secret?

Reading the source is not proof. `frappe/oauth.py:97-134` shows
`authenticate_client()` comparing a browser `user_id` cookie instead of a
client secret, so whether oauthlib routes a public client through it (fail) or
through `authenticate_client_id()` (pass) has to be observed against a running
site.

SAFETY RULES BUILT INTO THIS SCRIPT
  * It never creates, edits or deletes anything on the site. The only writes
    are the ones the OAuth server itself performs when issuing/revoking a
    token for the test client.
  * It never prints, logs or writes to disk: the authorization code, the code
    verifier/challenge secret material, access token, refresh token, client
    secret, or any Cookie. Every report line is redacted by construction.
  * The authorization code is read through a hidden prompt, so it never
    reaches shell history or the process argument list.
  * Token/refresh/revoke requests are sent with an opener that has no cookie
    jar, and the request builders below refuse to attach a Cookie header or a
    client_secret at all.
  * No retries on token/refresh/revoke — a repeated code exchange would muddy
    the very result we are measuring.

USAGE: see docs/OAUTH-PKCE-PROBE.md in this repository.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

# --- constants ---------------------------------------------------------------

AUTHORIZE_PATH = "/api/method/frappe.integrations.oauth2.authorize"
TOKEN_PATH = "/api/method/frappe.integrations.oauth2.get_token"
REVOKE_PATH = "/api/method/frappe.integrations.oauth2.revoke_token"
WHOAMI_PATH = "/api/method/frappe.auth.get_logged_user"

# RFC 7636 §4.1: 43..128 characters from the unreserved set.
VERIFIER_MIN_LEN = 43
VERIFIER_MAX_LEN = 128
UNRESERVED_RE = re.compile(r"^[A-Za-z0-9\-._~]+$")

DEFAULT_SCOPE = "openid all"
DEFAULT_TIMEOUT = 20

# Keys whose VALUES must never be rendered, whatever a server sends back.
SECRET_KEYS = frozenset(
    {
        "access_token",
        "refresh_token",
        "code",
        "code_verifier",
        "code_challenge",
        "client_secret",
        "id_token",
        "authorization",
        "cookie",
        "set-cookie",
        "password",
        "pwd",
    }
)


# --- PKCE primitives (pure, unit-tested) -------------------------------------


def generate_code_verifier(num_bytes: int = 64) -> str:
    """A CSPRNG verifier in the RFC 7636 unreserved charset.

    `token_urlsafe` emits [A-Za-z0-9_-], a subset of the unreserved set, so the
    result needs no translation. 64 bytes -> 86 chars, inside 43..128.
    """
    verifier = secrets.token_urlsafe(num_bytes)
    return verifier[:VERIFIER_MAX_LEN]


def code_challenge_s256(verifier: str) -> str:
    """base64url(SHA256(verifier)) with padding stripped — RFC 7636 §4.2.

    Mirrors Frappe's own comparison (`frappe/oauth.py:169-176`), which builds
    the same string and compares it to the stored challenge.
    """
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def generate_state(num_bytes: int = 32) -> str:
    return secrets.token_urlsafe(num_bytes)


def verifier_is_wellformed(verifier: str) -> bool:
    return (
        VERIFIER_MIN_LEN <= len(verifier) <= VERIFIER_MAX_LEN
        and bool(UNRESERVED_RE.match(verifier))
    )


# --- URL building / callback parsing (pure, unit-tested) ---------------------


def build_authorize_url(
    *,
    base_url: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
    scope: str = DEFAULT_SCOPE,
) -> str:
    """The exact authorization request. `redirect_uri` must match the value
    registered on the OAuth Client character for character — Frappe compares by
    exact membership (`frappe/oauth.py:29-42`)."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{base_url.rstrip('/')}{AUTHORIZE_PATH}?{urllib.parse.urlencode(params)}"


class CallbackError(Exception):
    """The callback URL could not be used. Message is always redacted."""


def parse_callback(callback_url: str, *, expected_state: str) -> str:
    """Return the authorization code from a pasted callback URL.

    Validates `state` BEFORE the code is handed back, so a mismatched callback
    can never reach a token request. Raises with a message that never contains
    the code or the state values.
    """
    raw = (callback_url or "").strip()
    if not raw:
        raise CallbackError("empty callback URL")

    parsed = urllib.parse.urlsplit(raw)
    if not parsed.query and not parsed.fragment:
        raise CallbackError("callback URL carries no query string")

    query = urllib.parse.parse_qs(parsed.query or parsed.fragment)

    if "error" in query:
        # Error CODE is a fixed OAuth vocabulary and safe; the description is not.
        raise CallbackError(f"authorization server returned error={query['error'][0][:64]!r}")

    state_values = query.get("state") or []
    if not state_values:
        raise CallbackError("callback URL has no state parameter")
    if not secrets.compare_digest(state_values[0], expected_state):
        raise CallbackError("STATE MISMATCH — refusing to exchange this code")

    code_values = query.get("code") or []
    if not code_values or not code_values[0]:
        raise CallbackError("callback URL has no authorization code")

    return code_values[0]


# --- request builders (pure, unit-tested) ------------------------------------


def build_token_request(
    *,
    base_url: str,
    client_id: str,
    redirect_uri: str,
    code: str,
    code_verifier: str,
) -> tuple[str, bytes, dict[str, str]]:
    """Public-client authorization_code exchange.

    Deliberately carries NO `client_secret` and NO `Cookie` header — that
    absence is the entire experiment.
    """
    body = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code": code,
        "code_verifier": code_verifier,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    return (
        f"{base_url.rstrip('/')}{TOKEN_PATH}",
        urllib.parse.urlencode(body).encode("ascii"),
        headers,
    )


def build_refresh_request(
    *, base_url: str, client_id: str, refresh_token: str
) -> tuple[str, bytes, dict[str, str]]:
    body = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    return (
        f"{base_url.rstrip('/')}{TOKEN_PATH}",
        urllib.parse.urlencode(body).encode("ascii"),
        headers,
    )


def build_revoke_request(
    *, base_url: str, token: str, token_type_hint: str = "access_token"
) -> tuple[str, bytes, dict[str, str]]:
    body = {"token": token, "token_type_hint": token_type_hint}
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    return (
        f"{base_url.rstrip('/')}{REVOKE_PATH}",
        urllib.parse.urlencode(body).encode("ascii"),
        headers,
    )


# --- redaction ---------------------------------------------------------------


def redact_payload(payload: object) -> object:
    """Replace every secret value with a presence flag, recursively.

    Applied to EVERY server response before anything is rendered, so even a
    malformed or unexpected body cannot leak material.
    """
    if isinstance(payload, dict):
        out: dict[str, object] = {}
        for key, value in payload.items():
            if str(key).lower() in SECRET_KEYS:
                out[f"has_{key}"] = bool(value)
            else:
                out[key] = redact_payload(value)
        return out
    if isinstance(payload, list):
        return [redact_payload(item) for item in payload]
    return payload


def summarize_token_response(status: int, payload: object) -> dict[str, object]:
    """The only shape this probe ever prints for a token response."""
    body = payload if isinstance(payload, dict) else {}
    return {
        "http_status": status,
        "token_type": body.get("token_type"),
        "expires_in": body.get("expires_in"),
        "scope": body.get("scope"),
        "has_access_token": bool(body.get("access_token")),
        "has_refresh_token": bool(body.get("refresh_token")),
        "has_id_token": bool(body.get("id_token")),
        "error": body.get("error"),
        "error_description_present": bool(body.get("error_description")),
    }


# --- HTTP (no cookie jar, no retries) ----------------------------------------


def _cookieless_opener() -> urllib.request.OpenerDirector:
    """An opener with NO cookie processor: nothing can attach or persist a
    Cookie, which is precisely the native-app condition under test."""
    return urllib.request.build_opener(urllib.request.HTTPSHandler())


def post_form(
    url: str, body: bytes, headers: dict[str, str], *, timeout: int = DEFAULT_TIMEOUT
) -> tuple[int, object, str | None]:
    """One POST. No retry — repeating a code exchange would corrupt the result."""
    if any(h.lower() == "cookie" for h in headers):
        raise AssertionError("refusing to send a Cookie header from this probe")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    return _send(request, timeout=timeout)


def get_with_bearer(
    url: str, access_token: str, *, timeout: int = DEFAULT_TIMEOUT
) -> tuple[int, object, str | None]:
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
        method="GET",
    )
    return _send(request, timeout=timeout)


def _send(request: urllib.request.Request, *, timeout: int) -> tuple[int, object, str | None]:
    opener = _cookieless_opener()
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", "replace")
            correlation = response.headers.get("X-Frappe-Request-Id") or response.headers.get(
                "X-Request-Id"
            )
            return response.status, _safe_json(raw), correlation
    except urllib.error.HTTPError as exc:  # 4xx/5xx still carry a useful body
        raw = exc.read().decode("utf-8", "replace")
        correlation = exc.headers.get("X-Frappe-Request-Id") if exc.headers else None
        return exc.code, _safe_json(raw), correlation
    except urllib.error.URLError as exc:
        # `reason` can hold a hostname but never credentials.
        return 0, {"error": "network_error", "error_description": str(exc.reason)[:120]}, None


def _safe_json(raw: str) -> object:
    try:
        return json.loads(raw)
    except ValueError:
        # NEVER echo an unparsable body: it could be an HTML page containing a
        # token in a query string. Only its shape is reported.
        return {"error": "non_json_response", "body_length": len(raw)}


# --- report ------------------------------------------------------------------


class Report:
    def __init__(self) -> None:
        self.checks: list[tuple[str, str, str]] = []

    def add(self, name: str, passed: bool | None, detail: str = "") -> None:
        result = "PASS" if passed else ("FAIL" if passed is False else "SKIPPED")
        self.checks.append((name, result, detail))
        print(f"  [{result:7}] {name}{(' — ' + detail) if detail else ''}")

    def render(self) -> str:
        lines = ["", "| Check | Result |", "| --- | --- |"]
        lines += [f"| {name} | {result} |" for name, result, _ in self.checks]
        return "\n".join(lines)


def show(title: str, data: object) -> None:
    print(f"\n{title}:")
    print(json.dumps(redact_payload(data), indent=2, sort_keys=True, default=str))


# --- flows -------------------------------------------------------------------


def run_success_flow(args: argparse.Namespace, report: Report) -> None:
    verifier = generate_code_verifier()
    challenge = code_challenge_s256(verifier)
    state = generate_state()

    report.add("Verifier is RFC 7636 well-formed", verifier_is_wellformed(verifier),
               f"length={len(verifier)}")

    print("\n1) Open this URL in your SYSTEM BROWSER and sign in:\n")
    print(build_authorize_url(
        base_url=args.base_url,
        client_id=args.client_id,
        redirect_uri=args.redirect_uri,
        state=state,
        code_challenge=challenge,
        scope=args.scope,
    ))
    print(
        "\n2) After approving you land on the redirect URI (the page may fail to\n"
        "   load — that is fine, the browser's address bar is what matters).\n"
        "   Paste the FULL callback URL below. Input is hidden, so it is never\n"
        "   written to your shell history.\n"
    )

    try:
        code = parse_callback(getpass.getpass("   Callback URL: "), expected_state=state)
    except CallbackError as exc:
        report.add("State matched / callback usable", False, str(exc))
        report.add("Code exchange without Cookie", None, "not reached")
        report.add("Code exchange without client_secret", None, "not reached")
        return

    report.add("State matched / callback usable", True)

    url, body, headers = build_token_request(
        base_url=args.base_url,
        client_id=args.client_id,
        redirect_uri=args.redirect_uri,
        code=code,
        code_verifier=verifier,
    )
    status, payload, correlation = post_form(url, body, headers, timeout=args.timeout)
    summary = summarize_token_response(status, payload)
    if correlation:
        summary["correlation_id"] = correlation
    show("Token exchange (no Cookie, no client_secret)", summary)

    exchanged = bool(summary["has_access_token"])
    report.add("Code exchange without Cookie", exchanged,
               f"http {status}" + (f", error={summary['error']}" if summary.get("error") else ""))
    report.add("Code exchange without client_secret", exchanged, f"http {status}")

    if not exchanged:
        for name in ("Bearer API call", "Refresh", "Revoke", "Revoked token rejected"):
            report.add(name, None, "no access token")
        return

    tokens = payload if isinstance(payload, dict) else {}
    access_token = str(tokens.get("access_token") or "")
    refresh_token = str(tokens.get("refresh_token") or "")

    # --- bearer call ---------------------------------------------------------
    status, payload, _ = get_with_bearer(
        f"{args.base_url.rstrip('/')}{WHOAMI_PATH}", access_token, timeout=args.timeout
    )
    identified = status == 200 and bool(
        isinstance(payload, dict) and payload.get("message")
    )
    show("Bearer identity call", {"http_status": status, "identified_a_user": identified})
    report.add("Bearer API call", identified, f"http {status}")

    # --- refresh -------------------------------------------------------------
    new_access = ""
    if refresh_token:
        url, body, headers = build_refresh_request(
            base_url=args.base_url, client_id=args.client_id, refresh_token=refresh_token
        )
        status, payload, _ = post_form(url, body, headers, timeout=args.timeout)
        refresh_summary = summarize_token_response(status, payload)
        show("Refresh (no Cookie, no client_secret)", refresh_summary)
        refreshed = bool(refresh_summary["has_access_token"])
        report.add("Refresh", refreshed, f"http {status}")
        if refreshed and isinstance(payload, dict):
            new_access = str(payload.get("access_token") or "")
            rotated = bool(payload.get("refresh_token")) and payload.get(
                "refresh_token"
            ) != refresh_token
            report.add("Refresh token rotated", rotated,
                       "server issued a different refresh token" if rotated
                       else "same refresh token reused")
    else:
        report.add("Refresh", None, "no refresh token issued")

    # --- revoke + proof it stopped working -----------------------------------
    token_to_revoke = new_access or access_token
    url, body, headers = build_revoke_request(base_url=args.base_url, token=token_to_revoke)
    status, payload, _ = post_form(url, body, headers, timeout=args.timeout)
    show("Revoke", {"http_status": status})
    report.add("Revoke", status in (200, 204), f"http {status}")

    status, payload, _ = get_with_bearer(
        f"{args.base_url.rstrip('/')}{WHOAMI_PATH}", token_to_revoke, timeout=args.timeout
    )
    rejected = status in (401, 403)
    show("Call with the revoked token", {"http_status": status, "rejected": rejected})
    report.add("Revoked token rejected", rejected, f"http {status}")


def run_wrong_verifier_flow(args: argparse.Namespace, report: Report) -> None:
    """Negative control: a FRESH authorization code exchanged with a verifier
    that does not match the challenge must be refused."""
    verifier = generate_code_verifier()
    challenge = code_challenge_s256(verifier)
    state = generate_state()

    print("\n1) Open this URL in your SYSTEM BROWSER and sign in:\n")
    print(build_authorize_url(
        base_url=args.base_url,
        client_id=args.client_id,
        redirect_uri=args.redirect_uri,
        state=state,
        code_challenge=challenge,
        scope=args.scope,
    ))
    print("\n2) Paste the FULL callback URL below (hidden input).\n")

    try:
        code = parse_callback(getpass.getpass("   Callback URL: "), expected_state=state)
    except CallbackError as exc:
        report.add("Wrong verifier rejected", None, f"not reached: {exc}")
        return

    # A different, equally well-formed verifier — never the matching one.
    wrong_verifier = generate_code_verifier()
    if wrong_verifier == verifier:  # astronomically unlikely; be explicit anyway
        wrong_verifier = generate_code_verifier()

    url, body, headers = build_token_request(
        base_url=args.base_url,
        client_id=args.client_id,
        redirect_uri=args.redirect_uri,
        code=code,
        code_verifier=wrong_verifier,
    )
    status, payload, _ = post_form(url, body, headers, timeout=args.timeout)
    summary = summarize_token_response(status, payload)
    show("Token exchange with a WRONG verifier", summary)

    refused = not summary["has_access_token"]
    report.add("Wrong verifier rejected", refused,
               f"http {status}" + (f", error={summary['error']}" if summary.get("error") else ""))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Probe whether Frappe accepts native (public-client) PKCE.",
        epilog="Never pass a client secret to this script; a public client has none.",
    )
    parser.add_argument("--base-url", required=True, help="https://<site> (no trailing path)")
    parser.add_argument("--client-id", required=True, help="OAuth Client's client_id")
    parser.add_argument(
        "--redirect-uri", required=True,
        help="EXACT redirect URI registered on the OAuth Client",
    )
    parser.add_argument("--scope", default=DEFAULT_SCOPE)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    parser.add_argument(
        "--flow", choices=("success", "wrong-verifier"), default="success",
        help="success: full happy path + refresh + revoke. "
             "wrong-verifier: negative control with a fresh code.",
    )
    args = parser.parse_args(argv)

    if not args.base_url.lower().startswith("https://"):
        parser.error("--base-url must be https://")

    print("Frappe native PKCE probe — nothing is created or modified on the site.")
    print("No code, verifier, token, secret or cookie is ever printed.\n")

    report = Report()
    report.add("State mismatch rejected locally", _selftest_state_mismatch(),
               "verified in-process before any network call")

    if args.flow == "success":
        run_success_flow(args, report)
    else:
        run_wrong_verifier_flow(args, report)

    print("\n" + "=" * 62)
    print("RESULT TABLE (safe to paste back verbatim)")
    print(report.render())
    print("\nRun the other flow with --flow "
          + ("wrong-verifier" if args.flow == "success" else "success"))
    return 0


def _selftest_state_mismatch() -> bool:
    """Prove locally, every run, that a mismatched state is refused before any
    token request can happen."""
    try:
        parse_callback("https://example.test/cb?code=x&state=wrong", expected_state="right")
    except CallbackError:
        return True
    return False


if __name__ == "__main__":
    sys.exit(main())
