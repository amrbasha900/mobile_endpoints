"""Offline tests for scripts/oauth_pkce_probe.py.

None of these need a real OAuth Client, a running site, or a network: they
cover the probe's pure logic and — more importantly — its safety properties,
so a future edit cannot quietly start leaking credential material or start
sending a Cookie / client_secret on the very request whose *absence* of those
is what the probe measures.

The probe is stdlib-only and never imports frappe, so it is loaded straight
from its path with no test stub involved.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import pathlib
import urllib.parse

import pytest

_PROBE_PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "oauth_pkce_probe.py"
_spec = importlib.util.spec_from_file_location("oauth_pkce_probe", _PROBE_PATH)
assert _spec and _spec.loader
probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(probe)


BASE = "https://site.example"
CLIENT_ID = "test-client-id"
REDIRECT = "https://auth.example/oauth2redirect"

# Obvious sentinels: if any of these ever appear in rendered output, the
# assertion that finds them is pointing at a real leak.
FAKE_CODE = "AUTHCODE-SENTINEL-111"
FAKE_VERIFIER = "VERIFIER-SENTINEL-222"
FAKE_ACCESS = "ACCESS-SENTINEL-333"
FAKE_REFRESH = "REFRESH-SENTINEL-444"
FAKE_SECRET = "SECRET-SENTINEL-555"


# --- verifier / challenge ----------------------------------------------------


def test_verifier_length_and_charset_match_rfc7636():
    for _ in range(50):
        verifier = probe.generate_code_verifier()
        assert probe.VERIFIER_MIN_LEN <= len(verifier) <= probe.VERIFIER_MAX_LEN
        assert probe.UNRESERVED_RE.match(verifier), verifier
        assert probe.verifier_is_wellformed(verifier)


def test_verifiers_are_unique_per_call():
    assert len({probe.generate_code_verifier() for _ in range(200)}) == 200


def test_wellformedness_rejects_out_of_spec_verifiers():
    assert not probe.verifier_is_wellformed("short")                      # < 43
    assert not probe.verifier_is_wellformed("a" * 129)                    # > 128
    assert not probe.verifier_is_wellformed("a" * 42 + "+")               # reserved char
    assert not probe.verifier_is_wellformed("a" * 42 + "/")
    assert not probe.verifier_is_wellformed("a" * 42 + "=")


def test_s256_challenge_matches_the_specification():
    verifier = probe.generate_code_verifier()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .decode("ascii")
        .rstrip("=")
    )
    assert probe.code_challenge_s256(verifier) == expected


def test_s256_challenge_matches_the_rfc7636_appendix_b_vector():
    """The verifier/challenge pair published in RFC 7636 Appendix B."""
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert probe.code_challenge_s256(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_challenge_is_base64url_without_padding():
    for _ in range(20):
        challenge = probe.code_challenge_s256(probe.generate_code_verifier())
        assert "=" not in challenge
        assert "+" not in challenge and "/" not in challenge
        assert len(challenge) == 43  # 32-byte digest, base64url, unpadded


def test_challenge_matches_the_algorithm_frappe_itself_applies():
    """frappe/oauth.py:169-176 base64-encodes the digest then rewrites +/= —
    the same string this probe sends as code_challenge."""
    verifier = probe.generate_code_verifier()
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    frappe_style = base64.b64encode(digest).decode("utf-8")
    frappe_style = frappe_style.replace("+", "-").replace("/", "_").replace("=", "")
    assert probe.code_challenge_s256(verifier) == frappe_style


# --- authorization URL -------------------------------------------------------


def test_authorize_url_carries_exactly_the_required_parameters():
    url = probe.build_authorize_url(
        base_url=BASE,
        client_id=CLIENT_ID,
        redirect_uri=REDIRECT,
        state="STATE",
        code_challenge="CHALLENGE",
        scope="openid all",
    )
    split = urllib.parse.urlsplit(url)
    query = dict(urllib.parse.parse_qsl(split.query))

    assert split.path == probe.AUTHORIZE_PATH
    assert query == {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT,
        "scope": "openid all",
        "state": "STATE",
        "code_challenge": "CHALLENGE",
        "code_challenge_method": "S256",
    }
    # The verifier must never travel on the authorization request.
    assert "code_verifier" not in query


def test_authorize_url_never_downgrades_to_plain():
    url = probe.build_authorize_url(
        base_url=BASE, client_id=CLIENT_ID, redirect_uri=REDIRECT,
        state="s", code_challenge="c",
    )
    assert "code_challenge_method=S256" in url
    assert "plain" not in url


def test_redirect_uri_is_sent_verbatim_for_exact_matching():
    tricky = "https://auth.example/oauth2redirect?x=1"
    url = probe.build_authorize_url(
        base_url=BASE, client_id=CLIENT_ID, redirect_uri=tricky,
        state="s", code_challenge="c",
    )
    query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    assert query["redirect_uri"] == tricky


# --- callback parsing / state ------------------------------------------------


def test_matching_state_returns_the_code():
    url = f"https://auth.example/cb?code={FAKE_CODE}&state=abc"
    assert probe.parse_callback(url, expected_state="abc") == FAKE_CODE


def test_state_mismatch_is_refused_before_any_exchange():
    with pytest.raises(probe.CallbackError) as err:
        probe.parse_callback(f"https://auth.example/cb?code={FAKE_CODE}&state=evil",
                             expected_state="abc")
    assert "STATE MISMATCH" in str(err.value)
    assert FAKE_CODE not in str(err.value)


def test_missing_state_is_refused():
    with pytest.raises(probe.CallbackError):
        probe.parse_callback(f"https://auth.example/cb?code={FAKE_CODE}", expected_state="abc")


def test_missing_code_is_refused():
    with pytest.raises(probe.CallbackError):
        probe.parse_callback("https://auth.example/cb?state=abc", expected_state="abc")


@pytest.mark.parametrize("url", ["", "   ", "https://auth.example/cb", "not-a-url"])
def test_malformed_callbacks_are_refused(url):
    with pytest.raises(probe.CallbackError):
        probe.parse_callback(url, expected_state="abc")


def test_server_error_callback_is_reported_without_the_description():
    with pytest.raises(probe.CallbackError) as err:
        probe.parse_callback(
            "https://auth.example/cb?error=access_denied"
            "&error_description=user%20SENSITIVE%20detail&state=abc",
            expected_state="abc",
        )
    assert "access_denied" in str(err.value)
    assert "SENSITIVE" not in str(err.value)


def test_the_probe_self_test_proves_state_mismatch_is_rejected():
    assert probe._selftest_state_mismatch() is True


# --- request builders: no cookie, no client secret ---------------------------


def test_token_request_sends_no_client_secret_and_no_cookie():
    url, body, headers = probe.build_token_request(
        base_url=BASE, client_id=CLIENT_ID, redirect_uri=REDIRECT,
        code=FAKE_CODE, code_verifier=FAKE_VERIFIER,
    )
    fields = dict(urllib.parse.parse_qsl(body.decode()))

    assert url == f"{BASE}{probe.TOKEN_PATH}"
    assert fields == {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT,
        "code": FAKE_CODE,
        "code_verifier": FAKE_VERIFIER,
    }
    assert "client_secret" not in fields
    assert not any(h.lower() == "cookie" for h in headers)
    assert not any(h.lower() == "authorization" for h in headers)


def test_refresh_request_sends_no_client_secret_and_no_cookie():
    _, body, headers = probe.build_refresh_request(
        base_url=BASE, client_id=CLIENT_ID, refresh_token=FAKE_REFRESH
    )
    fields = dict(urllib.parse.parse_qsl(body.decode()))
    assert fields["grant_type"] == "refresh_token"
    assert "client_secret" not in fields
    assert not any(h.lower() == "cookie" for h in headers)


def test_revoke_request_sends_no_client_secret_and_no_cookie():
    url, body, headers = probe.build_revoke_request(base_url=BASE, token=FAKE_ACCESS)
    fields = dict(urllib.parse.parse_qsl(body.decode()))
    assert url == f"{BASE}{probe.REVOKE_PATH}"
    assert fields["token"] == FAKE_ACCESS
    assert "client_secret" not in fields
    assert not any(h.lower() == "cookie" for h in headers)


def test_post_form_refuses_to_send_a_cookie_header():
    with pytest.raises(AssertionError):
        probe.post_form(f"{BASE}{probe.TOKEN_PATH}", b"a=1", {"Cookie": "sid=abc"})


def test_the_http_opener_has_no_cookie_processor():
    """A cookie jar would let a token request inherit browser state — exactly
    the condition this probe must NOT reproduce."""
    opener = probe._cookieless_opener()
    assert not any(
        type(handler).__name__ == "HTTPCookieProcessor" for handler in opener.handlers
    )


# --- redaction ---------------------------------------------------------------


def test_redaction_replaces_every_secret_with_a_presence_flag():
    redacted = probe.redact_payload(
        {
            "access_token": FAKE_ACCESS,
            "refresh_token": FAKE_REFRESH,
            "id_token": "ID-SENTINEL",
            "client_secret": FAKE_SECRET,
            "code": FAKE_CODE,
            "code_verifier": FAKE_VERIFIER,
            "token_type": "Bearer",
            "expires_in": 3600,
        }
    )
    rendered = json.dumps(redacted)
    for sentinel in (FAKE_ACCESS, FAKE_REFRESH, FAKE_SECRET, FAKE_CODE, FAKE_VERIFIER, "ID-SENTINEL"):
        assert sentinel not in rendered
    assert redacted["has_access_token"] is True
    assert redacted["has_refresh_token"] is True
    assert redacted["token_type"] == "Bearer"
    assert redacted["expires_in"] == 3600


def test_redaction_reaches_nested_and_listed_values():
    rendered = json.dumps(
        probe.redact_payload(
            {"outer": {"inner": [{"access_token": FAKE_ACCESS}, {"cookie": "sid=1"}]}}
        )
    )
    assert FAKE_ACCESS not in rendered
    assert "sid=1" not in rendered


def test_redaction_is_case_insensitive_about_header_style_keys():
    rendered = json.dumps(probe.redact_payload({"Set-Cookie": "sid=1", "Authorization": "Bearer x"}))
    assert "sid=1" not in rendered
    assert "Bearer x" not in rendered


def test_token_summary_reports_only_safe_fields():
    summary = probe.summarize_token_response(
        200,
        {
            "access_token": FAKE_ACCESS,
            "refresh_token": FAKE_REFRESH,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "openid all",
        },
    )
    rendered = json.dumps(summary)
    assert FAKE_ACCESS not in rendered and FAKE_REFRESH not in rendered
    assert summary["has_access_token"] is True
    assert summary["has_refresh_token"] is True
    assert summary["token_type"] == "Bearer"
    assert summary["expires_in"] == 3600
    assert summary["scope"] == "openid all"


def test_token_summary_of_an_error_response_keeps_the_description_out():
    summary = probe.summarize_token_response(
        400, {"error": "invalid_grant", "error_description": "SENSITIVE server text"}
    )
    rendered = json.dumps(summary)
    assert summary["error"] == "invalid_grant"
    assert summary["has_access_token"] is False
    assert "SENSITIVE" not in rendered
    assert summary["error_description_present"] is True


def test_token_summary_survives_a_malformed_response_without_leaking():
    for payload in (None, "a string", ["a", "list"], 42):
        summary = probe.summarize_token_response(500, payload)
        assert summary["has_access_token"] is False
        assert summary["http_status"] == 500


def test_a_non_json_body_is_never_echoed_back():
    """An HTML error page could carry a token in a query string — only its
    shape may be reported."""
    result = probe._safe_json(f"<html>token={FAKE_ACCESS}</html>")
    rendered = json.dumps(result)
    assert FAKE_ACCESS not in rendered
    assert result["error"] == "non_json_response"


# --- no code reuse / no retries ---------------------------------------------


def test_the_probe_never_retries_a_token_request():
    """A retried exchange would reuse a consumed authorization code and make
    the measurement meaningless."""
    source = _PROBE_PATH.read_text(encoding="utf-8")
    assert "retry" not in source.lower().replace("no retry", "").replace("retries", "")


def test_each_flow_obtains_its_own_fresh_code_and_verifier():
    """The negative control must mint a new verifier rather than reusing the
    success flow's, so it is a genuine mismatch against a fresh code."""
    source = probe.run_wrong_verifier_flow.__doc__ or ""
    assert "FRESH" in source
    body = _PROBE_PATH.read_text(encoding="utf-8")
    start = body.index("def run_wrong_verifier_flow")
    end = body.index("def main(")
    assert body.count("generate_code_verifier()", start, end) >= 2


def test_secret_key_list_covers_every_credential_this_flow_touches():
    for key in ("access_token", "refresh_token", "code", "code_verifier",
                "code_challenge", "client_secret", "id_token", "cookie", "set-cookie"):
        assert key in probe.SECRET_KEYS
