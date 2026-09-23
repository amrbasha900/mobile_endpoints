# Native PKCE compatibility probe — runbook

Phase 03, increment 1. Run this once against a **staging** Frappe site to
settle one question:

> Can Frappe 15.86.0 complete an Authorization Code + PKCE (S256) exchange for
> a native app when the token request carries **no Frappe session cookie** and
> **no client secret**?

Source reading is not proof. `frappe/oauth.py:97-134` shows
`authenticate_client()` comparing a browser `user_id` cookie rather than a
client secret; whether oauthlib routes a public client through that method
(fail) or through `authenticate_client_id()` (pass) can only be observed
against a running site. Everything downstream — the whole mobile design — waits
on this answer.

**Nothing in this increment changes the app.** The probe does not create the
OAuth Client, does not touch site config, and leaves
`pamper_allow_legacy_api_key_login` alone.

---

## 1. Create the test OAuth Client (manually, in Desk)

Use a **staging** site. Desk → search "OAuth Client" → New.

| Field | Value to use | Notes |
|---|---|---|
| App Name | `Pamper Native PKCE Probe` | Anything recognisable; it is temporary |
| User | the account you will sign in as | Test user, not a real customer admin |
| Redirect URIs | `https://<your-pamper-auth-host>/oauth2redirect` | **Placeholder — substitute your real central auth host.** One per line |
| Default Redirect URI | the same string, character for character | Must match exactly |
| Grant Type | `Authorization Code` | |
| Response Type | `Code` | |
| Scopes | `openid all` | The only scopes proven to exist on this version; do not invent others |
| Skip Authorization | unchecked | Keep the consent step visible for this test |
| Client Secret | **leave whatever Frappe generates; never copy it anywhere** | A public client does not use it. The probe never sends it. |

After saving, copy only the **client_id**. You will pass it on the command
line. **Do not copy the client secret** into a file, a shell, this repo, or a
message.

### Exact redirect URI matching

Frappe validates the redirect URI by exact membership in the registered list
(`frappe/oauth.py:29-42`) — no prefix or wildcard matching. A trailing slash,
a different scheme, or a different case will be rejected. The value you
register, the value you pass as `--redirect-uri`, and the value in the
authorization URL must be byte-identical.

For this probe the redirect target does not need to serve anything. The browser
will try to load it and may show an error page — that is fine. What matters is
the **address bar**, which holds `?code=...&state=...`.

---

## 2. Run the success flow

```bash
cd /home/frappe/frappe-bench/apps/mobile_endpoints   # or wherever this repo lives
python3 scripts/oauth_pkce_probe.py \
  --base-url https://<staging-site> \
  --client-id <client_id-from-step-1> \
  --redirect-uri https://<your-pamper-auth-host>/oauth2redirect \
  --flow success
```

The script prints an authorization URL. **Open it in your system browser**
(not a WebView, not curl), sign in, approve. You will be redirected to the
redirect URI; copy the **entire** URL from the address bar.

Back in the terminal, paste it at the hidden `Callback URL:` prompt. The input
is hidden, so the authorization code never enters your shell history or the
process list.

The probe then, in one pass:

1. verifies `state` locally **before** any token request;
2. exchanges the code with the `code_verifier`, from a fresh HTTP client with
   no cookie jar and no client secret;
3. calls `frappe.auth.get_logged_user` with the bearer token;
4. refreshes, again with no cookie and no secret;
5. revokes, then re-calls the API to prove the revoked token is refused.

---

## 3. Run the negative control

Run this **separately**, with a **fresh** authorization code (log in again):

```bash
python3 scripts/oauth_pkce_probe.py \
  --base-url https://<staging-site> \
  --client-id <client_id> \
  --redirect-uri https://<your-pamper-auth-host>/oauth2redirect \
  --flow wrong-verifier
```

It exchanges a brand-new code with a deliberately mismatched verifier. The
server **must** refuse it. If this one *succeeds*, PKCE is not being enforced
and that is a finding in its own right — report it.

Do not reuse a code between the two flows: Frappe deletes the authorization
code when a challenge is present and the verifier is missing or wrong
(`frappe/oauth.py:163-167`), so a reused code fails for the wrong reason.

---

## 4. What the probe will never print

The authorization code, the code verifier or challenge, the access token, the
refresh token, the client secret, any `Cookie` / `Set-Cookie` header, or any
`error_description` text. Server responses pass through a redactor before
anything is rendered, so even a malformed or unexpected body cannot leak
material. Output is limited to: HTTP status, `token_type`, `expires_in`,
`scope`, `has_access_token`, `has_refresh_token`, a correlation id when the
server sends one, and the OAuth `error` code (a fixed vocabulary).

That redaction is enforced by tests (`tests/test_oauth_pkce_probe.py`), so it
cannot regress silently.

---

## 5. Report this table back

Paste the table the script prints. It is already safe — it contains no
credential material.

| Check | Result |
| --- | --- |
| Code exchange without Cookie | PASS/FAIL |
| Code exchange without client_secret | PASS/FAIL |
| Bearer API call | PASS/FAIL |
| Refresh | PASS/FAIL |
| Revoke | PASS/FAIL |
| Wrong verifier rejected | PASS/FAIL |
| State mismatch rejected locally | PASS/FAIL |

Also useful, and all safe to share: the `http_status` and `error` code of any
failing step, plus whether "Refresh token rotated" said the server issued a
different refresh token.

### How to read the outcome

- **Code exchange PASS** → native public-client PKCE works on this version;
  the mobile design in `PHASE-03-AUTH-AUDIT.md` §4.1 proceeds as written.
- **Code exchange FAIL with `invalid_client`** → Finding C is real: the token
  endpoint wants the browser session cookie. The native flow cannot be
  standard, and the next increment has to evaluate alternatives (a
  server-side exchange through the BFF for every platform, or a Frappe-side
  change). Do not work around it in the app.

---

## 6. Clean up when finished

The test client is a live credential-issuing object. When the probe is done:

1. Desk → OAuth Client → open the probe client.
2. Revoke any tokens still outstanding: OAuth Bearer Token list → filter by
   this client → set Status to `Revoked` (or delete the rows).
3. **Delete the OAuth Client**, or at minimum clear its Redirect URIs so no
   code can be issued against it.

Leaving it enabled on a staging site with a real redirect URI is an unnecessary
standing risk.

---

## 7. Offline tests

The probe's logic and its safety properties are covered without any site:

```bash
python3 -m pytest tests/test_oauth_pkce_probe.py -q
```

35 tests: RFC 7636 verifier shape, the S256 challenge (including the RFC
Appendix B vector and Frappe's own transformation), base64url-without-padding,
authorization-URL parameters, state match/mismatch and malformed callbacks,
the absence of `Cookie` and `client_secret` on every built request, the
cookie-less opener, redaction of nested/odd/error/non-JSON payloads, and a
guard that no retry path exists.
