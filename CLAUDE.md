# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Install for development (Python 3.10+):

```bash
python3 -m venv .venv && source .venv/bin/activate && python -m pip install -e .
```

Run the mocked test suite (no network access required):

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Run a single test:

```bash
PYTHONPATH=src python -m unittest tests.test_client.<TestCase>.<test_method>
```

Live smoke test (posts real content, does not clean up):

```bash
cp examples/local_credentials.py.example examples/local_credentials.py  # fill in creds
python examples/manual_smoke_test.py
```

## Architecture

`src/truthsocial_py` is a src-layout package with three layers:

- `client.py` — `TruthSocialClient`: one HTTP session bound to at most one user
  token. Owns the `httpx.Client`, an `X-Truth-Session-Id` UUID header, all
  endpoint methods (`login`, `verify_credentials`, `upload_media`,
  `post_status`, `reply`), and error mapping. Every request funnels through
  `_request_json`, which is the single place where `httpx.RequestError` becomes
  `NetworkError`, non-2xx becomes `_raise_for_error`, and non-dict JSON becomes
  `ProtocolError`.
- `app.py` — `TruthSocialApp`: an OAuth app identity (client_id/secret) that
  mints independent clients. Holds an `RLock` around credentials so
  `rediscover()` and concurrent logins stay consistent. `login()` retries once
  through `_login_once` when `_is_invalid_client_error` matches OAuth
  `invalid_client`/`unauthorized_client` and `auto_rediscover` is on; existing
  clients keep their old credential snapshot.
- `models.py` — frozen dataclasses (`OAuthToken`, `Account`, `MediaAttachment`,
  `Status`, `OAuthAppCredentials`) built via `from_payload` classmethods that
  tolerate missing/oddly typed fields and retain the raw mapping.

New-device verification lives on the client alongside `login`:
`send_security_code` posts `/oauth/v2/choose_delivery_method`, and
`login_with_security_code` posts `/oauth/v2/verify_security_code` (the full
password grant plus `challenge_id` and `security_code`). A 403 with
`error: "security_code_required"` becomes `DeviceChallengeRequired`, whose
`challenge` holds the `challenge_id` and the `{kind, value}` delivery options;
`app.login` deliberately does not spend a rediscover retry on it.

2FA accounts take the sibling branch: a 403 with `error: "mfa_required"`
becomes `MfaRequired`, whose `challenge` holds the `mfa_token`, and
`login_with_mfa_code` posts `/oauth/mfa/challenge` with
`challenge_type: "totp"` plus the token and code — no password. That response
body carries a misleading "2FA code entered is incorrect" sentence on the
first prompt, so `MfaRequired` uses a fixed message and keeps the sentence on
`challenge.detail`; do not surface it as the message.

A 403 that carries no JSON object body becomes `ForbiddenError` (an `APIError`,
deliberately *not* an `AuthenticationError`) — checked after the `mfa_required`
and `security_code_required` branches, which always have bodies, and before the
generic 401/403 auth branch. The API explains app-level refusals in the body, so
a bodiless 403 is an edge/WAF rejection with a still-valid token; classifying it
as auth made callers discard a good session and burn a TOTP code. Keep 401
unconditionally `AuthenticationError` — only 403 is ambiguous.

`TruthSocialClient` takes `headers` (merged over the library defaults; rejects
`Authorization`), `cookies` (a `http.cookiejar.CookieJar`, shared by reference
— an `httpx.Cookies` would be copied and defeat the point), and `http2`.
`TruthSocialApp` owns one `CookieJar`, seeds it from discovery, and hands it to
every client it mints so Cloudflare's `__cf_bm` persists. `http2` is opt-in via
the `[http2]` extra and measurably gets discovery 403'd — httpx's h2 fingerprint
scores worse than HTTP/1.1. Do not flip the default without measuring.

`errors.py` defines the exception tree rooted at `TruthSocialError`.
`__init__.py` re-exports the entire public surface with an explicit `__all__` —
add new public names there.

### Credential discovery

`TruthSocialClient.discover_web_app_credentials()` scrapes the live web client:
parse homepage `<script src>` tags with `_ScriptSourceParser`, keep only
same-origin URLs, stream each bundle under byte caps
(`_MAX_DISCOVERY_*` constants), and regex for OAuth pairs. It deliberately
fails closed — cross-origin URLs, redirects, oversized responses, zero
candidates, and *ambiguous* multiple candidates all raise
`CredentialDiscoveryError`. Preserve these guards when touching discovery.

### Conventions that matter here

- Injectable `transport` / `transport_factory` params exist so tests can pass
  `httpx.MockTransport`; tests never hit the network. New network code must
  route through the existing client so it inherits that seam.
- Error messages must not leak `client_secret`, passwords, or tokens — tests
  assert on this.
- `post_status` is intentionally never auto-retried (unknown outcome on
  transport failure); callers supply `idempotency_key` instead.
- Endpoint payload shapes mirror what the Truth Social web client sends; the
  `truthsocial*.har` files at the repo root are the captured reference traffic
  (git-ignored, and they contain real credentials). Most JS/JSON bodies in them
  are stored base64-encoded, so plain grep misses them — decode
  `content.text` where `content.encoding == "base64"` before searching.

## Release

Distribution name is `truthsocial-py`; the import package is `truthsocial_py`.
Version lives only in `src/truthsocial_py/_version.py` and is pulled into
metadata via `[tool.setuptools.dynamic]` — bump it there, never in
`pyproject.toml`.

`.github/workflows/release.yml` runs on a `v*` tag: tests on 3.10–3.13, builds
sdist+wheel, checks that the tag matches `__version__`, then publishes to PyPI
via Trusted Publishing (OIDC, environment `pypi`, no stored token).
