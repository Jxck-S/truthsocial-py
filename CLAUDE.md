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
  `truthsocial*.har` files at the repo root are the captured reference traffic.

## Release

Distribution name is `truthsocial-py`; the import package is `truthsocial_py`.
Version lives only in `src/truthsocial_py/_version.py` and is pulled into
metadata via `[tool.setuptools.dynamic]` — bump it there, never in
`pyproject.toml`.

`.github/workflows/release.yml` runs on a `v*` tag: tests on 3.10–3.13, builds
sdist+wheel, checks that the tag matches `__version__`, then publishes to PyPI
via Trusted Publishing (OIDC, environment `pypi`, no stored token).
