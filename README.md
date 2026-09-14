# truthsocial-py

<div align="center">
  <img src="https://raw.githubusercontent.com/Jxck-S/truthsocial-py/main/docs/assets/truthsocial-py.png" alt="truthsocial-py logo" width="420" />
</div>

An unofficial, typed Python client for Truth Social.

`truthsocial-py` supports OAuth app discovery, manual app configuration, multiple
independent user sessions, text and media posts, replies, and structured API
errors.

> [!NOTE]
> Truth Social does not publish this interface as a stable public API.
> Endpoints and payloads may change.

## Features

- Discover the OAuth app identity from the deployed Truth Social web client
- Configure an OAuth app identity manually
- Log in multiple users with isolated tokens, HTTP state, and session IDs
- Rediscover rotated web-app credentials automatically or on demand
- Publish text and image posts
- Reply to a status by ID or `Status` object
- Answer new-device security-code challenges over email or SMS
- Complete 2FA logins with an authenticator (TOTP) code
- Reuse existing access tokens
- Handle authentication, rate-limit, transport, and protocol errors

## Installation

Python 3.10 or newer is required.

```bash
python -m pip install truthsocial-py
```

The distribution is `truthsocial-py`; the import package is `truthsocial_py`:

```python
from truthsocial_py import TruthSocialApp
```

To work on the library itself:

```bash
git clone https://github.com/Jxck-S/truthsocial-py.git
cd truthsocial-py
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Quick start

Create an app from the current Truth Social web deployment, then log in:

```python
import getpass

from truthsocial_py import TruthSocialApp


app = TruthSocialApp.from_web()

with app.login(
    username=input("Truth Social username: "),
    password=getpass.getpass("Truth Social password: "),
) as client:
    account = client.verify_credentials()
    status = client.post_status("Hello from truthsocial-py!")
    print(f"Posted as @{account.acct}: {status.url}")
```

## App identities

`TruthSocialApp` represents one OAuth application identity. Load the current
identity from the website:

```python
app = TruthSocialApp.from_web()
```

Or provide one manually:

```python
app = TruthSocialApp(
    client_id="your-client-id",
    client_secret="your-client-secret",
)
```

Web-loaded apps enable automatic rediscovery by default. If login returns
OAuth's `invalid_client` or `unauthorized_client` error, the app refreshes its
identity and retries once. Refresh it explicitly at any time:

```python
credentials = app.rediscover()
```

Rediscovery applies to future clients and login attempts. Existing clients
keep their current token and app snapshot. A manually configured app can opt
in with `auto_rediscover=True`.

## Multiple users

Every login returns a separate `TruthSocialClient`:

```python
alice = app.login("alice", "alice-password")
bob = app.login("bob", "bob-password")

try:
    alice.post_status("Posted by Alice")
    bob.post_status("Posted by Bob")
finally:
    alice.close()
    bob.close()
```

Create a client from a previously saved token without logging in again:

```python
alice = app.new_client(access_token=load_alice_token())
```

## User agent

Requests are sent with `truthsocial-py/<version>` by default, exposed as
`truthsocial_py.DEFAULT_USER_AGENT`. Override it on an app or a client:

```python
from truthsocial_py import DEFAULT_USER_AGENT, TruthSocialApp

app = TruthSocialApp.from_web(user_agent="my-bot/2.0 (+https://example.com)")
client = app.new_client()  # inherits the app's user agent
print(client.user_agent)
```

`TruthSocialClient(..., user_agent=...)` works the same way. The value must be
a non-empty, header-safe string; anything else raises `ConfigurationError`.

## Media posts

Pass paths through `media_files`; each file is uploaded before the status:

```python
status = client.post_status(
    "A photo post",
    media_files=["photo.png"],
    idempotency_key="your-stable-unique-key",
)

for attachment in status.media_attachments:
    print(attachment.id, attachment.url)
```

Upload separately when you need the attachment first:

```python
attachment = client.upload_media("photo.png")
status = client.post_status(
    "Uploaded separately",
    media_ids=[attachment.id],
)
```

`upload_media()` also accepts open binary files with optional `filename` and
`content_type` arguments. Do not combine `media_files` and `media_ids` in the
same call. Media types and size limits are controlled by Truth Social.

Truth Social currently accepts `public` visibility for these posting calls.

## Replies

Reply using a parent status ID:

```python
reply = client.reply("parent-status-id", "This is a reply")
```

Or reply to a returned `Status`, including media:

```python
reply_with_photo = client.reply(
    reply,
    "Replying to my reply",
    media_files=["photo.png"],
)
```

The lower-level equivalent is
`post_status(..., in_reply_to_id="parent-status-id")`.

## Low-level client

`TruthSocialClient` can be used directly:

```python
from truthsocial_py import TruthSocialClient


with TruthSocialClient(
    client_id="your-client-id",
    client_secret="your-client-secret",
) as client:
    client.login("username", "password")
```

It can also discover the deployed app identity for a single login:

```python
with TruthSocialClient() as client:
    client.login_with_web_app("username", "password")
```

Use `discover_web_app_credentials()` to obtain the typed app identity without
logging in.

## New device verification

Logging in from a device Truth Social has not seen before is rejected with a
`DeviceChallengeRequired` — a subclass of `AuthenticationError`, so existing
handlers still catch it, but it is raised only when the username and password
were accepted. Answering it takes two more calls: pick a delivery method to
have a 6-digit code sent, then repeat the login with that code.

Own the client yourself so the challenge is answered on the session that
raised it (see [Challenge handling](#challenge-handling) below):

```python
from truthsocial_py import DeviceChallengeRequired, TruthSocialApp

app = TruthSocialApp.from_web()
username, password = "someone", "hunter2"

with app.new_client() as client:
    try:
        client.login(username, password)
    except DeviceChallengeRequired as exc:
        challenge = exc.challenge
        print(exc.message)  # "New device login detected. Please select a..."
        for option in challenge.delivery_options:
            print(option.kind, option.value)  # e.g. email j***@example.com

        client.send_security_code(challenge, "email")
        client.login_with_security_code(
            username,
            password,
            security_code=input("security code: "),
            challenge=challenge,
        )

    client.post_status("hello from a verified device")
```

`send_security_code` may be called again with the same challenge to resend the
code. The password is required a second time because
`/oauth/v2/verify_security_code` issues the token itself; the challenge is not
a token exchange. `TruthSocialApp.login` never retries credential rediscovery
on this error, since the app credentials were not the problem.

## Two-factor accounts

An account with 2FA enabled rejects the password grant with `MfaRequired`,
another `AuthenticationError` subclass, handing back a short-lived `mfa_token`.
That token stands in for the password — redeeming it with the authenticator
code returns the access token directly.

```python
from truthsocial_py import MfaRequired, TruthSocialApp

app = TruthSocialApp.from_web()

with app.new_client() as client:
    try:
        client.login("someone", "hunter2")
    except MfaRequired as exc:
        client.login_with_mfa_code(input("2FA code: "), challenge=exc.challenge)

    client.post_status("hello from a 2FA account")
```

`login_with_mfa_code` defaults to `challenge_type="totp"`, the only type Truth
Social currently advertises. Note that the 403 body claims "The 2FA code
entered is incorrect" even on the first prompt, before any code has been sent;
that sentence is kept on `exc.challenge.detail` rather than used as the
exception message, so it cannot be mistaken for a rejected code. A code that
really is wrong fails the `login_with_mfa_code` call with a plain
`AuthenticationError` carrying that same message.

## Challenge handling

Both challenge flows are answered on the **same client that raised them**.
Each client carries its own `X-Truth-Session-Id` and connection, and a
challenge belongs to that session, so create the client first and keep it in
scope for the handler:

```python
with app.new_client() as client:   # you own the client
    try:
        client.login(username, password)
    except MfaRequired as exc:
        client.login_with_mfa_code(code, challenge=exc.challenge)
```

`TruthSocialApp.login` creates a client internally and closes it when login
fails, so it cannot be used to answer a challenge — it is the one-shot path
for accounts with 2FA disabled logging in from a known device. Owning the
client trades away its automatic retry on rotated app credentials; handle that
by calling `app.rediscover()` yourself if a login fails with an
`invalid_client` error.

An account can require both: `/oauth/v2/verify_security_code` may itself
return `mfa_required`, so the two handlers compose on the one client.

## Posting behavior

Status creation is not retried automatically because a transport failure can
leave the final outcome unknown. Supply a stable `idempotency_key` when your
application may retry a post.

When `media_files` is used, a later upload or post failure can leave an
uploaded attachment unused.

## Shaping requests like the web client

`truthsocial.com` sits behind Cloudflare Bot Management (it sets `__cf_bm`).
Three constructor options let a caller present a more browser-like identity;
all are opt-in and none change the default behaviour.

```python
app = TruthSocialApp.from_web(
    user_agent=CHROME_UA,
    headers={
        "Sec-CH-UA": '"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": "https://truthsocial.com",
        "Referer": "https://truthsocial.com/",
    },
)
```

`headers` is merged over the library's defaults, so `Accept` and `User-Agent`
can be replaced. `Authorization` is refused — it is set per request from the
access token.

Send only the **low-entropy** client hints (`Sec-CH-UA`, `-Mobile`,
`-Platform`). `truthsocial.com` returns no `Accept-CH`, so a real Chrome never
volunteers the high-entropy set (`-Arch`, `-Bitness`, `-Full-Version-List`,
`-Platform-Version`, `-Model`); sending them unprompted is itself a tell.

A single `CookieJar` is now shared by an app and every client it mints, and is
seeded from credential discovery — so the `__cf_bm` Cloudflare issues on first
contact is presented on subsequent calls instead of each client arriving cold.

### HTTP/2 is available, and currently makes things worse

`http2=True` requires the extra:

```bash
pip install "truthsocial-py[http2]"
```

Browsers never speak HTTP/1.1 to a Cloudflare site, so enabling it *sounds*
like it should help. Measured, it does the opposite — credential discovery,
which succeeds every time over HTTP/1.1, is refused every time over HTTP/2:

```
run 1 http1: OK   run 1 http2: HTTP 403
run 2 http1: OK   run 2 http2: HTTP 403
run 3 http1: OK   run 3 http2: HTTP 403
run 4 http1: OK   run 4 http2: HTTP 403
```

httpx's HTTP/2 fingerprint (SETTINGS values, window sizes, pseudo-header order)
is distinctive and nothing like Chrome's, and appears to score far worse than
plain HTTP/1.1, which is unremarkable among legitimate non-browser clients.
The option is kept because it is the right primitive and the underlying stack
may change, but **leave it off** unless you have measured otherwise.

## Errors

All library exceptions inherit from `TruthSocialError`:

- `ConfigurationError` and `NotAuthenticatedError`
- `CredentialDiscoveryError`
- `AuthenticationError`, and its `DeviceChallengeRequired` and `MfaRequired`
  subclasses
- `RateLimitError`, including an optional `retry_after`
- `ForbiddenError` — a 403 with no JSON body
- `APIError`
- `NetworkError` and `ProtocolError`

### `ForbiddenError` vs `AuthenticationError`

Truth Social explains every application-level refusal in a JSON body. A 403
that arrives with no body at all — no `error`, no `detail`, no `x-request-id`
header — did not come from the application; it came from the edge in front of
it, which scores requests for bot/WAF signals and drops a fraction of them.
`/api/v1/media` is by far the most common victim, and uploads can fail this way
at a steady single-digit-to-20% rate while the same token posts to
`/api/v1/statuses` without a single failure.

These raise `ForbiddenError`, which is **not** an `AuthenticationError`. That
distinction matters: the access token is untouched and still valid, so
re-authenticating cannot help, throws away a working session, and on a 2FA
account spends a TOTP code — fast enough to collide with the previous code's
30-second window and lock the account out of its own retry.

Treat it as a transient refusal of that one request: back off for minutes
rather than seconds (an immediate retry usually hits the same block), or
degrade gracefully.

```python
from truthsocial_py import ForbiddenError

try:
    status = client.post_status("hello", media_files=["map.png"])
except ForbiddenError:
    # The upload was blocked, not the session. Post without the image.
    status = client.post_status("hello")
```

Anything that *does* explain itself keeps the old behaviour: a 403 carrying an
`error` code or a `detail` string, and any 401, still raise
`AuthenticationError`, and `mfa_required` / `security_code_required` still take
priority as `MfaRequired` / `DeviceChallengeRequired`.

## Development

Run the mocked test suite:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Live smoke test

Prepare the local settings file:

```bash
cp examples/local_credentials.py.example examples/local_credentials.py
```

Fill in the username and password, then run:

```bash
python examples/manual_smoke_test.py
```

After confirmation, the script creates a public text post, a public reply, and
a public image post using `examples/truthsocial-py-test.png`. It does not delete them
afterward.
