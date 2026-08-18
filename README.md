# truthsocial-py

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

## Posting behavior

Status creation is not retried automatically because a transport failure can
leave the final outcome unknown. Supply a stable `idempotency_key` when your
application may retry a post.

When `media_files` is used, a later upload or post failure can leave an
uploaded attachment unused.

## Errors

All library exceptions inherit from `TruthSocialError`:

- `ConfigurationError` and `NotAuthenticatedError`
- `CredentialDiscoveryError`
- `AuthenticationError`
- `RateLimitError`, including an optional `retry_after`
- `APIError`
- `NetworkError` and `ProtocolError`

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
