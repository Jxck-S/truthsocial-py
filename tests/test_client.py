from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from uuid import UUID

import httpx

from truthpy import (
    APIError,
    AuthenticationError,
    ConfigurationError,
    CredentialDiscoveryError,
    NetworkError,
    NotAuthenticatedError,
    ProtocolError,
    RateLimitError,
    Status,
    TruthSocialClient,
    Visibility,
)

WEB_CLIENT_ID = "web-client-id-1234567890"
WEB_CLIENT_SECRET = "web-client-secret-1234567890"


def web_bundle(
    client_id: str = WEB_CLIENT_ID,
    client_secret: str = WEB_CLIENT_SECRET,
) -> str:
    return (
        "const env={};"
        "const oauth={"
        f'client_id:env.VITE_OAUTH_CLIENT_ID||"{client_id}",'
        f'client_secret:env.VITE_OAUTH_CLIENT_SECRET||"{client_secret}",'
        'redirect_uri:"urn:ietf:wg:oauth:2.0:oob"};'
        'const request={...oauth,grant_type:"password"};'
    )


class TruthSocialClientTests(unittest.TestCase):
    def make_client(self, handler, **kwargs) -> TruthSocialClient:
        client = TruthSocialClient(
            transport=httpx.MockTransport(handler),
            **kwargs,
        )
        self.addCleanup(client.close)
        return client

    def test_login_posts_password_grant_shape_and_retains_token(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.url.path, "/oauth/v2/token")
            self.assertEqual(request.headers["accept"], "application/json")
            self.assertEqual(
                request.headers["x-truth-session-id"],
                "session-id",
            )
            self.assertTrue(request.headers["user-agent"].startswith("truthpy/"))
            self.assertEqual(
                json.loads(request.content),
                {
                    "client_id": "app-id",
                    "client_secret": "app-secret",
                    "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
                    "grant_type": "password",
                    "scope": "read write follow push",
                    "username": "alice",
                    "password": "correct horse",
                },
            )
            return httpx.Response(
                200,
                json={
                    "access_token": "access-token",
                    "token_type": "Bearer",
                    "scope": "read write",
                    "created_at": 1234,
                },
            )

        client = self.make_client(
            handler,
            client_id="app-id",
            client_secret="app-secret",
            truth_session_id="session-id",
        )
        token = client.login("alice", "correct horse")

        self.assertEqual(token.access_token, "access-token")
        self.assertEqual(token.created_at, 1234)
        self.assertEqual(client.access_token, "access-token")
        self.assertTrue(client.is_authenticated)
        self.assertNotIn("access-token", repr(token))
        self.assertNotIn("access-token", repr(client))

    def test_client_generates_truth_session_id(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(
                request.headers["x-truth-session-id"],
                client.truth_session_id,
            )
            return httpx.Response(
                200,
                json={
                    "id": "42",
                    "username": "alice",
                    "acct": "alice",
                    "display_name": "Alice",
                },
            )

        client = self.make_client(handler, access_token="access-token")
        UUID(client.truth_session_id)
        client.verify_credentials()

    def test_discovers_web_credentials_from_same_origin_bundle(self):
        requested_urls = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested_urls.append(str(request.url))
            self.assertEqual(request.url.host, "truthsocial.com")
            if request.url.path == "/":
                return httpx.Response(
                    200,
                    html=(
                        '<script src="https://cdn.example/ignored.js"></script>'
                        '<script type="module" src="/assets/app.js"></script>'
                    ),
                )
            if request.url.path == "/assets/app.js":
                self.assertIn(
                    "application/javascript",
                    request.headers["accept"],
                )
                return httpx.Response(200, text=web_bundle())
            self.fail(f"unexpected request: {request.url}")

        client = self.make_client(handler)
        credentials = client.discover_web_app_credentials()

        self.assertEqual(credentials.client_id, WEB_CLIENT_ID)
        self.assertEqual(credentials.client_secret, WEB_CLIENT_SECRET)
        self.assertEqual(
            credentials.source_url,
            "https://truthsocial.com/assets/app.js",
        )
        self.assertIn(WEB_CLIENT_ID, repr(credentials))
        self.assertNotIn(WEB_CLIENT_SECRET, repr(credentials))
        self.assertEqual(
            requested_urls,
            [
                "https://truthsocial.com/",
                "https://truthsocial.com/assets/app.js",
            ],
        )

    def test_login_with_web_app_discovers_then_uses_current_pair(self):
        requested_paths = []

        def handler(request: httpx.Request) -> httpx.Response:
            requested_paths.append(request.url.path)
            if request.url.path == "/":
                return httpx.Response(
                    200,
                    html='<script src="/assets/app.js"></script>',
                )
            if request.url.path == "/assets/app.js":
                return httpx.Response(200, text=web_bundle())
            if request.url.path == "/oauth/v2/token":
                body = json.loads(request.content)
                self.assertEqual(body["client_id"], WEB_CLIENT_ID)
                self.assertEqual(body["client_secret"], WEB_CLIENT_SECRET)
                self.assertEqual(body["username"], "alice")
                self.assertEqual(body["password"], "account-password")
                return httpx.Response(
                    200,
                    json={
                        "access_token": "access-token",
                        "token_type": "Bearer",
                    },
                )
            self.fail(f"unexpected request: {request.url}")

        client = self.make_client(handler)
        token = client.login_with_web_app("alice", "account-password")

        self.assertEqual(token.access_token, "access-token")
        self.assertEqual(
            requested_paths,
            ["/", "/assets/app.js", "/oauth/v2/token"],
        )

    def test_discovery_rejects_ambiguous_credential_pairs(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(
                    200,
                    html=(
                        '<script src="/assets/one.js"></script>'
                        '<script src="/assets/two.js"></script>'
                    ),
                )
            if request.url.path == "/assets/one.js":
                return httpx.Response(200, text=web_bundle())
            if request.url.path == "/assets/two.js":
                return httpx.Response(
                    200,
                    text=web_bundle(
                        "other-client-id-1234567890",
                        "other-client-secret-1234567890",
                    ),
                )
            self.fail(f"unexpected request: {request.url}")

        client = self.make_client(handler)

        with self.assertRaisesRegex(
            CredentialDiscoveryError,
            "multiple public OAuth",
        ):
            client.discover_web_app_credentials()

    def test_discovery_rejects_bundle_without_credentials(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(
                    200,
                    html='<script src="/assets/app.js"></script>',
                )
            return httpx.Response(200, text="const app = {};")

        client = self.make_client(handler)

        with self.assertRaisesRegex(
            CredentialDiscoveryError,
            "no public OAuth",
        ):
            client.discover_web_app_credentials()

    def test_discovery_does_not_fetch_cross_origin_scripts(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.host, "truthsocial.com")
            return httpx.Response(
                200,
                html='<script src="https://evil.example/app.js"></script>',
            )

        client = self.make_client(handler)

        with self.assertRaisesRegex(
            CredentialDiscoveryError,
            "no same-origin",
        ):
            client.discover_web_app_credentials()

    def test_discovery_rejects_redirects(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                302,
                headers={"location": "https://evil.example/"},
            )

        client = self.make_client(handler)

        with self.assertRaisesRegex(
            CredentialDiscoveryError,
            "does not follow redirects",
        ):
            client.discover_web_app_credentials()

    def test_discovery_rejects_declared_oversized_response(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"content-length": "1000001"},
                text="<html></html>",
            )

        client = self.make_client(handler)

        with self.assertRaisesRegex(
            CredentialDiscoveryError,
            "size limit",
        ):
            client.discover_web_app_credentials()

    def test_login_requires_application_credentials_without_sending_request(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.fail(f"unexpected request: {request.url}")

        client = self.make_client(handler)

        with self.assertRaisesRegex(ConfigurationError, "client_id"):
            client.login("alice", "password")

    def test_login_400_is_authentication_error_without_secret_values(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, json={"error": "invalid_grant"})

        client = self.make_client(
            handler,
            client_id="app-id",
            client_secret="private-app-secret",
        )

        with self.assertRaises(AuthenticationError) as raised:
            client.login("alice", "private-password")

        message = str(raised.exception)
        self.assertIn("invalid_grant", message)
        self.assertNotIn("private-app-secret", message)
        self.assertNotIn("private-password", message)

    def test_verify_credentials_uses_bearer_token_and_returns_account(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(
                request.url.path,
                "/api/v1/accounts/verify_credentials",
            )
            self.assertEqual(
                request.headers["authorization"],
                "Bearer access-token",
            )
            return httpx.Response(
                200,
                json={
                    "id": "42",
                    "username": "alice",
                    "acct": "alice",
                    "display_name": "Alice",
                    "url": "https://truthsocial.com/@alice",
                },
            )

        client = self.make_client(handler, access_token="access-token")
        account = client.verify_credentials()

        self.assertEqual(account.id, "42")
        self.assertEqual(account.acct, "alice")
        self.assertEqual(account.raw["username"], "alice")

    def test_authenticated_call_without_token_fails_locally(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.fail(f"unexpected request: {request.url}")

        client = self.make_client(handler)

        with self.assertRaises(NotAuthenticatedError):
            client.verify_credentials()

    def test_post_status_uses_web_payload_and_idempotency_header(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.url.path, "/api/v1/statuses")
            self.assertEqual(
                request.headers["authorization"],
                "Bearer access-token",
            )
            self.assertEqual(request.headers["idempotency-key"], "post-123")
            self.assertEqual(
                json.loads(request.content),
                {
                    "content_type": "text/plain",
                    "in_reply_to_id": "parent-id",
                    "media_ids": ["media-id"],
                    "poll": None,
                    "published": True,
                    "status": "Hello",
                    "title": "",
                    "visibility": "public",
                    "group_timeline_visible": False,
                },
            )
            return httpx.Response(
                200,
                json={
                    "id": "status-id",
                    "content": "<p>Hello</p>",
                    "visibility": "public",
                    "url": "https://truthsocial.com/@alice/1",
                    "created_at": "2026-08-17T20:00:00.000Z",
                    "account": {
                        "id": "42",
                        "username": "alice",
                        "acct": "alice",
                        "display_name": "Alice",
                        "url": "https://truthsocial.com/@alice",
                    },
                },
            )

        client = self.make_client(handler, access_token="access-token")
        status = client.post_status(
            "Hello",
            visibility=Visibility.PUBLIC,
            media_ids=["media-id"],
            in_reply_to_id="parent-id",
            idempotency_key="post-123",
        )

        self.assertEqual(status.id, "status-id")
        self.assertEqual(status.visibility, "public")
        self.assertEqual(status.account.username, "alice")

    def test_upload_media_sends_multipart_shape(self):
        uploaded_bytes = b"not-a-real-png"

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.url.path, "/api/v1/media")
            self.assertEqual(
                request.headers["authorization"],
                "Bearer access-token",
            )
            self.assertTrue(
                request.headers["content-type"].startswith(
                    "multipart/form-data; boundary="
                )
            )
            self.assertIn(b'name="file"', request.content)
            self.assertIn(b'filename="photo.png"', request.content)
            self.assertIn(b"Content-Type: image/png", request.content)
            self.assertIn(uploaded_bytes, request.content)
            return httpx.Response(
                200,
                json={
                    "id": "media-id",
                    "type": "image",
                    "url": "https://example.test/original.png",
                    "preview_url": "https://example.test/preview.png",
                    "description": None,
                    "processing": "complete",
                    "meta": {
                        "original": {
                            "width": 640,
                            "height": 480,
                        }
                    },
                },
            )

        client = self.make_client(handler, access_token="access-token")
        stream = io.BytesIO(uploaded_bytes)
        attachment = client.upload_media(
            stream,
            filename="photo.png",
        )

        self.assertEqual(attachment.id, "media-id")
        self.assertEqual(attachment.type, "image")
        self.assertEqual(attachment.processing, "complete")
        self.assertEqual(attachment.meta["original"]["width"], 640)
        self.assertFalse(stream.closed)

    def test_post_status_uploads_media_files_before_posting(self):
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request.url.path)
            if request.url.path == "/api/v1/media":
                self.assertIn(b'filename="photo.png"', request.content)
                return httpx.Response(
                    200,
                    json={
                        "id": "uploaded-media-id",
                        "type": "image",
                        "url": "https://example.test/photo.png",
                        "preview_url": "https://example.test/preview.png",
                        "description": None,
                        "processing": "complete",
                        "meta": {},
                    },
                )

            self.assertEqual(request.url.path, "/api/v1/statuses")
            body = json.loads(request.content)
            self.assertEqual(body["status"], "Photo post")
            self.assertEqual(body["media_ids"], ["uploaded-media-id"])
            return httpx.Response(
                200,
                json={
                    "id": "status-id",
                    "content": "<p>Photo post</p>",
                    "visibility": "public",
                    "url": "https://truthsocial.com/@alice/2",
                    "created_at": "2026-08-17T20:00:00.000Z",
                    "in_reply_to_id": None,
                    "media_attachments": [
                        {
                            "id": "uploaded-media-id",
                            "type": "image",
                            "url": "https://example.test/photo.png",
                            "preview_url": "https://example.test/preview.png",
                            "description": None,
                            "processing": "complete",
                            "meta": {},
                        }
                    ],
                },
            )

        client = self.make_client(handler, access_token="access-token")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "photo.png")
            path.write_bytes(b"image contents")
            status = client.post_status(
                "Photo post",
                media_files=[path],
            )

        self.assertEqual(requests, ["/api/v1/media", "/api/v1/statuses"])
        self.assertEqual(status.media_attachments[0].id, "uploaded-media-id")

    def test_reply_posts_parent_id(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.url.path, "/api/v1/statuses")
            body = json.loads(request.content)
            self.assertEqual(body["status"], "This is a reply")
            self.assertEqual(body["in_reply_to_id"], "parent-status-id")
            self.assertEqual(body["media_ids"], [])
            return httpx.Response(
                200,
                json={
                    "id": "reply-id",
                    "content": "<p>This is a reply</p>",
                    "visibility": "public",
                    "url": "https://truthsocial.com/@alice/3",
                    "created_at": "2026-08-17T20:00:00.000Z",
                    "in_reply_to_id": "parent-status-id",
                    "media_attachments": [],
                },
            )

        client = self.make_client(handler, access_token="access-token")
        reply = client.reply("parent-status-id", "This is a reply")

        self.assertEqual(reply.id, "reply-id")
        self.assertEqual(reply.in_reply_to_id, "parent-status-id")

    def test_reply_accepts_status_model(self):
        parent = Status.from_payload(
            {
                "id": "parent-status-id",
                "content": "<p>Parent</p>",
                "visibility": "public",
            }
        )

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(
                json.loads(request.content)["in_reply_to_id"],
                parent.id,
            )
            return httpx.Response(
                200,
                json={
                    "id": "reply-id",
                    "content": "<p>Reply</p>",
                    "visibility": "public",
                    "in_reply_to_id": parent.id,
                },
            )

        client = self.make_client(handler, access_token="access-token")
        reply = client.reply(parent, "Reply")

        self.assertEqual(reply.in_reply_to_id, parent.id)

    def test_empty_status_requires_media_or_poll(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.fail(f"unexpected request: {request.url}")

        client = self.make_client(handler, access_token="access-token")

        with self.assertRaisesRegex(ValueError, "text, media, or a poll"):
            client.post_status("  ")

    def test_string_media_ids_are_rejected(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.fail(f"unexpected request: {request.url}")

        client = self.make_client(handler, access_token="access-token")

        with self.assertRaisesRegex(TypeError, "iterable"):
            client.post_status("Hello", media_ids="not-a-list")

    def test_media_ids_and_files_cannot_be_combined(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.fail(f"unexpected request: {request.url}")

        client = self.make_client(handler, access_token="access-token")

        with self.assertRaisesRegex(ValueError, "cannot be used together"):
            client.post_status(
                "Hello",
                media_ids=["media-id"],
                media_files=[Path("photo.png")],
            )

    def test_upload_stream_without_filename_is_rejected(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.fail(f"unexpected request: {request.url}")

        client = self.make_client(handler, access_token="access-token")

        with self.assertRaisesRegex(ValueError, "filename is required"):
            client.upload_media(io.BytesIO(b"contents"))

    def test_upload_requires_binary_stream(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.fail(f"unexpected request: {request.url}")

        client = self.make_client(handler, access_token="access-token")

        with self.assertRaisesRegex(TypeError, "binary mode"):
            client.upload_media(io.StringIO("contents"), filename="photo.txt")

    def test_unauthorized_response_is_authentication_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"error": "invalid_token"})

        client = self.make_client(handler, access_token="rejected-token")

        with self.assertRaises(AuthenticationError) as raised:
            client.verify_credentials()

        self.assertEqual(raised.exception.status_code, 401)
        self.assertNotIn("rejected-token", str(raised.exception))

    def test_rate_limit_error_exposes_retry_after(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                429,
                headers={"retry-after": "12.5", "x-request-id": "request-1"},
                json={"error": "Too many requests"},
            )

        client = self.make_client(handler, access_token="access-token")

        with self.assertRaises(RateLimitError) as raised:
            client.post_status("Hello")

        self.assertEqual(raised.exception.retry_after, 12.5)
        self.assertEqual(raised.exception.request_id, "request-1")

    def test_other_api_errors_preserve_status_and_message(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(422, json={"error": "Validation failed"})

        client = self.make_client(handler, access_token="access-token")

        with self.assertRaises(APIError) as raised:
            client.post_status("Hello")

        self.assertEqual(raised.exception.status_code, 422)
        self.assertIn("Validation failed", str(raised.exception))

    def test_non_json_success_is_protocol_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="not JSON")

        client = self.make_client(handler, access_token="access-token")

        with self.assertRaises(ProtocolError):
            client.verify_credentials()

    def test_transport_failure_is_network_error(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection failed", request=request)

        client = self.make_client(handler, access_token="access-token")

        with self.assertRaises(NetworkError) as raised:
            client.verify_credentials()

        self.assertIsInstance(raised.exception.__cause__, httpx.ConnectError)

    def test_invalid_base_url_is_rejected(self):
        with self.assertRaises(ConfigurationError):
            TruthSocialClient(base_url="file:///tmp/truth")

    def test_invalid_truth_session_id_is_rejected(self):
        with self.assertRaises(ConfigurationError):
            TruthSocialClient(truth_session_id="")


if __name__ == "__main__":
    unittest.main()
