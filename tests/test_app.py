from __future__ import annotations

import json
import unittest

import httpx

from truthpy import (
    AuthenticationError,
    ConfigurationError,
    TruthSocialApp,
)

OLD_CLIENT_ID = "old-web-client-id-1234567890"
OLD_CLIENT_SECRET = "old-web-client-secret-1234567890"
NEW_CLIENT_ID = "new-web-client-id-1234567890"
NEW_CLIENT_SECRET = "new-web-client-secret-1234567890"


def web_bundle(client_id: str, client_secret: str) -> str:
    return (
        "const env={};"
        "const oauth={"
        f'client_id:env.VITE_OAUTH_CLIENT_ID||"{client_id}",'
        f'client_secret:env.VITE_OAUTH_CLIENT_SECRET||"{client_secret}",'
        'redirect_uri:"urn:ietf:wg:oauth:2.0:oob"};'
        'const request={...oauth,grant_type:"password"};'
    )


class TruthSocialAppTests(unittest.TestCase):
    def test_manual_app_creates_isolated_logged_in_users(self):
        login_bodies = []
        factory_calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            login_bodies.append(body)
            return httpx.Response(
                200,
                json={
                    "access_token": f"{body['username']}-token",
                    "token_type": "Bearer",
                },
            )

        def transport_factory() -> httpx.BaseTransport:
            nonlocal factory_calls
            factory_calls += 1
            return httpx.MockTransport(handler)

        app = TruthSocialApp(
            client_id="manual-client-id",
            client_secret="manual-client-secret",
            transport_factory=transport_factory,
        )
        alice = app.login("alice", "alice-password")
        bob = app.login("bob", "bob-password")
        self.addCleanup(alice.close)
        self.addCleanup(bob.close)

        self.assertIsNot(alice, bob)
        self.assertNotEqual(alice.truth_session_id, bob.truth_session_id)
        self.assertEqual(alice.access_token, "alice-token")
        self.assertEqual(bob.access_token, "bob-token")
        self.assertEqual(factory_calls, 2)
        self.assertEqual(
            [body["username"] for body in login_bodies],
            ["alice", "bob"],
        )
        self.assertTrue(
            all(
                body["client_id"] == "manual-client-id"
                and body["client_secret"] == "manual-client-secret"
                for body in login_bodies
            )
        )
        self.assertEqual(app.credential_source, "manual")
        self.assertNotIn("manual-client-secret", repr(app))

    def test_from_web_loads_discovered_app_identity(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(
                    200,
                    html='<script src="/assets/app.js"></script>',
                )
            if request.url.path == "/assets/app.js":
                return httpx.Response(
                    200,
                    text=web_bundle(OLD_CLIENT_ID, OLD_CLIENT_SECRET),
                )
            self.fail(f"unexpected request: {request.url}")

        app = TruthSocialApp.from_web(
            transport_factory=lambda: httpx.MockTransport(handler)
        )

        self.assertEqual(app.credentials.client_id, OLD_CLIENT_ID)
        self.assertEqual(app.credentials.client_secret, OLD_CLIENT_SECRET)
        self.assertEqual(app.credential_source, "web")
        self.assertTrue(app.auto_rediscover)
        self.assertNotIn(OLD_CLIENT_SECRET, repr(app.credentials))

    def test_explicit_rediscovery_updates_only_future_clients(self):
        token_client_ids = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/":
                return httpx.Response(
                    200,
                    html='<script src="/assets/app.js"></script>',
                )
            if request.url.path == "/assets/app.js":
                return httpx.Response(
                    200,
                    text=web_bundle(NEW_CLIENT_ID, NEW_CLIENT_SECRET),
                )
            if request.url.path == "/oauth/v2/token":
                body = json.loads(request.content)
                token_client_ids.append(body["client_id"])
                return httpx.Response(
                    200,
                    json={
                        "access_token": f"token-{len(token_client_ids)}",
                        "token_type": "Bearer",
                    },
                )
            self.fail(f"unexpected request: {request.url}")

        app = TruthSocialApp(
            client_id="manual-client-id",
            client_secret="manual-client-secret",
            transport_factory=lambda: httpx.MockTransport(handler),
        )
        old_client = app.new_client()
        self.addCleanup(old_client.close)

        credentials = app.rediscover()
        old_client.login("old-user", "password")
        new_client = app.login("new-user", "password")
        self.addCleanup(new_client.close)

        self.assertEqual(credentials.client_id, NEW_CLIENT_ID)
        self.assertEqual(app.credential_source, "web")
        self.assertEqual(
            token_client_ids,
            ["manual-client-id", NEW_CLIENT_ID],
        )

    def test_invalid_client_login_rediscovery_retries_once(self):
        discovery_count = 0
        token_client_ids = []

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal discovery_count
            if request.url.path == "/":
                discovery_count += 1
                return httpx.Response(
                    200,
                    html='<script src="/assets/app.js"></script>',
                )
            if request.url.path == "/assets/app.js":
                pair = (
                    (OLD_CLIENT_ID, OLD_CLIENT_SECRET)
                    if discovery_count == 1
                    else (NEW_CLIENT_ID, NEW_CLIENT_SECRET)
                )
                return httpx.Response(200, text=web_bundle(*pair))
            if request.url.path == "/oauth/v2/token":
                body = json.loads(request.content)
                token_client_ids.append(body["client_id"])
                if body["client_id"] == OLD_CLIENT_ID:
                    return httpx.Response(
                        401,
                        json={
                            "error": "invalid_client",
                            "error_description": "OAuth client is stale",
                        },
                    )
                return httpx.Response(
                    200,
                    json={
                        "access_token": "new-access-token",
                        "token_type": "Bearer",
                    },
                )
            self.fail(f"unexpected request: {request.url}")

        app = TruthSocialApp.from_web(
            transport_factory=lambda: httpx.MockTransport(handler)
        )
        user = app.login("alice", "account-password")
        self.addCleanup(user.close)

        self.assertEqual(user.access_token, "new-access-token")
        self.assertEqual(discovery_count, 2)
        self.assertEqual(token_client_ids, [OLD_CLIENT_ID, NEW_CLIENT_ID])
        self.assertEqual(app.credentials.client_id, NEW_CLIENT_ID)

    def test_bad_password_does_not_trigger_rediscovery(self):
        discovery_count = 0
        token_attempts = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal discovery_count, token_attempts
            if request.url.path == "/":
                discovery_count += 1
                return httpx.Response(
                    200,
                    html='<script src="/assets/app.js"></script>',
                )
            if request.url.path == "/assets/app.js":
                return httpx.Response(
                    200,
                    text=web_bundle(OLD_CLIENT_ID, OLD_CLIENT_SECRET),
                )
            if request.url.path == "/oauth/v2/token":
                token_attempts += 1
                return httpx.Response(
                    401,
                    json={
                        "error": "invalid_grant",
                        "error_description": "Invalid username or password",
                    },
                )
            self.fail(f"unexpected request: {request.url}")

        app = TruthSocialApp.from_web(
            transport_factory=lambda: httpx.MockTransport(handler)
        )

        with self.assertRaises(AuthenticationError) as raised:
            app.login("alice", "wrong-password")

        self.assertEqual(raised.exception.error_code, "invalid_grant")
        self.assertEqual(discovery_count, 1)
        self.assertEqual(token_attempts, 1)

    def test_manual_app_does_not_auto_replace_invalid_credentials(self):
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request.url.path)
            return httpx.Response(
                401,
                json={"error": "invalid_client"},
            )

        app = TruthSocialApp(
            client_id="stale-client-id",
            client_secret="stale-client-secret",
            transport_factory=lambda: httpx.MockTransport(handler),
        )

        with self.assertRaises(AuthenticationError):
            app.login("alice", "password")

        self.assertEqual(requests, ["/oauth/v2/token"])
        self.assertEqual(app.credentials.client_id, "stale-client-id")

    def test_new_client_can_start_from_an_existing_access_token(self):
        app = TruthSocialApp(
            client_id="manual-client-id",
            client_secret="manual-client-secret",
        )

        client = app.new_client(access_token="saved-access-token")
        self.addCleanup(client.close)

        self.assertEqual(client.access_token, "saved-access-token")
        self.assertTrue(client.is_authenticated)

    def test_app_rejects_invalid_configuration(self):
        with self.assertRaises(ConfigurationError):
            TruthSocialApp(client_id="", client_secret="secret")

        with self.assertRaises(ConfigurationError):
            TruthSocialApp(
                client_id="client",
                client_secret="secret",
                auto_rediscover="yes",
            )

        app = TruthSocialApp(
            client_id="client",
            client_secret="secret",
            transport_factory=lambda: object(),
        )
        with self.assertRaisesRegex(ConfigurationError, "BaseTransport"):
            app.new_client()


if __name__ == "__main__":
    unittest.main()
