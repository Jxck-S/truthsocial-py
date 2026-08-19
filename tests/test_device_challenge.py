from __future__ import annotations

import json
import unittest

import httpx

from truthsocial_py import (
    AuthenticationError,
    ConfigurationError,
    DeliveryMethod,
    DeviceChallenge,
    DeviceChallengeRequired,
    TruthSocialClient,
)

CHALLENGE_BODY = {
    "error": "security_code_required",
    "challenge_id": "chal-123",
    "user_id": "108020950607433211",
    "supported_delivery_methods": [
        {"kind": "email", "value": "j***@example.com"},
        {"kind": "sms", "value": "+1 (***) ***-4321"},
    ],
    "errors": [
        {
            "error_code": "security_code_required",
            "error_message": (
                "New device login detected. Please select a delivery "
                "method for your security code."
            ),
        }
    ],
}


def client_with(handler) -> TruthSocialClient:
    return TruthSocialClient(
        client_id="app-client-id",
        client_secret="app-client-secret",
        transport=httpx.MockTransport(handler),
    )


class DeviceChallengeTests(unittest.TestCase):
    def test_login_raises_device_challenge_with_details(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.path, "/oauth/v2/token")
            return httpx.Response(
                403,
                json=CHALLENGE_BODY,
                headers={"x-request-id": "req-9"},
            )

        with client_with(handler) as client:
            with self.assertRaises(DeviceChallengeRequired) as ctx:
                client.login("someone", "hunter2")

        error = ctx.exception
        self.assertIsInstance(error, AuthenticationError)
        self.assertEqual(error.status_code, 403)
        self.assertEqual(error.error_code, "security_code_required")
        self.assertEqual(error.request_id, "req-9")
        self.assertIn("New device login detected", error.message)

        challenge = error.challenge
        self.assertEqual(challenge.challenge_id, "chal-123")
        self.assertEqual(challenge.username, "someone")
        self.assertEqual(challenge.delivery_kinds, ("email", "sms"))
        self.assertEqual(
            challenge.option_for(DeliveryMethod.EMAIL).value,
            "j***@example.com",
        )
        self.assertIsNone(challenge.option_for("push"))

    def test_bad_password_is_not_a_device_challenge(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                403,
                json={"error": "invalid_grant"},
            )

        with client_with(handler) as client:
            with self.assertRaises(AuthenticationError) as ctx:
                client.login("someone", "wrong")
        self.assertNotIsInstance(ctx.exception, DeviceChallengeRequired)

    def test_send_security_code_posts_choice(self) -> None:
        seen: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(
                request.url.path, "/oauth/v2/choose_delivery_method"
            )
            self.assertIsNone(request.headers.get("authorization"))
            seen.append(json.loads(request.content))
            return httpx.Response(200, json={"success": True})

        challenge = DeviceChallenge.from_payload(
            CHALLENGE_BODY, username="someone"
        )
        with client_with(handler) as client:
            client.send_security_code(challenge, DeliveryMethod.SMS)

        self.assertEqual(
            seen,
            [
                {
                    "username": "someone",
                    "challenge_id": "chal-123",
                    "delivery_method": "sms",
                }
            ],
        )

    def test_send_security_code_rejects_unoffered_method(self) -> None:
        challenge = DeviceChallenge.from_payload(
            {
                "challenge_id": "chal-123",
                "supported_delivery_methods": [{"kind": "email"}],
            },
            username="someone",
        )

        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("no request should be made")

        with client_with(handler) as client:
            with self.assertRaises(ConfigurationError):
                client.send_security_code(challenge, "sms")

    def test_send_security_code_requires_username_for_bare_id(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"success": True})

        with client_with(handler) as client:
            with self.assertRaises(ConfigurationError):
                client.send_security_code("chal-123", "email")
            client.send_security_code("chal-123", "email", username="someone")

    def test_login_with_security_code_returns_token(self) -> None:
        seen: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(
                request.url.path, "/oauth/v2/verify_security_code"
            )
            seen.append(json.loads(request.content))
            return httpx.Response(
                200,
                json={"access_token": "tok-abc", "token_type": "Bearer"},
            )

        challenge = DeviceChallenge.from_payload(
            CHALLENGE_BODY, username="someone"
        )
        with client_with(handler) as client:
            token = client.login_with_security_code(
                "someone",
                "hunter2",
                security_code=" 123456 ",
                challenge=challenge,
            )
            self.assertEqual(client.access_token, "tok-abc")

        self.assertEqual(token.access_token, "tok-abc")
        body = seen[0]
        self.assertEqual(body["challenge_id"], "chal-123")
        self.assertEqual(body["security_code"], "123456")
        self.assertEqual(body["grant_type"], "password")
        self.assertEqual(body["username"], "someone")
        self.assertEqual(body["password"], "hunter2")

    def test_login_with_security_code_rejects_blank_code(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("no request should be made")

        with client_with(handler) as client:
            with self.assertRaises(ConfigurationError):
                client.login_with_security_code(
                    "someone",
                    "hunter2",
                    security_code="   ",
                    challenge="chal-123",
                )

    def test_wrong_code_surfaces_human_message(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                403,
                json={
                    "error": "invalid_security_code",
                    "errors": [
                        {
                            "error_code": "invalid_security_code",
                            "error_message": "Invalid code, please try again.",
                        }
                    ],
                },
            )

        with client_with(handler) as client:
            with self.assertRaises(AuthenticationError) as ctx:
                client.login_with_security_code(
                    "someone",
                    "hunter2",
                    security_code="000000",
                    challenge="chal-123",
                )
        self.assertEqual(
            ctx.exception.message, "Invalid code, please try again."
        )
        self.assertNotIsInstance(ctx.exception, DeviceChallengeRequired)

    def test_secrets_are_not_leaked_in_error_text(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, json=CHALLENGE_BODY)

        with client_with(handler) as client:
            with self.assertRaises(DeviceChallengeRequired) as ctx:
                client.login("someone", "hunter2")
        text = str(ctx.exception) + repr(ctx.exception.challenge)
        self.assertNotIn("hunter2", text)
        self.assertNotIn("app-client-secret", text)


if __name__ == "__main__":
    unittest.main()
