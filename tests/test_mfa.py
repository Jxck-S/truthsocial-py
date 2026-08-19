from __future__ import annotations

import json
import unittest

import httpx

from truthsocial_py import (
    AuthenticationError,
    ConfigurationError,
    DeviceChallengeRequired,
    MfaChallenge,
    MfaRequired,
    TruthSocialClient,
)

MFA_TOKEN = "j3SWspxKKRG5QnMNe6xUiAsGn3Hn92AtPAKOMgC0KX4=="

# Shape captured from a live 2FA login: note supported_challenge_types is a
# bare string, and the errors sentence claims a wrong code before any code
# has been entered.
MFA_BODY = {
    "errors": [
        {
            "error_message": (
                "The 2FA code entered is incorrect. Please try again."
            ),
            "error_field": "mfa",
            "error_code": "MFA_INVALID",
        }
    ],
    "error": "mfa_required",
    "supported_challenge_types": "totp",
    "mfa_token": MFA_TOKEN,
}


def client_with(handler) -> TruthSocialClient:
    return TruthSocialClient(
        client_id="app-client-id",
        client_secret="app-client-secret",
        transport=httpx.MockTransport(handler),
    )


class MfaTests(unittest.TestCase):
    def test_login_raises_mfa_required(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.path, "/oauth/v2/token")
            return httpx.Response(403, json=MFA_BODY)

        with client_with(handler) as client:
            with self.assertRaises(MfaRequired) as ctx:
                client.login("someone", "hunter2")

        error = ctx.exception
        self.assertIsInstance(error, AuthenticationError)
        self.assertNotIsInstance(error, DeviceChallengeRequired)
        self.assertEqual(error.error_code, "mfa_required")
        self.assertEqual(error.challenge.mfa_token, MFA_TOKEN)
        self.assertEqual(error.challenge.username, "someone")
        self.assertEqual(error.challenge.challenge_types, ("totp",))

    def test_misleading_detail_is_not_the_message(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, json=MFA_BODY)

        with client_with(handler) as client:
            with self.assertRaises(MfaRequired) as ctx:
                client.login("someone", "hunter2")

        self.assertNotIn("incorrect", ctx.exception.message)
        self.assertIn("multi-factor", ctx.exception.message)
        # ...but it is still reachable for callers that want it.
        self.assertIn("incorrect", ctx.exception.challenge.detail)

    def test_login_with_mfa_code_returns_token(self) -> None:
        seen: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.path, "/oauth/mfa/challenge")
            self.assertIsNone(request.headers.get("authorization"))
            seen.append(json.loads(request.content))
            return httpx.Response(
                200,
                json={
                    "access_token": "tok-abc",
                    "token_type": "Bearer",
                    "scope": "read write follow push",
                    "created_at": 1787108391,
                },
            )

        challenge = MfaChallenge.from_payload(MFA_BODY, username="someone")
        with client_with(handler) as client:
            token = client.login_with_mfa_code(" 921535 ", challenge=challenge)
            self.assertEqual(client.access_token, "tok-abc")

        self.assertEqual(token.access_token, "tok-abc")
        self.assertEqual(
            seen[0],
            {
                "client_id": "app-client-id",
                "client_secret": "app-client-secret",
                "challenge_type": "totp",
                "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
                "scope": "read write follow push",
                "mfa_token": MFA_TOKEN,
                "code": "921535",
            },
        )

    def test_login_with_mfa_code_accepts_bare_token(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(
                json.loads(request.content)["mfa_token"], MFA_TOKEN
            )
            return httpx.Response(200, json={"access_token": "tok-abc"})

        with client_with(handler) as client:
            client.login_with_mfa_code("921535", challenge=MFA_TOKEN)

    def test_rejects_blank_code_and_unsupported_type(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise AssertionError("no request should be made")

        challenge = MfaChallenge.from_payload(MFA_BODY)
        with client_with(handler) as client:
            with self.assertRaises(ConfigurationError):
                client.login_with_mfa_code("  ", challenge=challenge)
            with self.assertRaises(ConfigurationError):
                client.login_with_mfa_code(
                    "921535", challenge=challenge, challenge_type="sms"
                )
            with self.assertRaises(ConfigurationError):
                client.login_with_mfa_code("921535", challenge="")

    def test_wrong_code_surfaces_human_message(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, json=MFA_BODY | {"error": "invalid"})

        with client_with(handler) as client:
            with self.assertRaises(AuthenticationError) as ctx:
                client.login_with_mfa_code("000000", challenge=MFA_TOKEN)

        self.assertNotIsInstance(ctx.exception, MfaRequired)
        self.assertEqual(
            ctx.exception.message,
            "The 2FA code entered is incorrect. Please try again.",
        )

    def test_secrets_are_not_leaked_in_error_text(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, json=MFA_BODY)

        with client_with(handler) as client:
            with self.assertRaises(MfaRequired) as ctx:
                client.login("someone", "hunter2")

        text = str(ctx.exception) + repr(ctx.exception.challenge)
        self.assertNotIn("hunter2", text)
        self.assertNotIn("app-client-secret", text)
        self.assertNotIn(MFA_TOKEN, text)


if __name__ == "__main__":
    unittest.main()
