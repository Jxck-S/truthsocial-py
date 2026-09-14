from __future__ import annotations

import io
import unittest

import httpx

from truthsocial_py import (
    APIError,
    AuthenticationError,
    DeviceChallengeRequired,
    ForbiddenError,
    MfaRequired,
    TruthSocialClient,
)


def client_with(handler, *, access_token: str | None = "access-token"):
    return TruthSocialClient(
        client_id="app-client-id",
        client_secret="app-client-secret",
        access_token=access_token,
        transport=httpx.MockTransport(handler),
    )


class BodilessForbiddenTests(unittest.TestCase):
    """A 403 with no JSON body is an edge refusal, not an auth failure.

    Captured from production: the edge in front of /api/v1/media rejects a
    fraction of uploads with an empty 403 -- no body, no x-request-id -- while
    the very same access token keeps working on /api/v1/statuses.
    """

    def test_bodiless_403_raises_forbidden_not_authentication(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.path, "/api/v1/media")
            return httpx.Response(403, content=b"")

        with client_with(handler) as client:
            with self.assertRaises(ForbiddenError) as ctx:
                client.upload_media(io.BytesIO(b"png"), filename="photo.png")

        error = ctx.exception
        # The whole point: callers must not be told to re-authenticate.
        self.assertNotIsInstance(error, AuthenticationError)
        self.assertIsInstance(error, APIError)
        self.assertEqual(error.status_code, 403)
        self.assertIsNone(error.error_code)
        self.assertIsNone(error.request_id)

    def test_non_json_403_body_is_also_forbidden(self) -> None:
        """WAF blocks often return an HTML interstitial rather than nothing."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, html="<html>Forbidden</html>")

        with client_with(handler) as client:
            with self.assertRaises(ForbiddenError):
                client.upload_media(io.BytesIO(b"png"), filename="photo.png")

    def test_json_403_body_that_is_not_an_object_is_forbidden(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, json=["nope"])

        with client_with(handler) as client:
            with self.assertRaises(ForbiddenError):
                client.upload_media(io.BytesIO(b"png"), filename="photo.png")


class GenuineAuthFailuresStillAuthenticateTests(unittest.TestCase):
    """Anything that actually explains itself keeps the old classification."""

    def test_403_with_error_payload_is_authentication_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, json={"error": "invalid_token"})

        with client_with(handler) as client:
            with self.assertRaises(AuthenticationError) as ctx:
                client.verify_credentials()

        self.assertNotIsInstance(ctx.exception, ForbiddenError)
        self.assertEqual(ctx.exception.error_code, "invalid_token")

    def test_403_with_detail_but_no_error_code_is_authentication_error(
        self,
    ) -> None:
        """A body without an `error` key still means the app answered."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(403, json={"detail": "forbidden"})

        with client_with(handler) as client:
            with self.assertRaises(AuthenticationError) as ctx:
                client.verify_credentials()

        self.assertNotIsInstance(ctx.exception, ForbiddenError)

    def test_bodiless_401_is_still_authentication_error(self) -> None:
        """Only 403 is reclassified; 401 is unambiguous."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, content=b"")

        with client_with(handler) as client:
            with self.assertRaises(AuthenticationError) as ctx:
                client.verify_credentials()

        self.assertNotIsInstance(ctx.exception, ForbiddenError)

    def test_mfa_and_device_challenge_still_take_priority(self) -> None:
        """Both carry a body, so they are matched before the bodiless check."""
        for error_code, expected in (
            ("mfa_required", MfaRequired),
            ("security_code_required", DeviceChallengeRequired),
        ):
            with self.subTest(error_code=error_code):

                def handler(request: httpx.Request) -> httpx.Response:
                    return httpx.Response(
                        403,
                        json={
                            "error": error_code,
                            "mfa_token": "tok",
                            "challenge_id": "cid",
                            "supported_challenge_types": "totp",
                        },
                    )

                with client_with(handler, access_token=None) as client:
                    with self.assertRaises(expected) as ctx:
                        client.login("someone", "hunter2")

                self.assertIsInstance(ctx.exception, AuthenticationError)
                self.assertNotIsInstance(ctx.exception, ForbiddenError)


if __name__ == "__main__":
    unittest.main()
