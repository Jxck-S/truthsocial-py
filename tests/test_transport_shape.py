from __future__ import annotations

import unittest

import httpx

from http.cookiejar import CookieJar

from truthsocial_py import ConfigurationError, TruthSocialClient

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
)
# Low-entropy client hints only: truthsocial.com sends no Accept-CH, so a real
# Chrome never volunteers the high-entropy set.
CHROME_HINTS = {
    "Sec-CH-UA": '"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
    "Accept-Language": "en-US,en;q=0.9",
    "Origin": "https://truthsocial.com",
    "Referer": "https://truthsocial.com/",
}


class ExtraHeadersTests(unittest.TestCase):
    def test_caller_headers_are_sent(self) -> None:
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen.update(request.headers)
            return httpx.Response(200, json={"id": "u1", "acct": "a"})

        client = TruthSocialClient(
            access_token="token",
            user_agent=CHROME_UA,
            headers=CHROME_HINTS,
            transport=httpx.MockTransport(handler),
        )
        with client:
            client.verify_credentials()

        for name, value in CHROME_HINTS.items():
            self.assertEqual(seen[name.lower()], value)
        self.assertEqual(seen["user-agent"], CHROME_UA)
        # The library's own header survives alongside them.
        self.assertIn("x-truth-session-id", seen)

    def test_caller_headers_override_defaults(self) -> None:
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen.update(request.headers)
            return httpx.Response(200, json={"id": "u1", "acct": "a"})

        client = TruthSocialClient(
            access_token="token",
            headers={"Accept": "application/json, text/plain, */*"},
            transport=httpx.MockTransport(handler),
        )
        with client:
            client.verify_credentials()

        self.assertEqual(seen["accept"], "application/json, text/plain, */*")

    def test_authorization_cannot_be_pinned(self) -> None:
        with self.assertRaises(ConfigurationError):
            TruthSocialClient(headers={"Authorization": "Bearer nope"})

    def test_unsafe_header_rejected(self) -> None:
        with self.assertRaises(ConfigurationError):
            TruthSocialClient(headers={"X-Bad": "line\r\ninjection"})

    def test_access_token_still_wins_for_authorization(self) -> None:
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen.update(request.headers)
            return httpx.Response(200, json={"id": "u1", "acct": "a"})

        client = TruthSocialClient(
            access_token="real-token",
            headers=CHROME_HINTS,
            transport=httpx.MockTransport(handler),
        )
        with client:
            client.verify_credentials()

        self.assertEqual(seen["authorization"], "Bearer real-token")


class Http2OptionTests(unittest.TestCase):
    def test_http2_must_be_a_bool(self) -> None:
        with self.assertRaises(ConfigurationError):
            TruthSocialClient(http2="yes")

    def test_default_is_http1(self) -> None:
        """Opt-in: h2 is an optional extra, so the default must not need it."""
        client = TruthSocialClient()
        with client:
            self.assertFalse(client._http._transport._pool._http2)


class CookieJarTests(unittest.TestCase):
    def test_cookies_are_shared_with_the_caller_jar(self) -> None:
        """Cloudflare's __cf_bm must survive across clients built from one jar."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"id": "u1", "acct": "a"},
                headers={"set-cookie": "__cf_bm=abc123; Path=/"},
            )

        jar = CookieJar()
        first = TruthSocialClient(
            access_token="token",
            cookies=jar,
            transport=httpx.MockTransport(handler),
        )
        with first:
            first.verify_credentials()

        self.assertEqual(
            [c.value for c in jar if c.name == "__cf_bm"], ["abc123"]
        )

        # A second client built from the same jar presents the cookie.
        sent = {}

        def echo(request: httpx.Request) -> httpx.Response:
            sent["cookie"] = request.headers.get("cookie", "")
            return httpx.Response(200, json={"id": "u1", "acct": "a"})

        second = TruthSocialClient(
            access_token="token",
            cookies=jar,
            transport=httpx.MockTransport(echo),
        )
        with second:
            second.verify_credentials()

        self.assertIn("__cf_bm=abc123", sent["cookie"])


if __name__ == "__main__":
    unittest.main()
