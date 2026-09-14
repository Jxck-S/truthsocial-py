from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import DeviceChallenge, MfaChallenge


class TruthSocialError(Exception):
    """Base exception for all truthsocial-py errors."""


class ConfigurationError(TruthSocialError):
    """Raised when the client is not configured for an operation."""


class NotAuthenticatedError(ConfigurationError):
    """Raised when an authenticated operation has no access token."""


class NetworkError(TruthSocialError):
    """Raised when a request cannot reach Truth Social."""


class ProtocolError(TruthSocialError):
    """Raised when Truth Social returns an unexpected response shape."""


class CredentialDiscoveryError(TruthSocialError):
    """Raised when public web-app OAuth credentials cannot be discovered."""


class APIError(TruthSocialError):
    """Raised when Truth Social returns an unsuccessful HTTP response."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        request_id: str | None = None,
        error_code: str | None = None,
    ) -> None:
        self.message = message
        self.status_code = status_code
        self.request_id = request_id
        self.error_code = error_code

        suffix = f" (HTTP {status_code}"
        if request_id:
            suffix += f", request {request_id}"
        suffix += ")"
        super().__init__(message + suffix)


class AuthenticationError(APIError):
    """Raised when login fails or an access token is rejected."""


class DeviceChallengeRequired(AuthenticationError):
    """Raised when Truth Social wants a security code for an unknown device.

    This is *not* a bad-credentials failure: the username and password were
    accepted, but the login came from a device Truth Social has not seen
    before, so it wants a 6-digit code delivered out of band first. Callers
    should branch on this exception type rather than on ``error_code``.

    ``challenge`` carries the ``challenge_id`` and the delivery options needed
    to continue via :meth:`TruthSocialClient.send_security_code` and
    :meth:`TruthSocialClient.login_with_security_code`.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        challenge: DeviceChallenge,
        request_id: str | None = None,
        error_code: str | None = None,
    ) -> None:
        self.challenge = challenge
        super().__init__(
            message,
            status_code=status_code,
            request_id=request_id,
            error_code=error_code,
        )


class MfaRequired(AuthenticationError):
    """Raised when an account has 2FA enabled and needs an authenticator code.

    Like :class:`DeviceChallengeRequired` this means the password was
    accepted. ``challenge`` carries the short-lived ``mfa_token`` that
    :meth:`TruthSocialClient.login_with_mfa_code` redeems along with the code.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        challenge: MfaChallenge,
        request_id: str | None = None,
        error_code: str | None = None,
    ) -> None:
        self.challenge = challenge
        super().__init__(
            message,
            status_code=status_code,
            request_id=request_id,
            error_code=error_code,
        )


class ForbiddenError(APIError):
    """Raised when Truth Social rejects a request without saying why.

    This is a 403 that carries no JSON body at all -- no ``error`` code, no
    ``detail``, and no ``x-request-id`` header. The API itself always explains
    an app-level refusal, so a bodiless 403 comes from the edge in front of it
    (bot/WAF scoring) rather than from Truth Social's application layer.

    It is deliberately *not* an :class:`AuthenticationError`: the access token
    is untouched and still valid. Re-authenticating in response to one throws
    away a working session and, on a 2FA account, burns a TOTP code for
    nothing. Treat it as a transient refusal of that single request -- back off
    and retry later, or degrade (for example, post without the attachment).

    ``/api/v1/media`` is by far the most common source.
    """


class RateLimitError(APIError):
    """Raised when Truth Social rejects a request for exceeding a rate limit."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        request_id: str | None = None,
        retry_after: float | None = None,
        error_code: str | None = None,
    ) -> None:
        self.retry_after = retry_after
        super().__init__(
            message,
            status_code=status_code,
            request_id=request_id,
            error_code=error_code,
        )
