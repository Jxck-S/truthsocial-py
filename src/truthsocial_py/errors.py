from __future__ import annotations


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
