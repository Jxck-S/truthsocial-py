from __future__ import annotations

from threading import RLock
from typing import Callable, TypeAlias

import httpx

from .client import (
    DEFAULT_BASE_URL,
    DEFAULT_SCOPE,
    OOB_REDIRECT_URI,
    TruthSocialClient,
    _is_header_safe,
    _normalize_base_url,
)
from .errors import (
    AuthenticationError,
    ConfigurationError,
    DeviceChallengeRequired,
    MfaRequired,
    TruthSocialError,
)
from .models import OAuthAppCredentials

TransportFactory: TypeAlias = Callable[[], httpx.BaseTransport]


class TruthSocialApp:
    """OAuth application identity that creates independent user clients."""

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float | httpx.Timeout | None = 20.0,
        transport_factory: TransportFactory | None = None,
        auto_rediscover: bool = False,
        user_agent: str | None = None,
    ) -> None:
        self._base_url = _normalize_base_url(base_url)
        self._timeout = timeout
        self._transport_factory = transport_factory
        self._user_agent = user_agent
        self._auto_rediscover = auto_rediscover
        self._lock = RLock()

        if transport_factory is not None and not callable(transport_factory):
            raise ConfigurationError("transport_factory must be callable")
        if not isinstance(auto_rediscover, bool):
            raise ConfigurationError("auto_rediscover must be a boolean")
        if user_agent is not None and not _is_header_safe(user_agent):
            raise ConfigurationError(
                "user_agent must be a non-empty header-safe string"
            )

        self._credentials = OAuthAppCredentials(
            client_id=self._validate_credential("client_id", client_id),
            client_secret=self._validate_credential(
                "client_secret",
                client_secret,
            ),
        )

    @classmethod
    def from_web(
        cls,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float | httpx.Timeout | None = 20.0,
        transport_factory: TransportFactory | None = None,
        auto_rediscover: bool = True,
        user_agent: str | None = None,
    ) -> TruthSocialApp:
        """Create an app from the OAuth identity in the deployed web client."""

        if not isinstance(auto_rediscover, bool):
            raise ConfigurationError("auto_rediscover must be a boolean")
        normalized_base_url = _normalize_base_url(base_url)
        with TruthSocialClient(
            base_url=normalized_base_url,
            timeout=timeout,
            transport=cls._make_transport_from_factory(transport_factory),
            user_agent=user_agent,
        ) as client:
            credentials = client.discover_web_app_credentials()

        app = cls(
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
            base_url=normalized_base_url,
            timeout=timeout,
            transport_factory=transport_factory,
            auto_rediscover=auto_rediscover,
            user_agent=user_agent,
        )
        app._credentials = credentials
        return app

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def credentials(self) -> OAuthAppCredentials:
        with self._lock:
            return self._credentials

    @property
    def auto_rediscover(self) -> bool:
        return self._auto_rediscover

    @property
    def user_agent(self) -> str | None:
        """Override sent as User-Agent, or None to use the library default."""

        return self._user_agent

    @property
    def credential_source(self) -> str:
        return "web" if self.credentials.source_url is not None else "manual"

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"base_url={self._base_url!r}, "
            f"credential_source={self.credential_source!r}, "
            f"auto_rediscover={self._auto_rediscover})"
        )

    def rediscover(self) -> OAuthAppCredentials:
        """Replace the app identity with the current deployed web identity."""

        with self._discovery_client() as client:
            credentials = client.discover_web_app_credentials()
        with self._lock:
            self._credentials = credentials
        return credentials

    def new_client(
        self,
        *,
        access_token: str | None = None,
    ) -> TruthSocialClient:
        """Create a separate client configured with this app identity."""

        return self._new_client(
            credentials=self.credentials,
            access_token=access_token,
        )

    def login(
        self,
        username: str,
        password: str,
        *,
        scope: str = DEFAULT_SCOPE,
        redirect_uri: str = OOB_REDIRECT_URI,
    ) -> TruthSocialClient:
        """Create and authenticate an independent user client."""

        try:
            return self._login_once(
                username,
                password,
                scope=scope,
                redirect_uri=redirect_uri,
            )
        except (DeviceChallengeRequired, MfaRequired):
            # The credentials were accepted; rediscovering and retrying would
            # only burn a second failed attempt. The caller must answer the
            # challenge instead.
            raise
        except AuthenticationError as exc:
            if (
                not self._auto_rediscover
                or not self._is_invalid_client_error(exc)
            ):
                raise

        self.rediscover()
        return self._login_once(
            username,
            password,
            scope=scope,
            redirect_uri=redirect_uri,
        )

    def _login_once(
        self,
        username: str,
        password: str,
        *,
        scope: str,
        redirect_uri: str,
    ) -> TruthSocialClient:
        client = self.new_client()
        try:
            client.login(
                username,
                password,
                scope=scope,
                redirect_uri=redirect_uri,
            )
        except TruthSocialError:
            client.close()
            raise
        return client

    def _new_client(
        self,
        *,
        credentials: OAuthAppCredentials,
        access_token: str | None = None,
    ) -> TruthSocialClient:
        return TruthSocialClient(
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
            access_token=access_token,
            base_url=self._base_url,
            timeout=self._timeout,
            transport=self._make_transport(),
            user_agent=self._user_agent,
        )

    def _discovery_client(self) -> TruthSocialClient:
        return TruthSocialClient(
            base_url=self._base_url,
            timeout=self._timeout,
            transport=self._make_transport(),
            user_agent=self._user_agent,
        )

    def _make_transport(self) -> httpx.BaseTransport | None:
        return self._make_transport_from_factory(self._transport_factory)

    @staticmethod
    def _make_transport_from_factory(
        transport_factory: TransportFactory | None,
    ) -> httpx.BaseTransport | None:
        if transport_factory is None:
            return None
        if not callable(transport_factory):
            raise ConfigurationError("transport_factory must be callable")
        transport = transport_factory()
        if not isinstance(transport, httpx.BaseTransport):
            raise ConfigurationError(
                "transport_factory must return an httpx.BaseTransport"
            )
        return transport

    @staticmethod
    def _validate_credential(name: str, value: str) -> str:
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or "\r" in value
            or "\n" in value
        ):
            raise ConfigurationError(
                f"{name} must be a non-empty header-safe string"
            )
        return value

    @staticmethod
    def _is_invalid_client_error(error: AuthenticationError) -> bool:
        error_code = (error.error_code or "").casefold()
        if error_code in {"invalid_client", "unauthorized_client"}:
            return True
        message = error.message.casefold().replace("_", " ")
        return any(
            marker in message
            for marker in (
                "invalid client",
                "client credentials",
                "unauthorized client",
            )
        )
