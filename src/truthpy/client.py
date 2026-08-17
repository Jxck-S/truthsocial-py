from __future__ import annotations

import io
import json
import mimetypes
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from os import PathLike
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Mapping, TypeAlias
from urllib.parse import urljoin
from uuid import uuid4

import httpx

from ._version import __version__
from .errors import (
    APIError,
    AuthenticationError,
    ConfigurationError,
    CredentialDiscoveryError,
    NetworkError,
    NotAuthenticatedError,
    ProtocolError,
    RateLimitError,
)
from .models import (
    Account,
    MediaAttachment,
    OAuthAppCredentials,
    OAuthToken,
    Status,
    Visibility,
)

DEFAULT_BASE_URL = "https://truthsocial.com"
DEFAULT_SCOPE = "read write follow push"
OOB_REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"
MediaSource: TypeAlias = str | PathLike[str] | BinaryIO

_MAX_DISCOVERY_HTML_BYTES = 1_000_000
_MAX_DISCOVERY_SCRIPT_BYTES = 4_000_000
_MAX_DISCOVERY_TOTAL_SCRIPT_BYTES = 12_000_000
_MAX_DISCOVERY_SCRIPTS = 8
_OAUTH_CREDENTIALS_PATTERN = re.compile(
    r"""["']?client_id["']?\s*:\s*"""
    r"""(?:[^,]{0,160}?\|\|\s*)?["']"""
    r"""(?P<client_id>[A-Za-z0-9._~+\-/=]{20,256})["']\s*,\s*"""
    r"""["']?client_secret["']?\s*:\s*"""
    r"""(?:[^,]{0,160}?\|\|\s*)?["']"""
    r"""(?P<client_secret>[A-Za-z0-9._~+\-/=]{20,256})["']\s*,\s*"""
    r"""["']?redirect_uri["']?\s*:\s*"""
    r"""["']urn:ietf:wg:oauth:2\.0:oob["']"""
)


class _ScriptSourceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.sources: list[str] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        if tag.lower() != "script":
            return
        source = next(
            (
                value
                for name, value in attrs
                if name.lower() == "src" and value
            ),
            None,
        )
        if source:
            self.sources.append(source)


def _normalize_base_url(base_url: str) -> str:
    parsed_base_url = httpx.URL(base_url)
    if (
        parsed_base_url.scheme not in {"http", "https"}
        or not parsed_base_url.host
        or parsed_base_url.query
        or parsed_base_url.fragment
    ):
        raise ConfigurationError(
            "base_url must be an HTTP(S) origin without a query or fragment"
        )
    return str(parsed_base_url).rstrip("/")


class TruthSocialClient:
    """Synchronous client for the Truth Social web API."""

    def __init__(
        self,
        *,
        client_id: str | None = None,
        client_secret: str | None = None,
        access_token: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float | httpx.Timeout | None = 20.0,
        transport: httpx.BaseTransport | None = None,
        truth_session_id: str | None = None,
    ) -> None:
        session_id = (
            str(uuid4()) if truth_session_id is None else truth_session_id
        )
        if (
            not isinstance(session_id, str)
            or not session_id
            or session_id != session_id.strip()
            or "\r" in session_id
            or "\n" in session_id
        ):
            raise ConfigurationError(
                "truth_session_id must be a non-empty header-safe string"
            )

        self._base_url = _normalize_base_url(base_url)
        self._client_id = client_id
        self._client_secret = client_secret
        self._access_token: str | None = None
        self._truth_session_id = session_id
        self._closed = False
        self._http = httpx.Client(
            timeout=timeout,
            transport=transport,
            follow_redirects=False,
            headers={
                "Accept": "application/json",
                "User-Agent": f"truthpy/{__version__}",
                "X-Truth-Session-Id": session_id,
            },
        )

        if access_token is not None:
            self.set_access_token(access_token)

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def access_token(self) -> str | None:
        return self._access_token

    @property
    def truth_session_id(self) -> str:
        return self._truth_session_id

    @property
    def is_authenticated(self) -> bool:
        return self._access_token is not None

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"base_url={self._base_url!r}, "
            f"authenticated={self.is_authenticated})"
        )

    def __enter__(self) -> TruthSocialClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            self._http.close()
            self._closed = True

    def set_access_token(self, access_token: str) -> None:
        if not isinstance(access_token, str) or not access_token:
            raise ConfigurationError("access_token must be a non-empty string")
        if access_token != access_token.strip():
            raise ConfigurationError(
                "access_token must not contain leading or trailing whitespace"
            )
        self._access_token = access_token

    def clear_access_token(self) -> None:
        self._access_token = None

    def login(
        self,
        username: str,
        password: str,
        *,
        scope: str = DEFAULT_SCOPE,
        redirect_uri: str = OOB_REDIRECT_URI,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> OAuthToken:
        """Exchange account credentials for an access token and retain it."""

        app_client_id = client_id or self._client_id
        app_client_secret = client_secret or self._client_secret
        if not app_client_id or not app_client_secret:
            raise ConfigurationError(
                "login requires client_id and client_secret app credentials"
            )
        if not isinstance(username, str) or not username:
            raise ConfigurationError("username must be a non-empty string")
        if not isinstance(password, str) or not password:
            raise ConfigurationError("password must be a non-empty string")
        if not isinstance(scope, str) or not scope.strip():
            raise ConfigurationError("scope must be a non-empty string")
        if not isinstance(redirect_uri, str) or not redirect_uri:
            raise ConfigurationError("redirect_uri must be a non-empty string")

        payload = self._request_json(
            "POST",
            "/oauth/v2/token",
            json_body={
                "client_id": app_client_id,
                "client_secret": app_client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "password",
                "scope": scope,
                "username": username,
                "password": password,
            },
            authentication_request=True,
        )
        token = OAuthToken.from_payload(payload)
        if not token.access_token:
            raise ProtocolError(
                "Truth Social token response did not contain an access_token"
            )

        self.set_access_token(token.access_token)
        return token

    def discover_web_app_credentials(self) -> OAuthAppCredentials:
        """Discover the public OAuth credentials embedded in the live web app."""

        homepage_url = self._base_url + "/"
        homepage, _ = self._fetch_discovery_text(
            homepage_url,
            max_bytes=_MAX_DISCOVERY_HTML_BYTES,
            accept="text/html,application/xhtml+xml",
        )
        parser = _ScriptSourceParser()
        parser.feed(homepage)

        script_urls: list[str] = []
        seen_urls: set[str] = set()
        for source in parser.sources:
            try:
                script_url = urljoin(homepage_url, source)
            except ValueError as exc:
                raise CredentialDiscoveryError(
                    "Truth Social homepage contained an invalid script URL"
                ) from exc
            if (
                script_url in seen_urls
                or not self._is_same_origin(script_url)
            ):
                continue
            seen_urls.add(script_url)
            script_urls.append(script_url)

        if not script_urls:
            raise CredentialDiscoveryError(
                "Truth Social homepage contained no same-origin script assets"
            )
        if len(script_urls) > _MAX_DISCOVERY_SCRIPTS:
            raise CredentialDiscoveryError(
                "Truth Social homepage referenced too many script assets"
            )

        candidates: dict[tuple[str, str], str] = {}
        total_script_bytes = 0
        for script_url in script_urls:
            remaining_bytes = (
                _MAX_DISCOVERY_TOTAL_SCRIPT_BYTES - total_script_bytes
            )
            if remaining_bytes <= 0:
                raise CredentialDiscoveryError(
                    "Truth Social script assets exceeded the discovery limit"
                )
            script, script_bytes = self._fetch_discovery_text(
                script_url,
                max_bytes=min(_MAX_DISCOVERY_SCRIPT_BYTES, remaining_bytes),
                accept="text/javascript,application/javascript,*/*;q=0.1",
            )
            total_script_bytes += script_bytes
            if total_script_bytes > _MAX_DISCOVERY_TOTAL_SCRIPT_BYTES:
                raise CredentialDiscoveryError(
                    "Truth Social script assets exceeded the discovery limit"
                )

            for match in _OAUTH_CREDENTIALS_PATTERN.finditer(script):
                pair = (
                    match.group("client_id"),
                    match.group("client_secret"),
                )
                candidates.setdefault(pair, script_url)

        if not candidates:
            raise CredentialDiscoveryError(
                "no public OAuth credential pair was found in Truth Social's "
                "same-origin web assets"
            )
        if len(candidates) != 1:
            raise CredentialDiscoveryError(
                "multiple public OAuth credential pairs were found in Truth "
                "Social's web assets"
            )

        (client_id, client_secret), source_url = next(iter(candidates.items()))
        return OAuthAppCredentials(
            client_id=client_id,
            client_secret=client_secret,
            source_url=source_url,
        )

    def login_with_web_app(
        self,
        username: str,
        password: str,
        *,
        scope: str = DEFAULT_SCOPE,
        redirect_uri: str = OOB_REDIRECT_URI,
    ) -> OAuthToken:
        """Discover the current web-app credentials, then log in."""

        credentials = self.discover_web_app_credentials()
        return self.login(
            username,
            password,
            scope=scope,
            redirect_uri=redirect_uri,
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
        )

    def verify_credentials(self) -> Account:
        """Return the account associated with the current access token."""

        payload = self._request_json(
            "GET",
            "/api/v1/accounts/verify_credentials",
            authenticated=True,
        )
        if not isinstance(payload.get("id"), str):
            raise ProtocolError(
                "Truth Social account response did not contain an account id"
            )
        return Account.from_payload(payload)

    def upload_media(
        self,
        file: MediaSource,
        *,
        filename: str | None = None,
        content_type: str | None = None,
    ) -> MediaAttachment:
        """Upload one media file and return its attachment metadata."""

        if isinstance(file, (str, PathLike)):
            path = Path(file)
            upload_filename = filename or path.name
            with path.open("rb") as stream:
                return self._upload_media_stream(
                    stream,
                    filename=upload_filename,
                    content_type=content_type,
                )

        if isinstance(file, io.TextIOBase):
            raise TypeError("file must be opened in binary mode")
        if not callable(getattr(file, "read", None)):
            raise TypeError("file must be a path or readable binary file")
        if getattr(file, "closed", False):
            raise ValueError("file must be open")

        upload_filename = filename
        if upload_filename is None:
            source_name = getattr(file, "name", None)
            if isinstance(source_name, (str, PathLike)):
                upload_filename = Path(source_name).name
        if not upload_filename:
            raise ValueError(
                "filename is required for file objects without a name"
            )

        return self._upload_media_stream(
            file,
            filename=upload_filename,
            content_type=content_type,
        )

    def _upload_media_stream(
        self,
        stream: BinaryIO,
        *,
        filename: str,
        content_type: str | None,
    ) -> MediaAttachment:
        if (
            not isinstance(filename, str)
            or not filename
            or "\r" in filename
            or "\n" in filename
        ):
            raise ValueError("filename must be a non-empty header-safe string")

        media_type = (
            content_type
            or mimetypes.guess_type(filename)[0]
            or "application/octet-stream"
        )
        if (
            not isinstance(media_type, str)
            or not media_type
            or "\r" in media_type
            or "\n" in media_type
        ):
            raise ValueError(
                "content_type must be a non-empty header-safe string"
            )

        payload = self._request_json(
            "POST",
            "/api/v1/media",
            authenticated=True,
            files={"file": (filename, stream, media_type)},
        )
        if not isinstance(payload.get("id"), str):
            raise ProtocolError(
                "Truth Social media response did not contain an attachment id"
            )
        return MediaAttachment.from_payload(payload)

    def post_status(
        self,
        status: str,
        *,
        visibility: Visibility | str = Visibility.PUBLIC,
        media_ids: Iterable[str] = (),
        media_files: Iterable[MediaSource] = (),
        in_reply_to_id: str | None = None,
        poll: Mapping[str, Any] | None = None,
        published: bool = True,
        title: str = "",
        group_timeline_visible: bool = False,
        content_type: str = "text/plain",
        idempotency_key: str | None = None,
    ) -> Status:
        """Publish a status using the same payload shape as the web client."""

        self._validate_post_arguments(
            status=status,
            in_reply_to_id=in_reply_to_id,
            poll=poll,
            content_type=content_type,
            title=title,
            idempotency_key=idempotency_key,
        )
        normalized_media_ids, normalized_media_files = (
            self._normalize_media_inputs(
                status=status,
                poll=poll,
                media_ids=media_ids,
                media_files=media_files,
            )
        )
        visibility_value = self._normalize_visibility(visibility)

        if normalized_media_files:
            normalized_media_ids = [
                self.upload_media(media_file).id
                for media_file in normalized_media_files
            ]

        headers = (
            {"Idempotency-Key": idempotency_key}
            if idempotency_key is not None
            else None
        )
        payload = self._request_json(
            "POST",
            "/api/v1/statuses",
            authenticated=True,
            headers=headers,
            json_body={
                "content_type": content_type,
                "in_reply_to_id": in_reply_to_id or "",
                "media_ids": normalized_media_ids,
                "poll": dict(poll) if poll is not None else None,
                "published": published,
                "status": status,
                "title": title,
                "visibility": visibility_value,
                "group_timeline_visible": group_timeline_visible,
            },
        )
        if not isinstance(payload.get("id"), str):
            raise ProtocolError(
                "Truth Social status response did not contain a status id"
            )
        return Status.from_payload(payload)

    @staticmethod
    def _normalize_media_inputs(
        *,
        status: str,
        poll: Mapping[str, Any] | None,
        media_ids: Iterable[str],
        media_files: Iterable[MediaSource],
    ) -> tuple[list[str], list[MediaSource]]:
        if isinstance(media_ids, (str, bytes)):
            raise TypeError("media_ids must be an iterable of string ids")
        if isinstance(media_files, (str, bytes, PathLike)):
            raise TypeError(
                "media_files must be an iterable; wrap a single path in a list"
            )

        normalized_media_ids = list(media_ids)
        normalized_media_files = list(media_files)
        if any(
            not isinstance(media_id, str) or not media_id
            for media_id in normalized_media_ids
        ):
            raise ValueError("media_ids must contain only non-empty strings")
        if normalized_media_ids and normalized_media_files:
            raise ValueError("media_ids and media_files cannot be used together")
        if (
            not status.strip()
            and not normalized_media_ids
            and not normalized_media_files
            and poll is None
        ):
            raise ValueError("a status requires text, media, or a poll")
        return normalized_media_ids, normalized_media_files

    @staticmethod
    def _normalize_visibility(visibility: Visibility | str) -> str:
        visibility_value = (
            visibility.value if isinstance(visibility, Visibility) else visibility
        )
        if not isinstance(visibility_value, str) or not visibility_value:
            raise ValueError("visibility must be a non-empty string")
        return visibility_value

    @staticmethod
    def _validate_post_arguments(
        *,
        status: str,
        in_reply_to_id: str | None,
        poll: Mapping[str, Any] | None,
        content_type: str,
        title: str,
        idempotency_key: str | None,
    ) -> None:
        if not isinstance(status, str):
            raise TypeError("status must be a string")
        if in_reply_to_id is not None and (
            not isinstance(in_reply_to_id, str) or not in_reply_to_id
        ):
            raise ValueError("in_reply_to_id must be a non-empty string")
        if poll is not None and not isinstance(poll, Mapping):
            raise TypeError("poll must be a mapping")
        if not isinstance(content_type, str) or not content_type:
            raise ValueError("content_type must be a non-empty string")
        if not isinstance(title, str):
            raise TypeError("title must be a string")
        if idempotency_key is not None and (
            not isinstance(idempotency_key, str) or not idempotency_key
        ):
            raise ValueError("idempotency_key must be a non-empty string")

    def reply(
        self,
        status_id: str | Status,
        text: str,
        *,
        visibility: Visibility | str = Visibility.PUBLIC,
        media_ids: Iterable[str] = (),
        media_files: Iterable[MediaSource] = (),
        poll: Mapping[str, Any] | None = None,
        published: bool = True,
        title: str = "",
        group_timeline_visible: bool = False,
        content_type: str = "text/plain",
        idempotency_key: str | None = None,
    ) -> Status:
        """Reply to a status ID or a previously returned Status."""

        parent_id = status_id.id if isinstance(status_id, Status) else status_id
        return self.post_status(
            text,
            visibility=visibility,
            media_ids=media_ids,
            media_files=media_files,
            in_reply_to_id=parent_id,
            poll=poll,
            published=published,
            title=title,
            group_timeline_visible=group_timeline_visible,
            content_type=content_type,
            idempotency_key=idempotency_key,
        )

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        authenticated: bool = False,
        authentication_request: bool = False,
        headers: Mapping[str, str] | None = None,
        json_body: Mapping[str, Any] | None = None,
        files: Mapping[str, tuple[str, BinaryIO, str]] | None = None,
    ) -> dict[str, Any]:
        if self._closed:
            raise ConfigurationError("client is closed")

        request_headers = dict(headers or {})
        if authenticated:
            if self._access_token is None:
                raise NotAuthenticatedError(
                    "this operation requires an access token; call login() or "
                    "pass access_token when creating the client"
                )
            request_headers["Authorization"] = f"Bearer {self._access_token}"

        try:
            response = self._http.request(
                method,
                self._base_url + path,
                headers=request_headers,
                json=json_body,
                files=files,
            )
        except httpx.RequestError as exc:
            raise NetworkError(
                f"could not reach Truth Social: {type(exc).__name__}"
            ) from exc

        if response.is_error:
            self._raise_for_error(
                response,
                authentication_request=authentication_request,
            )

        try:
            payload = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ProtocolError(
                "Truth Social returned a non-JSON success response"
            ) from exc

        if not isinstance(payload, dict):
            raise ProtocolError(
                "Truth Social returned a JSON response that was not an object"
            )
        return payload

    def _fetch_discovery_text(
        self,
        url: str,
        *,
        max_bytes: int,
        accept: str,
    ) -> tuple[str, int]:
        if self._closed:
            raise ConfigurationError("client is closed")
        if not self._is_same_origin(url):
            raise CredentialDiscoveryError(
                "credential discovery refused a cross-origin URL"
            )

        try:
            with self._http.stream(
                "GET",
                url,
                headers={"Accept": accept},
            ) as response:
                if response.is_redirect:
                    raise CredentialDiscoveryError(
                        "credential discovery does not follow redirects"
                    )
                if response.is_error:
                    raise CredentialDiscoveryError(
                        "credential discovery request returned "
                        f"HTTP {response.status_code}"
                    )

                content_length = response.headers.get("content-length")
                if content_length is not None:
                    try:
                        declared_bytes = int(content_length)
                    except ValueError as exc:
                        raise CredentialDiscoveryError(
                            "credential discovery received an invalid "
                            "Content-Length header"
                        ) from exc
                    if declared_bytes > max_bytes:
                        raise CredentialDiscoveryError(
                            "credential discovery response exceeded its "
                            "size limit"
                        )

                chunks: list[bytes] = []
                received_bytes = 0
                for chunk in response.iter_bytes():
                    received_bytes += len(chunk)
                    if received_bytes > max_bytes:
                        raise CredentialDiscoveryError(
                            "credential discovery response exceeded its "
                            "size limit"
                        )
                    chunks.append(chunk)
        except httpx.HTTPError as exc:
            raise NetworkError(
                "could not fetch Truth Social web assets: "
                f"{type(exc).__name__}"
            ) from exc

        return b"".join(chunks).decode("utf-8", errors="replace"), received_bytes

    def _is_same_origin(self, url: str) -> bool:
        try:
            candidate = httpx.URL(url)
            base = httpx.URL(self._base_url)
        except (httpx.InvalidURL, ValueError):
            return False
        return (
            candidate.scheme in {"http", "https"}
            and candidate.scheme == base.scheme
            and candidate.host == base.host
            and self._effective_port(candidate) == self._effective_port(base)
            and not candidate.username
            and not candidate.password
        )

    @staticmethod
    def _effective_port(url: httpx.URL) -> int | None:
        if url.port is not None:
            return url.port
        if url.scheme == "https":
            return 443
        if url.scheme == "http":
            return 80
        return None

    @staticmethod
    def _raise_for_error(
        response: httpx.Response,
        *,
        authentication_request: bool,
    ) -> None:
        message = f"Truth Social API returned HTTP {response.status_code}"
        try:
            payload = response.json()
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = None

        if isinstance(payload, Mapping):
            for key in ("error_description", "error", "message"):
                value = payload.get(key)
                if isinstance(value, str) and value:
                    message = value
                    break

        request_id = response.headers.get("x-request-id")
        error_code = None
        if isinstance(payload, Mapping):
            error_value = payload.get("error")
            if isinstance(error_value, str) and error_value:
                error_code = error_value
        if response.status_code == 429:
            raise RateLimitError(
                message,
                status_code=response.status_code,
                request_id=request_id,
                error_code=error_code,
                retry_after=TruthSocialClient._parse_retry_after(
                    response.headers.get("retry-after")
                ),
            )
        if response.status_code in {401, 403} or (
            authentication_request and response.status_code == 400
        ):
            raise AuthenticationError(
                message,
                status_code=response.status_code,
                request_id=request_id,
                error_code=error_code,
            )
        raise APIError(
            message,
            status_code=response.status_code,
            request_id=request_id,
            error_code=error_code,
        )

    @staticmethod
    def _parse_retry_after(value: str | None) -> float | None:
        if value is None:
            return None
        try:
            return max(0.0, float(value))
        except ValueError:
            pass

        try:
            retry_at = parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError):
            return None
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=timezone.utc)
        return max(
            0.0,
            (retry_at - datetime.now(timezone.utc)).total_seconds(),
        )
