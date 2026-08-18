from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping


class Visibility(str, Enum):
    PUBLIC = "public"
    UNLISTED = "unlisted"
    PRIVATE = "private"
    DIRECT = "direct"


@dataclass(frozen=True, slots=True)
class OAuthAppCredentials:
    client_id: str
    client_secret: str = field(repr=False)
    source_url: str | None = None


def _string(payload: Mapping[str, Any], key: str, default: str = "") -> str:
    value = payload.get(key)
    return value if isinstance(value, str) else default


def _optional_string(payload: Mapping[str, Any], key: str) -> str | None:
    value = payload.get(key)
    return value if isinstance(value, str) else None


def _optional_int(payload: Mapping[str, Any], key: str) -> int | None:
    value = payload.get(key)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _raw(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(payload))


@dataclass(frozen=True, slots=True)
class OAuthToken:
    access_token: str = field(repr=False)
    token_type: str = "Bearer"
    scope: str | None = None
    created_at: int | None = None
    expires_in: int | None = None
    refresh_token: str | None = field(default=None, repr=False)
    raw: Mapping[str, Any] = field(
        default_factory=lambda: MappingProxyType({}),
        repr=False,
        compare=False,
    )

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> OAuthToken:
        return cls(
            access_token=_string(payload, "access_token"),
            token_type=_string(payload, "token_type", "Bearer"),
            scope=_optional_string(payload, "scope"),
            created_at=_optional_int(payload, "created_at"),
            expires_in=_optional_int(payload, "expires_in"),
            refresh_token=_optional_string(payload, "refresh_token"),
            raw=_raw(payload),
        )


@dataclass(frozen=True, slots=True)
class Account:
    id: str
    username: str
    acct: str
    display_name: str
    url: str | None
    raw: Mapping[str, Any] = field(repr=False, compare=False)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> Account:
        return cls(
            id=_string(payload, "id"),
            username=_string(payload, "username"),
            acct=_string(payload, "acct"),
            display_name=_string(payload, "display_name"),
            url=_optional_string(payload, "url"),
            raw=_raw(payload),
        )


@dataclass(frozen=True, slots=True)
class MediaAttachment:
    id: str
    type: str
    url: str | None
    preview_url: str | None
    description: str | None
    processing: str | None
    meta: Mapping[str, Any]
    raw: Mapping[str, Any] = field(repr=False, compare=False)

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, Any],
    ) -> MediaAttachment:
        meta_payload = payload.get("meta")
        meta = (
            MappingProxyType(dict(meta_payload))
            if isinstance(meta_payload, Mapping)
            else MappingProxyType({})
        )
        return cls(
            id=_string(payload, "id"),
            type=_string(payload, "type"),
            url=_optional_string(payload, "url"),
            preview_url=_optional_string(payload, "preview_url"),
            description=_optional_string(payload, "description"),
            processing=_optional_string(payload, "processing"),
            meta=meta,
            raw=_raw(payload),
        )


@dataclass(frozen=True, slots=True)
class Status:
    id: str
    content: str
    visibility: str
    url: str | None
    created_at: str | None
    account: Account | None
    in_reply_to_id: str | None
    media_attachments: tuple[MediaAttachment, ...]
    raw: Mapping[str, Any] = field(repr=False, compare=False)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> Status:
        account_payload = payload.get("account")
        account = (
            Account.from_payload(account_payload)
            if isinstance(account_payload, Mapping)
            else None
        )
        attachments_payload = payload.get("media_attachments")
        attachments = (
            tuple(
                MediaAttachment.from_payload(item)
                for item in attachments_payload
                if isinstance(item, Mapping)
            )
            if isinstance(attachments_payload, list)
            else ()
        )
        return cls(
            id=_string(payload, "id"),
            content=_string(payload, "content"),
            visibility=_string(payload, "visibility"),
            url=_optional_string(payload, "url"),
            created_at=_optional_string(payload, "created_at"),
            account=account,
            in_reply_to_id=_optional_string(payload, "in_reply_to_id"),
            media_attachments=attachments,
            raw=_raw(payload),
        )
