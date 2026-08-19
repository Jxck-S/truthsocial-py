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


class DeliveryMethod(str, Enum):
    """Channels a new-device security code can be delivered over."""

    EMAIL = "email"
    SMS = "sms"


@dataclass(frozen=True, slots=True)
class DeliveryOption:
    """One delivery channel offered for a device challenge.

    ``value`` is the masked destination Truth Social will send the code to
    (a partially redacted email address or phone number), suitable for
    showing to a human choosing between options.
    """

    kind: str
    value: str | None = None
    raw: Mapping[str, Any] = field(
        default_factory=lambda: MappingProxyType({}),
        repr=False,
    )

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "DeliveryOption":
        return cls(
            kind=_string(payload, "kind").strip().casefold(),
            value=_optional_string(payload, "value"),
            raw=_raw(payload),
        )


@dataclass(frozen=True, slots=True)
class DeviceChallenge:
    """A new-device verification challenge raised by a rejected login.

    Truth Social answers a password grant from an unrecognised device with
    HTTP 403 and ``error: "security_code_required"``; the response carries the
    challenge id and the delivery channels the account supports.
    """

    challenge_id: str
    username: str = ""
    delivery_options: tuple[DeliveryOption, ...] = ()
    detail: str = ""
    raw: Mapping[str, Any] = field(
        default_factory=lambda: MappingProxyType({}),
        repr=False,
    )

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, Any],
        *,
        username: str = "",
    ) -> "DeviceChallenge":
        options_payload = payload.get("supported_delivery_methods")
        options = (
            tuple(
                DeliveryOption.from_payload(item)
                for item in options_payload
                if isinstance(item, Mapping)
            )
            if isinstance(options_payload, list)
            else ()
        )
        return cls(
            challenge_id=_string(payload, "challenge_id"),
            username=username,
            delivery_options=options,
            detail=_error_detail(payload),
            raw=_raw(payload),
        )

    @property
    def delivery_kinds(self) -> tuple[str, ...]:
        """The ``kind`` of every offered delivery option, e.g. ``("email",)``."""

        return tuple(option.kind for option in self.delivery_options if option.kind)

    def option_for(self, method: str | DeliveryMethod) -> DeliveryOption | None:
        """Return the offered option matching ``method``, if any."""

        wanted = _delivery_kind(method)
        for option in self.delivery_options:
            if option.kind == wanted:
                return option
        return None


def _delivery_kind(method: str | DeliveryMethod) -> str:
    value = method.value if isinstance(method, DeliveryMethod) else method
    if not isinstance(value, str) or not value.strip():
        return ""
    return value.strip().casefold()


def _error_detail(payload: Mapping[str, Any]) -> str:
    """Pull the human-readable sentence out of an API error payload.

    Truth Social puts the terse machine code in ``error`` and the sentence
    worth showing a human in ``errors[0].error_message``.
    """

    errors = payload.get("errors")
    if isinstance(errors, list):
        for item in errors:
            if not isinstance(item, Mapping):
                continue
            message = item.get("error_message")
            if isinstance(message, str) and message:
                return message
    return ""


@dataclass(frozen=True, slots=True)
class MfaChallenge:
    """A multi-factor authentication challenge raised by a rejected login.

    Truth Social answers a password grant for a 2FA-enabled account with
    HTTP 403 and ``error: "mfa_required"``, handing back a short-lived
    ``mfa_token``. That token — not the password — is what redeems the
    authenticator code.

    ``detail`` is the sentence from the response's ``errors`` list. Note that
    Truth Social sends "The 2FA code entered is incorrect" even on the first
    prompt, before any code has been submitted, so it is kept here rather than
    used as the exception message.
    """

    mfa_token: str = field(repr=False)
    username: str = ""
    challenge_types: tuple[str, ...] = ()
    detail: str = ""
    raw: Mapping[str, Any] = field(
        default_factory=lambda: MappingProxyType({}),
        repr=False,
    )

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, Any],
        *,
        username: str = "",
    ) -> "MfaChallenge":
        return cls(
            mfa_token=_string(payload, "mfa_token"),
            username=username,
            challenge_types=_challenge_types(
                payload.get("supported_challenge_types")
            ),
            detail=_error_detail(payload),
            raw=_raw(payload),
        )

    def supports(self, challenge_type: str) -> bool:
        """Return whether ``challenge_type`` is offered for this challenge."""

        if not self.challenge_types:
            return True
        wanted = challenge_type.strip().casefold()
        return wanted in self.challenge_types


def _challenge_types(value: Any) -> tuple[str, ...]:
    """Normalise ``supported_challenge_types``.

    Truth Social sends a bare string (``"totp"``) rather than a list, but
    tolerate both.
    """

    if isinstance(value, str):
        return tuple(
            part.strip().casefold()
            for part in value.split(",")
            if part.strip()
        )
    if isinstance(value, (list, tuple)):
        return tuple(
            item.strip().casefold()
            for item in value
            if isinstance(item, str) and item.strip()
        )
    return ()
