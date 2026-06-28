from __future__ import annotations

from contextvars import ContextVar, Token
from typing import Optional
from uuid import uuid4


_REQUEST_ID: ContextVar[Optional[str]] = ContextVar("acvp_request_id", default=None)


def normalize_request_id(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = str(value).strip()
    if not normalized:
        return None
    return normalized.replace("\r", "").replace("\n", "")


def set_request_id(value: Optional[str] = None) -> Token[Optional[str]]:
    request_id = normalize_request_id(value) or str(uuid4())
    return _REQUEST_ID.set(request_id)


def reset_request_id(token: Token[Optional[str]]) -> None:
    _REQUEST_ID.reset(token)


def current_request_id() -> Optional[str]:
    return _REQUEST_ID.get()


def get_or_create_request_id(request: object = None) -> str:
    header_value = None
    headers = getattr(request, "headers", None)
    if headers is not None:
        header_value = normalize_request_id(headers.get("X-Request-ID"))
    if header_value is not None:
        if _REQUEST_ID.get() != header_value:
            _REQUEST_ID.set(header_value)
        return header_value

    request_id = _REQUEST_ID.get()
    if request_id is None:
        request_id = str(uuid4())
        _REQUEST_ID.set(request_id)
    return request_id
