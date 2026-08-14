"""JSON-RPC 2.0 message types for MCP.

MCP is JSON-RPC 2.0 over a choice of transports. This module implements only
the message layer -- framing, identifiers, error codes -- so the transports and
the gateway can share one vocabulary and be tested without sockets.

Written directly against the specification rather than delegating to an SDK for
two reasons: Steward is a *proxy*, so it must both speak client and act as a
server, and it needs to inspect and rewrite messages in flight (filtering
``tools/list``, rejecting a ``tools/call``) which a high-level SDK abstracts
away.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

JSONRPC_VERSION = "2.0"

# Protocol revision Steward implements.
PROTOCOL_VERSION = "2026-07-28"

# Required request metadata keys defined by the base protocol.
META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"


class ErrorCode:
    """Standard JSON-RPC codes plus the MCP-relevant application range."""

    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603

    # Application-defined. Steward uses a distinct code for authorization so a
    # client can tell "you may not do this" apart from "that tool is broken" --
    # the first is final, the second is worth retrying.
    UNAUTHORIZED = -32001
    UPSTREAM_UNAVAILABLE = -32002


class JsonRpcError(Exception):
    """An error destined for the wire as a JSON-RPC error object."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

    def to_dict(self) -> dict[str, Any]:
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            error["data"] = self.data
        return error


@dataclass
class Request:
    method: str
    params: dict[str, Any] = field(default_factory=dict)
    id: str | int | None = None

    @property
    def is_notification(self) -> bool:
        """Notifications carry no id and must never be answered."""
        return self.id is None

    def to_dict(self) -> dict[str, Any]:
        message: dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "method": self.method}
        if self.params:
            message["params"] = self.params
        if self.id is not None:
            message["id"] = self.id
        return message


@dataclass
class Response:
    id: str | int | None
    result: Any = None
    error: dict[str, Any] | None = None

    @property
    def is_error(self) -> bool:
        return self.error is not None

    def to_dict(self) -> dict[str, Any]:
        message: dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "id": self.id}
        if self.error is not None:
            message["error"] = self.error
        else:
            message["result"] = self.result
        return message


def parse_message(payload: dict[str, Any]) -> Request | Response:
    """Turn a decoded JSON object into a Request or Response."""
    if not isinstance(payload, dict):
        raise JsonRpcError(ErrorCode.INVALID_REQUEST, "message must be a JSON object")

    if payload.get("jsonrpc") != JSONRPC_VERSION:
        raise JsonRpcError(
            ErrorCode.INVALID_REQUEST, f"jsonrpc must be {JSONRPC_VERSION!r}"
        )

    if "method" in payload:
        params = payload.get("params") or {}
        if not isinstance(params, dict):
            # MCP only uses by-name parameters, so a positional array is invalid.
            raise JsonRpcError(ErrorCode.INVALID_PARAMS, "params must be an object")
        return Request(method=str(payload["method"]), params=params, id=payload.get("id"))

    if "result" in payload or "error" in payload:
        return Response(
            id=payload.get("id"),
            result=payload.get("result"),
            error=payload.get("error"),
        )

    raise JsonRpcError(ErrorCode.INVALID_REQUEST, "message has neither method nor result")


def error_response(request_id: str | int | None, error: JsonRpcError) -> dict[str, Any]:
    return Response(id=request_id, error=error.to_dict()).to_dict()


def result_response(request_id: str | int | None, result: Any) -> dict[str, Any]:
    return Response(id=request_id, result=result).to_dict()


class IdGenerator:
    """Monotonic request ids.

    The specification requires that a multi-round-trip retry use an id
    different from the original request, so ids are never recycled.
    """

    def __init__(self, prefix: str = "steward") -> None:
        self._prefix = prefix
        self._counter: Iterator[int] = itertools.count(1)

    def next(self) -> str:
        return f"{self._prefix}-{next(self._counter)}"


def request_meta(client_name: str, client_version: str, capabilities: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the ``_meta`` block every MCP request must carry."""
    return {
        META_PROTOCOL_VERSION: PROTOCOL_VERSION,
        META_CLIENT_INFO: {"name": client_name, "version": client_version},
        META_CLIENT_CAPABILITIES: capabilities or {},
    }
