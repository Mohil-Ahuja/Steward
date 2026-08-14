"""Client for talking to upstream MCP servers.

Steward sits between an agent and the real tool providers, so it needs to *be*
an MCP client. Three transports are supported:

* ``stdio`` -- launch the server as a subprocess and exchange newline-delimited
  JSON over its stdin/stdout. This is how most local MCP servers ship.
* ``http`` -- Streamable HTTP, POSTing JSON-RPC to a URL.
* ``inproc`` -- an in-process server object, used by the bundled mock servers
  so the whole system (and the entire evaluation suite) runs with no
  subprocesses, no sockets and no network.

The ``inproc`` transport is not a testing shortcut bolted on afterwards; it is
what makes the evaluation pipeline hermetic and reproducible. Numbers produced
by the eval harness must not depend on whether some server happened to be
reachable.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Protocol

from .jsonrpc import (
    PROTOCOL_VERSION,
    ErrorCode,
    IdGenerator,
    JsonRpcError,
    Request,
    request_meta,
)

CLIENT_NAME = "steward"
CLIENT_VERSION = "1.0.0"


class Transport(ABC):
    """Carries one JSON-RPC request and returns the decoded response."""

    @abstractmethod
    async def send(self, message: dict[str, Any], timeout: float) -> dict[str, Any]:
        ...

    async def close(self) -> None:  # pragma: no cover - default no-op
        return None


class InProcessServer(Protocol):
    """Anything exposing an MCP ``handle`` coroutine."""

    async def handle(self, message: dict[str, Any]) -> dict[str, Any] | None:
        ...


class InProcessTransport(Transport):
    """Dispatch straight to a Python object implementing the server side."""

    def __init__(self, server: InProcessServer) -> None:
        self._server = server

    async def send(self, message: dict[str, Any], timeout: float) -> dict[str, Any]:
        try:
            response = await asyncio.wait_for(self._server.handle(message), timeout)
        except TimeoutError as exc:
            raise JsonRpcError(
                ErrorCode.UPSTREAM_UNAVAILABLE, f"upstream timed out after {timeout}s"
            ) from exc
        return response or {}


class StdioTransport(Transport):
    """Newline-delimited JSON-RPC over a subprocess's stdio.

    A lock serialises requests because the responses on a shared pipe are not
    otherwise attributable: without it, two concurrent calls could each read
    the other's reply. Real concurrency would need a reader task demultiplexing
    on the JSON-RPC id, which is deliberately out of scope here -- upstream
    servers are pooled per connection instead.
    """

    def __init__(self, command: list[str], env: dict[str, str] | None = None, cwd: str | None = None) -> None:
        self._command = command
        self._env = env
        self._cwd = cwd
        self._process: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()

    async def _ensure_process(self) -> asyncio.subprocess.Process:
        if self._process is None or self._process.returncode is not None:
            self._process = await asyncio.create_subprocess_exec(
                *self._command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._env,
                cwd=self._cwd,
            )
        return self._process

    async def send(self, message: dict[str, Any], timeout: float) -> dict[str, Any]:
        async with self._lock:
            process = await self._ensure_process()
            assert process.stdin and process.stdout

            line = json.dumps(message, ensure_ascii=False) + "\n"
            process.stdin.write(line.encode("utf-8"))
            await process.stdin.drain()

            try:
                raw = await asyncio.wait_for(process.stdout.readline(), timeout)
            except TimeoutError as exc:
                raise JsonRpcError(
                    ErrorCode.UPSTREAM_UNAVAILABLE, f"upstream timed out after {timeout}s"
                ) from exc

            if not raw:
                stderr = b""
                if process.stderr:
                    # Best effort: the process is already gone, so a slow or
                    # empty stderr must not delay reporting the real failure.
                    with contextlib.suppress(TimeoutError):
                        stderr = await asyncio.wait_for(process.stderr.read(2048), 1.0)
                raise JsonRpcError(
                    ErrorCode.UPSTREAM_UNAVAILABLE,
                    "upstream closed the connection",
                    {"stderr": stderr.decode("utf-8", "replace")[:512]},
                )

            try:
                return json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise JsonRpcError(
                    ErrorCode.PARSE_ERROR, f"upstream sent malformed JSON: {exc}"
                ) from exc

    async def close(self) -> None:
        if self._process and self._process.returncode is None:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), 5.0)
            except TimeoutError:  # pragma: no cover - defensive
                self._process.kill()


class HttpTransport(Transport):
    """Streamable HTTP transport."""

    def __init__(self, url: str, headers: dict[str, str] | None = None) -> None:
        self._url = url
        self._headers = {
            "content-type": "application/json",
            "accept": "application/json, text/event-stream",
            **(headers or {}),
        }
        self._client: Any = None

    async def _ensure_client(self) -> Any:
        if self._client is None:
            import httpx

            self._client = httpx.AsyncClient(timeout=None)
        return self._client

    async def send(self, message: dict[str, Any], timeout: float) -> dict[str, Any]:
        import httpx

        client = await self._ensure_client()
        try:
            response = await client.post(
                self._url, json=message, headers=self._headers, timeout=timeout
            )
        except httpx.HTTPError as exc:
            raise JsonRpcError(
                ErrorCode.UPSTREAM_UNAVAILABLE, f"upstream request failed: {exc}"
            ) from exc

        if response.status_code >= 400:
            raise JsonRpcError(
                ErrorCode.UPSTREAM_UNAVAILABLE,
                f"upstream returned HTTP {response.status_code}",
                {"body": response.text[:512]},
            )

        if response.status_code == 202 or not response.content:
            return {}  # accepted notification

        try:
            return response.json()
        except ValueError as exc:
            raise JsonRpcError(
                ErrorCode.PARSE_ERROR, f"upstream sent malformed JSON: {exc}"
            ) from exc

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


@dataclass
class UpstreamTool:
    """One tool as advertised by an upstream server."""

    server: str
    name: str
    description: str | None = None
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] = field(default_factory=dict)
    title: str | None = None

    @classmethod
    def from_wire(cls, server: str, payload: dict[str, Any]) -> UpstreamTool:
        return cls(
            server=server,
            name=str(payload.get("name", "")),
            title=payload.get("title"),
            description=payload.get("description"),
            input_schema=payload.get("inputSchema") or {},
            output_schema=payload.get("outputSchema"),
            annotations=payload.get("annotations") or {},
        )

    def to_wire(self) -> dict[str, Any]:
        tool: dict[str, Any] = {"name": self.name, "inputSchema": self.input_schema or {"type": "object"}}
        if self.title:
            tool["title"] = self.title
        if self.description:
            tool["description"] = self.description
        if self.output_schema:
            tool["outputSchema"] = self.output_schema
        if self.annotations:
            tool["annotations"] = self.annotations
        return tool


class UpstreamClient:
    """An MCP client bound to one upstream server."""

    def __init__(self, name: str, transport: Transport, timeout: float = 30.0) -> None:
        self.name = name
        self._transport = transport
        self._timeout = timeout
        self._ids = IdGenerator(prefix=f"steward-{name}")
        self._initialized = False
        self.server_info: dict[str, Any] = {}
        self.capabilities: dict[str, Any] = {}

    async def _call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        request = Request(method=method, params=dict(params or {}), id=self._ids.next())
        request.params["_meta"] = request_meta(CLIENT_NAME, CLIENT_VERSION)

        payload = await self._transport.send(request.to_dict(), self._timeout)
        if not payload:
            return None

        if "error" in payload and payload["error"]:
            error = payload["error"]
            raise JsonRpcError(
                int(error.get("code", ErrorCode.INTERNAL_ERROR)),
                str(error.get("message", "upstream error")),
                error.get("data"),
            )
        return payload.get("result")

    async def initialize(self) -> dict[str, Any]:
        if self._initialized:
            return self.server_info

        result = await self._call(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
                "capabilities": {},
            },
        ) or {}

        self.server_info = result.get("serverInfo", {})
        self.capabilities = result.get("capabilities", {})
        self._initialized = True
        return self.server_info

    async def list_tools(self) -> list[UpstreamTool]:
        """Fetch the full catalogue, following pagination cursors."""
        await self.initialize()

        tools: list[UpstreamTool] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()

        while True:
            params = {"cursor": cursor} if cursor else {}
            result = await self._call("tools/list", params) or {}

            for payload in result.get("tools", []) or []:
                tools.append(UpstreamTool.from_wire(self.name, payload))

            cursor = result.get("nextCursor")
            if not cursor:
                break
            if cursor in seen_cursors:
                # A server repeating a cursor would loop us forever; stop and
                # keep what we have rather than hang the gateway.
                break
            seen_cursors.add(cursor)

        return tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        await self.initialize()
        result = await self._call("tools/call", {"name": name, "arguments": arguments})
        return result or {}

    async def close(self) -> None:
        await self._transport.close()


def build_transport(spec: dict[str, Any]) -> Transport:
    """Construct a transport from a registry entry."""
    kind = str(spec.get("transport", "stdio")).lower()

    if kind == "stdio":
        command = spec.get("command")
        if not command:
            raise ValueError("stdio upstream requires a 'command'")
        if isinstance(command, str):
            command = command.split()
        return StdioTransport(list(command), env=spec.get("env"), cwd=spec.get("cwd"))

    if kind in {"http", "streamable-http"}:
        url = spec.get("url")
        if not url:
            raise ValueError("http upstream requires a 'url'")
        return HttpTransport(str(url), headers=spec.get("headers"))

    if kind == "inproc":
        target = spec.get("server")
        if target is None:
            raise ValueError("inproc upstream requires a 'server' object")
        return InProcessTransport(target)

    raise ValueError(f"unknown transport {kind!r}")
