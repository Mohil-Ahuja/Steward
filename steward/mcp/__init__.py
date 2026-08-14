"""MCP protocol layer: JSON-RPC codec, upstream client, gateway, integrity."""

from .client import (
    HttpTransport,
    InProcessTransport,
    StdioTransport,
    Transport,
    UpstreamClient,
    UpstreamTool,
    build_transport,
)
from .gateway import Principal, StewardGateway, namespaced, split_namespaced
from .integrity import (
    DescriptorHashes,
    canonical_json,
    descriptor_matches_pin,
    hash_from_mcp_tool,
    hash_tool_definition,
)
from .jsonrpc import PROTOCOL_VERSION, ErrorCode, JsonRpcError, Request, Response
from .registry import (
    DiscoveryReport,
    ToolChange,
    UpstreamRegistry,
    catalogue,
    discover,
    pin_tool,
    set_quarantine,
)
from .sanitize import SanitizedResult, sanitize_content, sanitize_tool_result

__all__ = [
    "DescriptorHashes",
    "DiscoveryReport",
    "ErrorCode",
    "HttpTransport",
    "InProcessTransport",
    "JsonRpcError",
    "PROTOCOL_VERSION",
    "Principal",
    "Request",
    "Response",
    "SanitizedResult",
    "StdioTransport",
    "StewardGateway",
    "ToolChange",
    "Transport",
    "UpstreamClient",
    "UpstreamRegistry",
    "UpstreamTool",
    "build_transport",
    "canonical_json",
    "catalogue",
    "descriptor_matches_pin",
    "discover",
    "hash_from_mcp_tool",
    "hash_tool_definition",
    "namespaced",
    "pin_tool",
    "sanitize_content",
    "sanitize_tool_result",
    "set_quarantine",
    "split_namespaced",
]
