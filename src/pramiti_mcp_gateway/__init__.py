"""pramiti-mcp-gateway — security posture scanner and passive gateway for MCP.

See what your AI agents can actually *do*. The v1 surface is the offline
``scan``: classify the action risk of any MCP server's declared tools with zero
infrastructure.

Public API:
    classify_tool(name, description, input_schema, server) -> ToolRisk
    scan_manifest(manifest) -> PostureReport
"""
from __future__ import annotations

from pramiti_mcp_gateway.classifier import ToolRisk, classify_tool
from pramiti_mcp_gateway.scan import PostureReport, render_text, scan_manifest

__version__ = "0.1.0"

__all__ = [
    "ToolRisk",
    "classify_tool",
    "PostureReport",
    "scan_manifest",
    "render_text",
    "__version__",
]
