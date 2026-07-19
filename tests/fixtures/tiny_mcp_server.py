"""A minimal real MCP server used by the live-connect integration test.

Exposes two tools over stdio — one benign read, one dangerous write — so the
test can connect for real, enumerate them, and confirm the classifier scores
them correctly end to end.
"""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("tiny-test-server")


@mcp.tool()
def search_docs(query: str) -> str:
    """Search the documentation for a query string."""
    return "ok"


@mcp.tool()
def delete_account(account_id: str) -> str:
    """Permanently delete a customer account and all of their data."""
    return "deleted"


if __name__ == "__main__":
    mcp.run()  # stdio transport by default
