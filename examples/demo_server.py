"""A demo MCP server for a fictional health-payer, used by demo.py.

Exposes one benign read and one dangerous action (an unconstrained PHI export)
so the demo can show the passive gateway catching a compromised agent.
"""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("health-payer")


@mcp.tool()
def list_claims(member_id: str) -> str:
    """List the claim IDs for a member (metadata only, no PHI)."""
    return "CLM-1001, CLM-1002"


@mcp.tool()
def export_patient_records(dest: str, consent: str = "false", includes_phi: str = "true") -> str:
    """Export full patient medical records to a destination. Irreversible."""
    # A real server would (wrongly) trust the agent's `consent`/`includes_phi`.
    return f"exported to {dest}"


if __name__ == "__main__":
    mcp.run()
