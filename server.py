"""FastMCP Cloud & Standard MCP Server for MCP-Gatekeeper.

Deployable directly to fastmcp.cloud or run locally via FastMCP / Claude Desktop / Antigravity / ChatGPT.
"""
import asyncio
import json
from typing import Dict, Any, Optional
from fastmcp import FastMCP
from sqlalchemy import select, desc

from src.database.connection import init_db, AsyncSessionLocal
from src.database.repository import register_server
from src.proxy.mcp_proxy import MCPTrustGatewayProxy
from src.detection.pipeline import TwoStageDetectionPipeline
from src.database.models import Incident, AuditLog
from src.config import settings
from src.security_utils import validate_upstream_url

# Create FastMCP instance
mcp = FastMCP("MCP-Gatekeeper")
gateway_proxy = MCPTrustGatewayProxy()

@mcp.tool(
    name="check_tool_security",
    description="Inspects a tool response payload for prompt injection, payload tampering, or security risks using 2-stage (Rule + LLM) scanner."
)
async def check_tool_security(
    tool_name: str,
    response_payload: dict,
    request_payload: Optional[dict] = None
) -> dict:
    """Inspects tool response payloads for prompt injection or malicious content."""
    await init_db()
    req_payload = request_payload or {}
    pipeline = TwoStageDetectionPipeline()
    verdict, reason, meta = await pipeline.classify_response(tool_name, req_payload, response_payload)

    return {
        "verdict": verdict,
        "reason": reason,
        "is_safe": verdict == "clean",
        "metadata": meta
    }

@mcp.tool(
    name="register_upstream_mcp_server",
    description="Registers an upstream MCP server with the Trust Gateway for proxy protection."
)
async def register_upstream_mcp_server(
    server_id: str,
    server_name: str,
    upstream_url: str
) -> str:
    """Registers an upstream MCP server with the Trust Gateway after SSRF validation."""
    await init_db()
    try:
        validated_url = validate_upstream_url(upstream_url)
    except ValueError as val_err:
        return f"Registration Rejected: {str(val_err)}"

    async with AsyncSessionLocal() as db:
        s = await register_server(db, server_id, server_name, validated_url)
        return f"Upstream server '{s.name}' registered successfully. Proxy endpoint: http://localhost:8000/proxy/{s.id}"

@mcp.tool(
    name="get_security_incidents",
    description="Returns recent flagged security incidents, prompt injections, and rug-pull attempts."
)
async def get_security_incidents(limit: int = 10) -> list:
    """Returns recent flagged security incidents (capped to max 100)."""
    safe_limit = max(1, min(limit, 100))
    await init_db()
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(Incident).order_by(desc(Incident.created_at)).limit(safe_limit))
        incidents = res.scalars().all()
        return [{"id": i.id, "severity": i.severity, "detection_type": i.detection_type, "details": i.details, "created_at": i.created_at.isoformat()} for i in incidents]

@mcp.tool(
    name="get_audit_log",
    description="Returns the SHA-256 hash-chained tamper-evident security audit log."
)
async def get_audit_log(limit: int = 10) -> list:
    """Returns the SHA-256 hash-chained security audit log (capped to max 100)."""
    safe_limit = max(1, min(limit, 100))
    await init_db()
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(safe_limit))
        entries = res.scalars().all()
        return [{"id": e.id, "actor": e.actor, "action": e.action, "target": e.target, "current_hash": e.current_hash, "created_at": e.created_at.isoformat()} for e in entries]

@mcp.tool(
    name="resolve_human_approval",
    description="Approves or denies a held high-risk tool call pending human confirmation (Requires ADMIN_API_KEY)."
)
async def resolve_human_approval(
    confirmation_id: str,
    approve: bool,
    admin_key: str = "",
    resolved_by: str = "admin"
) -> str:
    """Approves or denies a held high-risk action (Auth protected)."""
    if admin_key != settings.ADMIN_API_KEY:
        return "Unauthorized: Invalid or missing admin_key parameter. Approval denied."

    await init_db()
    async with AsyncSessionLocal() as db:
        res = await gateway_proxy.confirmation_mgr.resolve_confirmation(db, confirmation_id, approved=approve, resolved_by=resolved_by)
        if not res:
            return f"Confirmation request '{confirmation_id}' not found or already resolved."
        return f"Confirmation request '{confirmation_id}' resolved: {res.status}"

@mcp.custom_route("/dashboard", methods=["GET"])
async def dashboard_route(request):
    """Renders the Admin Dashboard UI on FastMCP Cloud (Requires Admin Authentication)."""
    from starlette.responses import HTMLResponse
    from jinja2 import Template
    from src.admin_ui.app import HTML_TEMPLATE
    from src.database.models import UpstreamServer, HumanConfirmation

    # Auth check via query parameter or request header
    query_key = request.query_params.get("admin_key", "")
    header_key = request.headers.get("X-Admin-Key", "")
    
    if query_key != settings.ADMIN_API_KEY and header_key != settings.ADMIN_API_KEY:
        return HTMLResponse(
            "<html><body style='background:#090d16;color:#ef4444;font-family:sans-serif;padding:40px;'>"
            "<h1>🛡️ 401 Unauthorized</h1>"
            "<p>Admin Dashboard access requires authentication. Pass <code>?admin_key=YOUR_KEY</code> in URL or <code>X-Admin-Key</code> header.</p>"
            "</body></html>",
            status_code=401
        )

    await init_db()
    async with AsyncSessionLocal() as db:
        servers_res = await db.execute(select(UpstreamServer))
        servers = servers_res.scalars().all()
        
        conf_res = await db.execute(select(HumanConfirmation).where(HumanConfirmation.status == "pending"))
        confirmations = conf_res.scalars().all()
        
        inc_res = await db.execute(select(Incident).order_by(desc(Incident.created_at)).limit(20))
        incidents = inc_res.scalars().all()
        
        audit_res = await db.execute(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(30))
        audit_log = audit_res.scalars().all()
        
        template = Template(HTML_TEMPLATE)
        html = template.render(
            servers=servers,
            confirmations=confirmations,
            incidents=incidents,
            audit_log=audit_log
        )
        return HTMLResponse(html)

if __name__ == "__main__":
    mcp.run()

