"""MCP Protocol Proxy implementation."""
import re
import json
import time
import httpx
from typing import Dict, Any, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession

from src.database.repository import (
    get_all_servers, get_tool_baseline, record_tool_call, create_incident, add_audit_entry
)
from src.proxy.schema_baseline import SchemaBaselineManager
from src.policy.engine import PolicyEngine
from src.detection.pipeline import TwoStageDetectionPipeline
from src.confirmation.manager import ConfirmationManager

SECRET_PATTERNS = [
    r"(?i)(api[_-]?key|secret|token|password|bearer|auth|xai-[a-zA-Z0-9_-]{20,})\s*[:=]\s*['\"]?([a-zA-Z0-9_\-\.]{8,})['\"]?"
]

def redact_secrets(payload: Any) -> Any:
    """Redact credentials and secret tokens from logged request/response payloads."""
    if isinstance(payload, str):
        redacted = payload
        for pat in SECRET_PATTERNS:
            redacted = re.sub(pat, r"\1: [REDACTED]", redacted)
        return redacted
    elif isinstance(payload, dict):
        new_dict = {}
        for k, v in payload.items():
            if any(term in k.lower() for term in ["key", "secret", "password", "token", "auth", "grok"]):
                new_dict[k] = "[REDACTED]"
            else:
                new_dict[k] = redact_secrets(v)
        return new_dict
    elif isinstance(payload, list):
        return [redact_secrets(item) for item in payload]
    return payload


class MCPTrustGatewayProxy:
    """MCP Proxy Handler between agent clients and upstream MCP servers."""

    def __init__(self, confirmation_mgr: Optional[ConfirmationManager] = None):
        self.baseline_mgr = SchemaBaselineManager()
        self.policy_engine = PolicyEngine()
        self.classifier_pipeline = TwoStageDetectionPipeline()
        self.confirmation_mgr = confirmation_mgr or ConfirmationManager()

    async def handle_list_tools(
        self,
        db: AsyncSession,
        server_id: str,
        upstream_tools: list
    ) -> Dict[str, Any]:
        """Intercepts tools/list response from upstream server and diffs against baseline."""
        diff_res = await self.baseline_mgr.verify_and_update_tools(db, server_id, upstream_tools)
        
        # Filter tool list: block unapproved or changed tools
        approved_tools = []
        for t in upstream_tools:
            tool_name = t.get("name")
            if tool_name in diff_res["approved_tools"]:
                approved_tools.append(t)
                
        return {
            "tools": approved_tools,
            "diff_summary": diff_res
        }

    async def handle_call_tool(
        self,
        db: AsyncSession,
        server_id: str,
        upstream_url: str,
        tool_name: str,
        arguments: Dict[str, Any]
    ) -> Tuple[bool, Dict[str, Any], str]:
        """
        Proxy handler for tools/call execution.
        Flow:
        1. Baseline Check (Block if unapproved / schema changed)
        2. Policy Check (Allow, Block, Rate-Limit, Confirm)
        3. Forward to Upstream Server
        4. Response Scanning via Two-Stage Classifier
        5. Log to DB & Audit Trail
        """
        start_time = time.time()
        
        # 1. Baseline Check
        baseline = await get_tool_baseline(db, server_id, tool_name)
        if not baseline or baseline.status != "approved":
            latency = (time.time() - start_time) * 1000
            await record_tool_call(
                db, server_id, tool_name, redact_secrets(arguments),
                {"error": "Blocked by baseline rug-pull check"},
                classifier_verdict="blocked", policy_decision="blocked_baseline", latency_ms=latency
            )
            return False, {
                "isError": True,
                "content": [{"type": "text", "text": f"Tool call blocked: Tool '{tool_name}' schema is unapproved or modified."}]
            }, "blocked_baseline"

        # 2. Policy Check
        decision, reason, policy_meta = await self.policy_engine.evaluate_call(db, server_id, tool_name, arguments)
        
        if decision == "blocked" or decision == "rate_limited":
            latency = (time.time() - start_time) * 1000
            await record_tool_call(
                db, server_id, tool_name, redact_secrets(arguments),
                {"error": reason}, classifier_verdict="clean", policy_decision=decision, latency_ms=latency
            )
            return False, {
                "isError": True,
                "content": [{"type": "text", "text": f"Tool call blocked by gateway policy: {reason}"}]
            }, decision

        if decision == "held_for_confirm":
            # Record initial held call
            tool_call_rec = await record_tool_call(
                db, server_id, tool_name, redact_secrets(arguments),
                {"status": "holding_for_confirmation"},
                classifier_verdict="clean", policy_decision="held_for_confirm", latency_ms=0
            )
            conf_req = await self.confirmation_mgr.create_confirmation_request(db, tool_call_rec.id, tool_name)
            
            # Wait for human approval or fail-closed timeout
            resolution, resolved_by = await self.confirmation_mgr.wait_for_resolution(db, conf_req.id)
            if resolution != "approved":
                latency = (time.time() - start_time) * 1000
                return False, {
                    "isError": True,
                    "content": [{"type": "text", "text": f"Action denied: High-risk confirmation status '{resolution}' (resolved by {resolved_by})."}]
                }, "confirmation_denied"

        # 3. Forward request to Upstream Server via HTTP
        upstream_response_payload = None
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    f"{upstream_url}/tools/call",
                    json={"name": tool_name, "arguments": arguments}
                )
                if resp.status_code == 200:
                    upstream_response_payload = resp.json()
                else:
                    upstream_response_payload = {
                        "isError": True,
                        "content": [{"type": "text", "text": f"Upstream server returned HTTP {resp.status_code}: {resp.text}"}]
                    }
        except Exception as exc:
            # Fail closed on upstream server error
            latency = (time.time() - start_time) * 1000
            await record_tool_call(
                db, server_id, tool_name, redact_secrets(arguments),
                {"error": str(exc)}, classifier_verdict="error", policy_decision="upstream_failed", latency_ms=latency
            )
            return False, {
                "isError": True,
                "content": [{"type": "text", "text": f"Upstream server connection failed: {str(exc)}"}]
            }, "upstream_error"

        # 4. Response Scanning via Two-Stage Classifier
        verdict, scan_reason, scan_meta = await self.classifier_pipeline.classify_response(
            tool_name, arguments, upstream_response_payload
        )
        latency = (time.time() - start_time) * 1000

        redacted_req = redact_secrets(arguments)
        redacted_resp = redact_secrets(upstream_response_payload)

        # Fail-closed check: if verdict is malicious, suspicious, or error_blocked -> BLOCK!
        if verdict in ["malicious", "suspicious", "error_blocked"]:
            await record_tool_call(
                db, server_id, tool_name, redacted_req, redacted_resp,
                classifier_verdict=verdict, policy_decision="blocked_injection", latency_ms=latency
            )
            await create_incident(
                db,
                detection_type="response_prompt_injection",
                severity="high" if verdict == "malicious" else "medium",
                details={
                    "server_id": server_id,
                    "tool_name": tool_name,
                    "verdict": verdict,
                    "reason": scan_reason,
                    "scan_meta": scan_meta
                },
                server_id=server_id
            )
            await add_audit_entry(
                db,
                actor="classifier_pipeline",
                action="tool_response_blocked",
                target=f"{server_id}:{tool_name}",
                details={"verdict": verdict, "reason": scan_reason}
            )
            return False, {
                "isError": True,
                "content": [{"type": "text", "text": f"Security Alert: Tool response blocked by Gateway injection detection ({scan_reason})."}]
            }, "blocked_injection"

        # Safe clean response -> Return to client
        await record_tool_call(
            db, server_id, tool_name, redacted_req, redacted_resp,
            classifier_verdict="clean", policy_decision="allowed", latency_ms=latency
        )
        return True, upstream_response_payload, "allowed"
