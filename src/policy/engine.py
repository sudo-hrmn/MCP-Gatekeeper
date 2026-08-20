"""Policy rule evaluator for MCP Trust Gateway."""
import time
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from src.database.models import PolicyRule

HIGH_RISK_ACTION_SUBSTRINGS = [
    "delete", "remove", "drop", "destroy", "send_funds", "transfer",
    "update_permission", "grant_access", "exec_", "shell_command", "write_file"
]

class PolicyEngine:
    """Evaluates rules for tool calls (allow / block / confirm / rate_limit)."""

    def __init__(self):
        # Sliding window rate limiter state: {(server_id, tool_name): [timestamps]}
        self.call_timestamps: Dict[Tuple[str, str], List[float]] = {}

    def _check_rate_limit(self, server_id: str, tool_name: str, max_per_min: int) -> bool:
        """Returns True if within rate limit, False if rate limit exceeded."""
        key = (server_id, tool_name)
        now = time.time()
        window_start = now - 60.0
        
        timestamps = self.call_timestamps.get(key, [])
        # Prune old timestamps
        timestamps = [ts for ts in timestamps if ts > window_start]
        
        if len(timestamps) >= max_per_min:
            self.call_timestamps[key] = timestamps
            return False
            
        timestamps.append(now)
        self.call_timestamps[key] = timestamps
        return True

    async def evaluate_call(
        self,
        db: AsyncSession,
        server_id: str,
        tool_name: str,
        request_payload: Any
    ) -> Tuple[str, str, Dict[str, Any]]:
        """
        Evaluates policy for an incoming tool call before forwarding to server.
        Returns:
            Tuple of (decision, reason, details)
            decision: 'allowed', 'blocked', 'held_for_confirm', 'rate_limited'
        """
        # Fetch active policies (ordered by priority: tool-specific > server-specific > global)
        stmt = select(PolicyRule).where(
            (PolicyRule.server_id == server_id) | (PolicyRule.server_id == None)
        )
        result = await db.execute(stmt)
        rules = list(result.scalars().all())

        # Sort rules: tool_name match first, then server_id match, then global
        def rule_priority(r: PolicyRule):
            if r.tool_name == tool_name:
                return 3
            if r.tool_name is None and r.server_id == server_id:
                return 2
            return 1

        rules.sort(key=rule_priority, reverse=True)

        for rule in rules:
            if rule.tool_name and rule.tool_name != tool_name:
                continue
                
            rule_type = rule.rule_type.lower()
            config = rule.rule_config or {}

            if rule_type == "block":
                return "blocked", f"Explicit block policy rule ID '{rule.id}'", {"rule_id": rule.id}

            if rule_type == "confirm":
                return "held_for_confirm", f"Action held for human confirmation by policy rule ID '{rule.id}'", {"rule_id": rule.id}

            if rule_type == "rate_limit":
                limit = config.get("rate_limit_per_min", 30)
                if not self._check_rate_limit(server_id, tool_name, limit):
                    return "rate_limited", f"Rate limit of {limit} calls/min exceeded", {"rate_limit": limit}

            if rule_type == "allow":
                return "allowed", f"Explicit allow policy rule ID '{rule.id}'", {"rule_id": rule.id}

        # Implicit high-risk action detection if no explicit rule matches
        lower_tool = tool_name.lower()
        for hr_pattern in HIGH_RISK_ACTION_SUBSTRINGS:
            if hr_pattern in lower_tool:
                return (
                    "held_for_confirm",
                    f"High-risk action detected ('{tool_name}' matches high-risk pattern '{hr_pattern}')",
                    {"high_risk_pattern": hr_pattern}
                )

        return "allowed", "Default policy: allowed", {}
