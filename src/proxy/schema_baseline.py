"""Connect-time schema baseline & rug-pull diff detector."""
import json
import hashlib
from typing import Dict, Any, List, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from src.database.repository import get_tool_baseline, save_tool_baseline, create_incident, add_audit_entry

class SchemaBaselineManager:
    """Detects tool schema modifications (rug pulls) against baseline definitions."""

    @staticmethod
    def _compute_hash(schema_json: Dict[str, Any]) -> str:
        s = json.dumps(schema_json, sort_keys=True)
        return hashlib.sha256(s.encode("utf-8")).hexdigest()

    async def verify_and_update_tools(
        self,
        db: AsyncSession,
        server_id: str,
        current_tools: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Diffs tools against stored baselines.
        Returns diff summary:
            {
              "approved_tools": [...],
              "changed_tools": [...],
              "new_tools": [...]
            }
        """
        approved_tools = []
        changed_tools = []
        new_tools = []

        for tool in current_tools:
            tool_name = tool.get("name")
            if not tool_name:
                continue

            current_hash = self._compute_hash(tool)
            baseline = await get_tool_baseline(db, server_id, tool_name)

            if not baseline:
                # First time seeing this tool -> capture initial baseline as pending or approved
                await save_tool_baseline(db, server_id, tool_name, tool, approved_by="initial_connect", status="approved")
                approved_tools.append(tool_name)
                new_tools.append(tool_name)
                await add_audit_entry(
                    db,
                    actor="system",
                    action="schema_baseline_created",
                    target=f"{server_id}:{tool_name}",
                    details={"tool": tool_name}
                )
            else:
                if baseline.description_hash == current_hash and baseline.status == "approved":
                    approved_tools.append(tool_name)
                else:
                    # Schema mismatch or unapproved state -> Flag Rug-Pull!
                    changed_tools.append(tool_name)
                    # Create incident
                    await create_incident(
                        db,
                        detection_type="rug_pull_schema_change",
                        severity="high",
                        details={
                            "server_id": server_id,
                            "tool_name": tool_name,
                            "baseline_hash": baseline.description_hash,
                            "current_hash": current_hash,
                            "message": "Tool schema modified since baseline approval. Blocking call until re-approved."
                        },
                        server_id=server_id
                    )
                    await add_audit_entry(
                        db,
                        actor="system",
                        action="rug_pull_detected",
                        target=f"{server_id}:{tool_name}",
                        details={"baseline_hash": baseline.description_hash, "new_hash": current_hash}
                    )

        return {
            "approved_tools": approved_tools,
            "changed_tools": changed_tools,
            "new_tools": new_tools
        }
