"""Repository helper functions for data access & hash-chained audit logging."""
import hashlib
import json
import uuid
import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, desc
from src.database.models import (
    UpstreamServer, ToolBaseline, ToolCall, PolicyRule,
    HumanConfirmation, Incident, AuditLog
)

def compute_hash(actor: str, action: str, target: str, details: Any, prev_hash: str, timestamp_str: str) -> str:
    """Compute SHA-256 hash for audit record chaining."""
    payload = f"{actor}|{action}|{target}|{json.dumps(details, sort_keys=True)}|{prev_hash}|{timestamp_str}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def add_audit_entry(
    db: AsyncSession,
    actor: str,
    action: str,
    target: str,
    details: Optional[Dict[str, Any]] = None
) -> AuditLog:
    """Add a tamper-evident audit log entry linked to the previous entry via SHA-256 hash chaining."""
    details = details or {}
    
    # Fetch last audit entry hash
    result = await db.execute(select(AuditLog).order_by(desc(AuditLog.created_at)).limit(1))
    last_entry = result.scalar_one_or_none()
    prev_hash = last_entry.current_hash if last_entry else "0" * 64
    
    now = datetime.datetime.now(datetime.timezone.utc)
    timestamp_str = now.isoformat()
    current_hash = compute_hash(actor, action, target, details, prev_hash, timestamp_str)
    
    entry = AuditLog(
        id=str(uuid.uuid4()),
        actor=actor,
        action=action,
        target=target,
        details=details,
        previous_hash=prev_hash,
        current_hash=current_hash,
        created_at=now
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry


async def get_all_servers(db: AsyncSession) -> List[UpstreamServer]:
    result = await db.execute(select(UpstreamServer))
    return list(result.scalars().all())


async def register_server(db: AsyncSession, server_id: str, name: str, upstream_url: str) -> UpstreamServer:
    server = UpstreamServer(
        id=server_id,
        name=name,
        upstream_url=upstream_url,
        status="active"
    )
    db.add(server)
    await db.commit()
    await db.refresh(server)
    return server


async def get_tool_baseline(db: AsyncSession, server_id: str, tool_name: str) -> Optional[ToolBaseline]:
    result = await db.execute(
        select(ToolBaseline).where(
            ToolBaseline.server_id == server_id,
            ToolBaseline.tool_name == tool_name
        )
    )
    return result.scalar_one_or_none()


async def save_tool_baseline(
    db: AsyncSession,
    server_id: str,
    tool_name: str,
    schema_json: Dict[str, Any],
    approved_by: str = "system",
    status: str = "approved"
) -> ToolBaseline:
    schema_str = json.dumps(schema_json, sort_keys=True)
    desc_hash = hashlib.sha256(schema_str.encode("utf-8")).hexdigest()
    
    baseline = await get_tool_baseline(db, server_id, tool_name)
    now = datetime.datetime.now(datetime.timezone.utc)
    
    if baseline:
        baseline.schema_json = schema_json
        baseline.description_hash = desc_hash
        baseline.approved_at = now
        baseline.approved_by = approved_by
        baseline.status = status
    else:
        baseline = ToolBaseline(
            id=str(uuid.uuid4()),
            server_id=server_id,
            tool_name=tool_name,
            schema_json=schema_json,
            description_hash=desc_hash,
            approved_at=now,
            approved_by=approved_by,
            status=status
        )
        db.add(baseline)
    
    await db.commit()
    await db.refresh(baseline)
    return baseline


async def record_tool_call(
    db: AsyncSession,
    server_id: str,
    tool_name: str,
    request_payload: Any,
    response_payload: Any,
    classifier_verdict: str,
    policy_decision: str,
    latency_ms: float
) -> ToolCall:
    tool_call = ToolCall(
        id=str(uuid.uuid4()),
        server_id=server_id,
        tool_name=tool_name,
        request_payload=request_payload,
        response_payload=response_payload,
        classifier_verdict=classifier_verdict,
        policy_decision=policy_decision,
        latency_ms=latency_ms
    )
    db.add(tool_call)
    await db.commit()
    await db.refresh(tool_call)
    return tool_call


async def create_incident(
    db: AsyncSession,
    detection_type: str,
    severity: str,
    details: Dict[str, Any],
    tool_call_id: Optional[str] = None,
    server_id: Optional[str] = None
) -> Incident:
    incident = Incident(
        id=str(uuid.uuid4()),
        tool_call_id=tool_call_id,
        server_id=server_id,
        severity=severity,
        detection_type=detection_type,
        details=details,
        reviewed=False
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    return incident
