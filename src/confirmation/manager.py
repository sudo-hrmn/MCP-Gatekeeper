"""Human Confirmation Manager with fail-closed timeout support."""
import asyncio
import datetime
import uuid
from typing import Dict, Optional, Tuple, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from src.config import settings
from src.database.models import HumanConfirmation, ToolCall
from src.database.repository import add_audit_entry

class ConfirmationManager:
    """Manages pending human approval gates for high-risk actions."""

    def __init__(self):
        # Event objects in memory for active pending calls: {confirmation_id: asyncio.Event}
        self._events: Dict[str, asyncio.Event] = {}
        # Result dictionary: {confirmation_id: (status, resolved_by)}
        self._results: Dict[str, Tuple[str, str]] = {}

    async def create_confirmation_request(
        self,
        db: AsyncSession,
        tool_call_id: str,
        tool_name: str
    ) -> HumanConfirmation:
        conf_id = str(uuid.uuid4())
        now = datetime.datetime.now(datetime.timezone.utc)
        confirmation = HumanConfirmation(
            id=conf_id,
            tool_call_id=tool_call_id,
            tool_name=tool_name,
            status="pending",
            requested_at=now
        )
        db.add(confirmation)
        await db.commit()
        await db.refresh(confirmation)
        
        self._events[conf_id] = asyncio.Event()
        
        await add_audit_entry(
            db,
            actor="system",
            action="confirmation_requested",
            target=tool_name,
            details={"confirmation_id": conf_id, "tool_call_id": tool_call_id}
        )
        return confirmation

    async def wait_for_resolution(
        self,
        db: AsyncSession,
        confirmation_id: str,
        timeout_seconds: Optional[int] = None
    ) -> Tuple[str, str]:
        """
        Waits for a human to resolve the pending confirmation request.
        If unanswered within timeout, fails closed (returns 'denied', 'system_timeout').
        """
        timeout = timeout_seconds or settings.CONFIRMATION_TIMEOUT_SECONDS
        event = self._events.get(confirmation_id)
        
        if not event:
            event = asyncio.Event()
            self._events[confirmation_id] = event

        try:
            await asyncio.wait_for(event.wait(), timeout=float(timeout))
            status, resolved_by = self._results.pop(confirmation_id, ("denied", "unknown"))
            return status, resolved_by
        except asyncio.TimeoutError:
            # Fail closed on timeout
            now = datetime.datetime.now(datetime.timezone.utc)
            await db.execute(
                update(HumanConfirmation)
                .where(HumanConfirmation.id == confirmation_id)
                .values(status="timed_out", resolved_at=now, resolved_by="system_timeout")
            )
            await db.commit()
            
            await add_audit_entry(
                db,
                actor="system_timeout",
                action="confirmation_timed_out",
                target=confirmation_id,
                details={"status": "timed_out", "reason": f"No answer within {timeout}s"}
            )
            
            self._events.pop(confirmation_id, None)
            self._results.pop(confirmation_id, None)
            return "denied", "system_timeout"

    async def resolve_confirmation(
        self,
        db: AsyncSession,
        confirmation_id: str,
        approved: bool,
        resolved_by: str = "admin"
    ) -> Optional[HumanConfirmation]:
        """Resolves a pending human confirmation request."""
        status = "approved" if approved else "denied"
        now = datetime.datetime.now(datetime.timezone.utc)
        
        result = await db.execute(select(HumanConfirmation).where(HumanConfirmation.id == confirmation_id))
        confirmation = result.scalar_one_or_none()
        
        if not confirmation:
            return None
            
        confirmation.status = status
        confirmation.resolved_at = now
        confirmation.resolved_by = resolved_by
        await db.commit()
        await db.refresh(confirmation)

        await add_audit_entry(
            db,
            actor=resolved_by,
            action="confirmation_resolved",
            target=confirmation_id,
            details={"status": status, "approved": approved}
        )

        self._results[confirmation_id] = (status, resolved_by)
        event = self._events.get(confirmation_id)
        if event:
            event.set()

        return confirmation
