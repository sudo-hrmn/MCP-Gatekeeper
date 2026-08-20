"""Tests for Policy Engine evaluation."""
import pytest
from src.policy.engine import PolicyEngine
from src.database.models import PolicyRule

@pytest.mark.asyncio
async def test_policy_default_allow(db_session):
    engine = PolicyEngine()
    decision, reason, details = await engine.evaluate_call(db_session, "server_1", "get_weather", {})
    assert decision == "allowed"

@pytest.mark.asyncio
async def test_policy_high_risk_auto_confirm(db_session):
    engine = PolicyEngine()
    decision, reason, details = await engine.evaluate_call(db_session, "server_1", "delete_user_account", {})
    assert decision == "held_for_confirm"

@pytest.mark.asyncio
async def test_policy_explicit_block(db_session):
    engine = PolicyEngine()
    rule = PolicyRule(id="rule_1", server_id="server_1", tool_name="bad_tool", rule_type="block")
    db_session.add(rule)
    await db_session.commit()

    decision, reason, details = await engine.evaluate_call(db_session, "server_1", "bad_tool", {})
    assert decision == "blocked"
