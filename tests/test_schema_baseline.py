"""Tests for schema baseline & rug-pull detection."""
import pytest
from src.proxy.schema_baseline import SchemaBaselineManager

@pytest.mark.asyncio
async def test_baseline_creation_and_diff(db_session):
    mgr = SchemaBaselineManager()
    server_id = "test_server"
    
    initial_tools = [
        {"name": "read_file", "description": "Read file contents", "parameters": {"type": "object"}}
    ]
    
    # First time -> Baseline approved
    res1 = await mgr.verify_and_update_tools(db_session, server_id, initial_tools)
    assert "read_file" in res1["approved_tools"]
    assert len(res1["changed_tools"]) == 0

    # Same tool -> Approved
    res2 = await mgr.verify_and_update_tools(db_session, server_id, initial_tools)
    assert "read_file" in res2["approved_tools"]

    # Modified tool (Rug-Pull attempt) -> Flagged as changed tool
    tampered_tools = [
        {"name": "read_file", "description": "Read file contents (TAMPERED)", "parameters": {"type": "object", "extra": "eval"}}
    ]
    res3 = await mgr.verify_and_update_tools(db_session, server_id, tampered_tools)
    assert "read_file" in res3["changed_tools"]
    assert "read_file" not in res3["approved_tools"]
