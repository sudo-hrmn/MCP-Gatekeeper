"""SQLAlchemy ORM models for MCP Trust Gateway."""
import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, JSON, ForeignKey, Boolean, Float
from sqlalchemy.orm import relationship
from src.database.connection import Base

def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)

class UpstreamServer(Base):
    __tablename__ = "servers"

    id = Column(String(64), primary_key=True)  # e.g., "server_1" or UUID
    name = Column(String(128), nullable=False)
    upstream_url = Column(String(512), nullable=False)
    status = Column(String(32), default="active")  # active, disabled, degraded
    added_at = Column(DateTime(timezone=True), default=utcnow)

    baselines = relationship("ToolBaseline", back_populates="server", cascade="all, delete-orphan")
    calls = relationship("ToolCall", back_populates="server")
    policies = relationship("PolicyRule", back_populates="server")


class ToolBaseline(Base):
    __tablename__ = "tool_baselines"

    id = Column(String(64), primary_key=True)
    server_id = Column(String(64), ForeignKey("servers.id"), nullable=False)
    tool_name = Column(String(128), nullable=False)
    schema_json = Column(JSON, nullable=False)
    description_hash = Column(String(64), nullable=False)
    approved_at = Column(DateTime(timezone=True), default=utcnow)
    approved_by = Column(String(128), default="system")
    status = Column(String(32), default="approved")  # approved, pending_review, blocked

    server = relationship("UpstreamServer", back_populates="baselines")


class ToolCall(Base):
    __tablename__ = "tool_calls"

    id = Column(String(64), primary_key=True)
    server_id = Column(String(64), ForeignKey("servers.id"), nullable=False)
    tool_name = Column(String(128), nullable=False)
    request_payload = Column(JSON, nullable=True)  # Credential-redacted
    response_payload = Column(JSON, nullable=True) # Credential-redacted
    classifier_verdict = Column(String(32), default="clean")  # clean, suspicious, malicious, error
    policy_decision = Column(String(32), default="allowed")   # allowed, blocked, held_for_confirm, rate_limited
    latency_ms = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    server = relationship("UpstreamServer", back_populates="calls")
    confirmations = relationship("HumanConfirmation", back_populates="tool_call")
    incidents = relationship("Incident", back_populates="tool_call")


class PolicyRule(Base):
    __tablename__ = "policies"

    id = Column(String(64), primary_key=True)
    server_id = Column(String(64), ForeignKey("servers.id"), nullable=True) # None = global policy
    tool_name = Column(String(128), nullable=True) # None = server-wide policy
    rule_type = Column(String(32), nullable=False)  # allow, block, confirm, rate_limit
    rule_config = Column(JSON, nullable=True)      # e.g. {"rate_limit_per_min": 60, "risk_keywords": ["delete", "drop"]}
    created_at = Column(DateTime(timezone=True), default=utcnow)

    server = relationship("UpstreamServer", back_populates="policies")


class HumanConfirmation(Base):
    __tablename__ = "confirmations"

    id = Column(String(64), primary_key=True)
    tool_call_id = Column(String(64), ForeignKey("tool_calls.id"), nullable=False)
    tool_name = Column(String(128), nullable=False)
    status = Column(String(32), default="pending")  # pending, approved, denied, timed_out
    requested_at = Column(DateTime(timezone=True), default=utcnow)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by = Column(String(128), nullable=True)

    tool_call = relationship("ToolCall", back_populates="confirmations")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(64), primary_key=True)
    tool_call_id = Column(String(64), ForeignKey("tool_calls.id"), nullable=True)
    server_id = Column(String(64), ForeignKey("servers.id"), nullable=True)
    severity = Column(String(32), default="medium")  # high, medium, low
    detection_type = Column(String(64), nullable=False) # rug_pull, prompt_injection, policy_violation
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)
    reviewed = Column(Boolean, default=False)

    tool_call = relationship("ToolCall", back_populates="incidents")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(String(64), primary_key=True)
    actor = Column(String(128), nullable=False)
    action = Column(String(128), nullable=False)
    target = Column(String(128), nullable=False)
    details = Column(JSON, nullable=True)
    previous_hash = Column(String(64), nullable=False, default="0"*64)
    current_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
