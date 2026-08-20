"""
Application configuration for MCP Trust Gateway.
"""
import os
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    # Gateway settings
    HOST: str = Field(default="0.0.0.0", alias="GATEWAY_HOST")
    PORT: int = Field(default=8000, alias="GATEWAY_PORT")
    ADMIN_API_KEY: str = Field(default="trust-gateway-admin-key-secret", alias="ADMIN_API_KEY")
    DATABASE_URL: str = Field(default="sqlite+aiosqlite:///mcp_trust_gateway.db", alias="DATABASE_URL")
    
    # LLM Security Classifier API Configuration (Supports Grok, OpenAI, DeepSeek, Ollama, etc.)
    LLM_API_KEY: Optional[str] = Field(default_factory=lambda: os.getenv("LLM_API_KEY") or os.getenv("GROK_API") or os.getenv("OPENAI_API_KEY"))
    LLM_API_URL: str = Field(default_factory=lambda: os.getenv("LLM_API_URL") or os.getenv("GROK_API_URL") or "https://api.x.ai/v1/chat/completions")
    LLM_MODEL: str = Field(default_factory=lambda: os.getenv("LLM_MODEL") or os.getenv("GROK_MODEL") or "grok-2-latest")
    CLASSIFIER_TIMEOUT_SECONDS: float = Field(default=3.0, alias="CLASSIFIER_TIMEOUT_SECONDS")
    
    # Confirmation Gate Configuration
    CONFIRMATION_TIMEOUT_SECONDS: int = Field(default=60, alias="CONFIRMATION_TIMEOUT_SECONDS")
    
    # Default Policy Mode: fail_closed by default
    FAIL_CLOSED: bool = Field(default=True, alias="FAIL_CLOSED")
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
