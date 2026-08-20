"""Abstract interfaces for detection engines."""
from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple

class BaseClassifier(ABC):
    """Abstract interface for tool response injection detection."""

    @abstractmethod
    async def classify_response(
        self,
        tool_name: str,
        request_payload: Any,
        response_payload: Any
    ) -> Tuple[str, str, Dict[str, Any]]:
        """
        Classifies a tool response.
        Returns:
            Tuple of (verdict, confidence_reason, metadata)
            verdict: 'clean', 'suspicious', 'malicious', 'error_blocked'
        """
        pass
