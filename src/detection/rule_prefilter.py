"""Stage 1: Fast Rule-Based Injection Prefilter."""
import re
import json
from typing import Any, Dict, Tuple, List
from src.detection.interfaces import BaseClassifier

KNOWN_INJECTION_PATTERNS = [
    # System prompt override / instruction hijacking
    r"(?i)ignore\s+(all\s+)?previous\s+instructions",
    r"(?i)disregard\s+prior\s+directives",
    r"(?i)system\s*:\s*you\s+are\s+now",
    r"(?i)\[SYSTEM\s+INSTRUCTION\]",
    r"(?i)\[ADMIN\s+OVERRIDE\]",
    r"(?i)act\s+as\s+an?\s+unrestricted",
    r"(?i)new\s+instruction\s*:\s*",
    r"(?i)you\s+must\s+now\s+execute",
    
    # Exfiltration & Poisoning patterns (MCPoison, CurXecute)
    r"(?i)curl\s+-X\s+POST\s+http",
    r"(?i)wget\s+--post-data",
    r"(?i)send\s+api_key\s+to",
    r"(?i)exfiltrate",
    r"(?i)<script[\s>].*?<\/script>",
    r"(?i)eval\s*\(\s*base64",
    r"(?i)exec\s*\(\s*decode",
    r"(?i)system\s*\(\s*['\"]rm\s+-rf",

    # Prompt injection trapped inside markdown / hidden elements
    r"(?i)<!--\s*#system:.*?-->",
    r"(?i)font-size:\s*0px;.*?ignore",
    r"(?i)display:\s*none;.*?instruction"
]

HIGH_RISK_KEYWORDS = [
    "delete_database", "drop_table", "transfer_funds", "sudo", "chmod 777",
    "password_reset", "override_security"
]

class RulePrefilter(BaseClassifier):
    """Stage 1 Rule-Based Fast Scanner."""

    def __init__(self):
        self.compiled_patterns = [re.compile(p, re.DOTALL) for p in KNOWN_INJECTION_PATTERNS]

    def _extract_text(self, obj: Any) -> str:
        """Recursively convert payload to text for scanning."""
        if isinstance(obj, str):
            return obj
        if isinstance(obj, (dict, list)):
            return json.dumps(obj)
        return str(obj)

    async def classify_response(
        self,
        tool_name: str,
        request_payload: Any,
        response_payload: Any
    ) -> Tuple[str, str, Dict[str, Any]]:
        text_content = self._extract_text(response_payload)
        
        # Check against known malicious patterns
        for pattern in self.compiled_patterns:
            match = pattern.search(text_content)
            if match:
                matched_snippet = match.group(0)[:60]
                return (
                    "malicious",
                    f"Matched known prompt injection pattern: '{matched_snippet}'",
                    {"stage": "stage1_rule", "matched_pattern": matched_snippet}
                )

        # Check for suspicious high risk keywords or ambiguous formatting
        for kw in HIGH_RISK_KEYWORDS:
            if kw in text_content.lower() and tool_name not in ["security_audit", "admin_log"]:
                return (
                    "suspicious",
                    f"Contains high-risk keyword: '{kw}'",
                    {"stage": "stage1_rule", "suspicious_keyword": kw}
                )

        return (
            "clean",
            "Passed Stage 1 rule-based checks",
            {"stage": "stage1_rule"}
        )
