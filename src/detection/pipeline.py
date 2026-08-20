"""Two-stage detection pipeline combining fast rule prefilter and Stage 2 LLM classifier."""
import time
from typing import Any, Dict, Tuple
from src.detection.interfaces import BaseClassifier
from src.detection.rule_prefilter import RulePrefilter
from src.detection.llm_classifier import LLMClassifier

class TwoStageDetectionPipeline(BaseClassifier):
    """Orchestrates Stage 1 (RulePrefilter) and Stage 2 (LLMClassifier)."""

    def __init__(self, enable_stage2: bool = True):
        self.stage1 = RulePrefilter()
        self.stage2 = LLMClassifier()
        self.enable_stage2 = enable_stage2

    async def classify_response(
        self,
        tool_name: str,
        request_payload: Any,
        response_payload: Any
    ) -> Tuple[str, str, Dict[str, Any]]:
        start_time = time.time()
        
        # Stage 1: Fast rule-based scan
        verdict, reason, meta1 = await self.stage1.classify_response(tool_name, request_payload, response_payload)
        
        if verdict == "malicious":
            elapsed = (time.time() - start_time) * 1000
            meta1["latency_ms"] = elapsed
            return verdict, reason, meta1
        
        # If suspicious or if full LLM verification is requested, escalate to Stage 2
        if verdict == "suspicious" and self.enable_stage2:
            verdict2, reason2, meta2 = await self.stage2.classify_response(tool_name, request_payload, response_payload)
            elapsed = (time.time() - start_time) * 1000
            meta2.update({"stage1_verdict": verdict, "latency_ms": elapsed})
            
            # If Stage 2 fails closed or returns malicious/suspicious, adopt Stage 2 decision
            return verdict2, reason2, meta2
            
        elapsed = (time.time() - start_time) * 1000
        meta1["latency_ms"] = elapsed
        return verdict, reason, meta1
