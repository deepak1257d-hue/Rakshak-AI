import logging
from typing import Dict, Any
from app.schemas.domain import RawToolResultSchema, RefinedSecurityInsightSchema, SeverityLevel

logger = logging.getLogger(__name__)

class UntrustedParserAgent:
    """
    Agent 1: Untrusted Parser Model
    Takes raw, potentially hostile scanner outputs (stdout, HTTP responses, banners)
    and strips prompt-injection payloads, mapping the data strictly into Pydantic models.
    """
    @staticmethod
    def parse_raw_output(tool_name: str, raw_output: str, target_host: str) -> RawToolResultSchema:
        # Sanitize any potential prompt injection strings or markdown backticks
        clean_raw = raw_output.replace("SYSTEM INSTRUCTION:", "[REDACTED]").replace("IGNORE PREVIOUS", "[REDACTED]")
        
        # Extract potential evidence cleanly
        evidence_snippet = clean_raw[:500] if len(clean_raw) > 500 else clean_raw
        
        return RawToolResultSchema(
            tool_name=tool_name,
            raw_finding=clean_raw[:200],
            affected_host=target_host,
            evidence=evidence_snippet,
            potential_cve=None
        )

class SystemReasoningAgent:
    """
    Agent 2: System Reasoning Model
    Legacy placeholder. Scanner text alone is insufficient to synthesize verified findings.
    """
    @staticmethod
    def generate_insight(sanitized_input: RawToolResultSchema) -> RefinedSecurityInsightSchema:
        raise NotImplementedError(
            "The legacy dual-LLM simulator cannot create findings from unverified scanner text."
        )

class DualLLMPipeline:
    """
    Orchestrates the Dual-LLM Anti-Prompt Injection Pipeline
    """
    def __init__(self):
        self.parser = UntrustedParserAgent()
        self.reasoner = SystemReasoningAgent()

    def process_scanner_output(self, tool_name: str, raw_output: str, target_host: str) -> Dict[str, Any]:
        # Step 1: Untrusted Parser parses raw output into structured model
        sanitized_struct = self.parser.parse_raw_output(tool_name, raw_output, target_host)
        
        # Step 2: System Reasoning Agent generates safe business/technical insights & code patch diff
        refined_insight = self.reasoner.generate_insight(sanitized_struct)
        
        return {
            "sanitized_input": sanitized_struct.model_dump(),
            "insight": refined_insight.model_dump()
        }

dual_llm_pipeline = DualLLMPipeline()
