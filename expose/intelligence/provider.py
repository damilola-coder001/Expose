"""AI Security Intelligence Provider Interface & Data Models (Phases 11 & 18).

Defines the pluggable SecurityResearchProvider interface and structured schemas for
AI-driven technical explanation, site contextualization, grounded web research,
comparative incident analysis, actionable developer remediation, and fix prioritization.

Architectural Rule:
- The AI never has unrestricted control of the scanner.
- The AI never modifies deterministic security scores or alters finding severity.
- All external claims must be grounded in authoritative sources (OWASP, NIST, CISA, CVE,
  official vendor advisories) and citations must be preserved.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator


class SourceType(str, Enum):
    OWASP = "OWASP"
    NIST = "NIST"
    CISA = "CISA"
    CVE = "CVE"
    VENDOR_DOC = "VENDOR_DOC"
    REPUTABLE_RESEARCH = "REPUTABLE_RESEARCH"
    RFC_STANDARD = "RFC_STANDARD"


class SourceCitation(BaseModel):
    """An authoritative external reference verified during grounded research."""
    title: str = Field(description="Title of the authoritative publication, guideline, or advisory")
    url: str = Field(description="Canonical URL of the external reference")
    source_type: SourceType = Field(default=SourceType.REPUTABLE_RESEARCH, description="Source classification")
    snippet: Optional[str] = Field(default=None, description="Relevant excerpt supporting the claim")
    citation_indices: List[int] = Field(default_factory=list, description="Inline text segment indices where cited")


class AIIntelligenceReport(BaseModel):
    """Structured AI security intelligence output for a single finding."""
    provider_name: str = Field(description="Identifier of research provider (e.g. gemini-2.5-flash, mock-provider)")
    model_version: Optional[str] = Field(default=None, description="AI model version used")
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Phase 12 AI Prompt / Reasoning Contract (8 Canonical Sections)
    observation: str = Field(
        default="",
        description="OBSERVATION: What did Expose actually observe?"
    )
    evidence_summary: str = Field(
        default="",
        description="EVIDENCE: What evidence supports it?"
    )
    security_meaning: str = Field(
        default="",
        description="SECURITY MEANING: What does the observation mean?"
    )
    confidence_explanation: str = Field(
        default="",
        description="CONFIDENCE: How certain are we?"
    )
    impact: str = Field(
        default="",
        description="IMPACT: What could happen?"
    )
    real_world_context: str = Field(
        default="",
        description="REAL-WORLD CONTEXT: What trusted research or documented incidents exist?"
    )
    recommendation: str = Field(
        default="",
        description="RECOMMENDATION: What should the developer do?"
    )
    verification_method: str = Field(
        default="",
        description="VERIFICATION: How can Expose determine whether the issue is fixed?"
    )

    # Phase 11 Backward-Compatible / Extended Fields
    explanation: str = Field(
        default="",
        description="Explain: What does this finding mean technically?"
    )
    contextual_impact: str = Field(
        default="",
        description="Contextualize: Why does it matter specifically for this target website and technology?"
    )
    research_summary: str = Field(
        default="",
        description="Research: Authoritative, current technical context synthesized from primary sources."
    )
    comparative_examples: str = Field(
        default="",
        description="Compare: Documented real-world breach patterns or weakness classes."
    )
    developer_recommendations: List[str] = Field(
        default_factory=list,
        description="Recommend: Step-by-step actionable remediation actions for developers."
    )
    priority_rationale: str = Field(
        default="",
        description="Prioritize: Why this should be fixed before other lower-risk issues."
    )

    # Phase 18 Grounding Citations
    source_citations: List[SourceCitation] = Field(
        default_factory=list,
        description="Preserved external authoritative citations (OWASP, NIST, CISA, CVE, RFCs)"
    )
    is_grounded: bool = Field(
        default=True,
        description="Indicates whether the response is grounded with real-time web search"
    )

    @model_validator(mode="before")
    @classmethod
    def sync_reasoning_contract(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Sync observation / evidence_summary
            if not data.get("observation") and data.get("evidence_summary"):
                data["observation"] = data.get("evidence_summary")
            elif not data.get("evidence_summary") and data.get("observation"):
                data["evidence_summary"] = data.get("observation")

            # Sync explanation <-> security_meaning
            if not data.get("security_meaning") and data.get("explanation"):
                data["security_meaning"] = data["explanation"]
            elif not data.get("explanation") and data.get("security_meaning"):
                data["explanation"] = data["security_meaning"]

            # Sync impact <-> contextual_impact
            if not data.get("impact") and data.get("contextual_impact"):
                data["impact"] = data["contextual_impact"]
            elif not data.get("contextual_impact") and data.get("impact"):
                data["contextual_impact"] = data["impact"]

            # Sync real_world_context <-> research_summary / comparative_examples
            if not data.get("real_world_context"):
                parts = [p for p in [data.get("research_summary"), data.get("comparative_examples")] if p]
                if parts:
                    data["real_world_context"] = " ".join(parts)
            else:
                if not data.get("research_summary"):
                    data["research_summary"] = data["real_world_context"]
                if not data.get("comparative_examples"):
                    data["comparative_examples"] = data["real_world_context"]

            # Sync recommendation <-> developer_recommendations
            if not data.get("recommendation") and data.get("developer_recommendations"):
                if isinstance(data["developer_recommendations"], list):
                    data["recommendation"] = " ".join(data["developer_recommendations"])
                else:
                    data["recommendation"] = str(data["developer_recommendations"])
            elif not data.get("developer_recommendations") and data.get("recommendation"):
                data["developer_recommendations"] = [data["recommendation"]]
        return data


class FindingPriorityItem(BaseModel):
    """Priority order item for holistic remediation roadmap."""
    finding_id: str
    title: str
    priority_rank: int
    urgency_tier: str  # IMMEDIATE_ACTION, HIGH_PRIORITY, MEDIUM_PRIORITY, DEFENSIVE_HARDENING
    justification: str


class AIPrioritizationReport(BaseModel):
    """Holistic multi-finding prioritization roadmap."""
    target: str
    prioritized_items: List[FindingPriorityItem] = Field(default_factory=list)
    executive_summary: str
    remediation_roadmap: List[str] = Field(default_factory=list)


class SecurityResearchProvider(ABC):
    """Pluggable interface for AI Security Intelligence and Web Research providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider identifier."""
        pass

    @abstractmethod
    async def analyze_finding(
        self,
        target_host: str,
        finding_data: Dict[str, Any],
        tech_context: Optional[Dict[str, Any]] = None,
    ) -> AIIntelligenceReport:
        """Analyzes a finding, generating explanation, contextualization, grounded research,

        comparisons, actionable remediation recommendations, and priority justification.
        """
        pass

    @abstractmethod
    async def prioritize_findings(
        self,
        target_host: str,
        findings_data: List[Dict[str, Any]],
        tech_context: Optional[Dict[str, Any]] = None,
    ) -> AIPrioritizationReport:
        """Prioritizes findings across an entire scan, producing a structured remediation roadmap."""
        pass
