"""AI Security Intelligence & Grounded Web Research Package (Phases 11 & 18).

Provides pluggable AI intelligence providers, structured intelligence models,
and factory methods.
"""

import os
from typing import Optional

from .provider import (
    AIIntelligenceReport,
    AIPrioritizationReport,
    FindingPriorityItem,
    SecurityResearchProvider,
    SourceCitation,
    SourceType,
)
from .mock_provider import MockSecurityResearchProvider
from .gemini_provider import GeminiResearchProvider
from .safety import (
    AIPermissionPolicy,
    AgenticRiskViolation,
    GoalHijackingError,
    ToolMisuseError,
    detect_goal_hijacking,
    get_ai_permission_policy,
    sanitize_ai_input_text,
    validate_ai_tool_invocation,
)


def get_research_provider(
    provider_type: Optional[str] = None,
    api_key: Optional[str] = None,
) -> SecurityResearchProvider:
    """Factory function returning the configured SecurityResearchProvider.
    
    If provider_type is explicitly 'mock', returns MockSecurityResearchProvider.
    If provider_type is 'gemini' or GEMINI_API_KEY is present, returns GeminiResearchProvider.
    Otherwise, returns MockSecurityResearchProvider for hermetic local operation.
    """
    selected_type = (provider_type or os.getenv("EXPOSE_AI_PROVIDER", "")).lower()

    if selected_type == "mock":
        return MockSecurityResearchProvider()

    key = api_key or os.getenv("GEMINI_API_KEY")
    if selected_type == "gemini" or key:
        return GeminiResearchProvider(api_key=key)

    # Clean default: Mock provider for hermetic testing and offline use
    return MockSecurityResearchProvider()


__all__ = [
    "SecurityResearchProvider",
    "AIIntelligenceReport",
    "AIPrioritizationReport",
    "FindingPriorityItem",
    "SourceCitation",
    "SourceType",
    "GeminiResearchProvider",
    "MockSecurityResearchProvider",
    "get_research_provider",
    "AIPermissionPolicy",
    "AgenticRiskViolation",
    "GoalHijackingError",
    "ToolMisuseError",
    "detect_goal_hijacking",
    "get_ai_permission_policy",
    "sanitize_ai_input_text",
    "validate_ai_tool_invocation",
]
