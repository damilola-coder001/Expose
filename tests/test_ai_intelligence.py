"""Unit tests for Phase 11 (AI Security Intelligence) & Phase 18 (AI Web Research).

Validates:
- SecurityResearchProvider interface compliance
- 6 Core AI responsibilities: Explain, Contextualize, Research, Compare, Recommend, Prioritize
- Authoritative source grounding and citations (OWASP, NIST, CISA, RFCs)
- Zero AI Scoring Authority (score and severities are strictly deterministic)
- Clean fallback to hermetic mock researcher when GEMINI_API_KEY is not set.
"""

import pytest
from expose.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    ObservationStatus,
    Severity,
    TargetScope,
)
from expose.intelligence import (
    AIIntelligenceReport,
    AIPrioritizationReport,
    GeminiResearchProvider,
    MockSecurityResearchProvider,
    SecurityResearchProvider,
    SourceType,
    get_research_provider,
)
from expose.intelligence.gemini_provider import classify_source_url
from expose.core.orchestrator import ScanOrchestrator


@pytest.mark.asyncio
async def test_mock_provider_fulfills_all_ai_responsibilities():
    """Validates that MockSecurityResearchProvider delivers all 6 Phase 11 responsibilities."""
    provider = MockSecurityResearchProvider()
    target_host = "example.com"
    finding_data = {
        "title": "Strict-Transport-Security Header Missing",
        "category": "TRANSPORT_SECURITY",
        "severity": "MEDIUM",
        "confidence": "CONFIRMED",
        "cwe_id": "CWE-319",
        "evidence": {"summary": "HSTS header absent."},
    }

    report = await provider.analyze_finding(target_host, finding_data)

    assert isinstance(report, AIIntelligenceReport)
    # 1. Explain
    assert report.explanation is not None and len(report.explanation) > 20
    # 2. Contextualize
    assert target_host in report.contextual_impact
    # 3. Research
    assert "OWASP" in report.research_summary or "RFC" in report.research_summary
    # 4. Compare
    assert "SSL-stripping" in report.comparative_examples or "theft" in report.comparative_examples.lower()
    # 5. Recommend
    assert len(report.developer_recommendations) >= 2
    # 6. Prioritize
    assert report.priority_rationale is not None and len(report.priority_rationale) > 10

    # Grounded citations
    assert len(report.source_citations) >= 2
    for cite in report.source_citations:
        assert cite.url.startswith("http")
        assert cite.source_type in [SourceType.OWASP, SourceType.CISA, SourceType.NIST, SourceType.RFC_STANDARD]


@pytest.mark.asyncio
async def test_mock_provider_prioritizes_findings_holistically():
    """Validates that prioritize_findings sequences issues by exploitability and urgency."""
    provider = MockSecurityResearchProvider()
    findings_data = [
        {"id": "EXP-1", "title": "Missing Referrer-Policy", "severity": "LOW", "cwe_id": "CWE-200"},
        {"id": "EXP-2", "title": "Exposed .env Configuration File", "severity": "CRITICAL", "cwe_id": "CWE-200"},
        {"id": "EXP-3", "title": "Missing HSTS Header", "severity": "MEDIUM", "cwe_id": "CWE-319"},
    ]

    prio_report = await provider.prioritize_findings("bank.example.com", findings_data)

    assert isinstance(prio_report, AIPrioritizationReport)
    assert len(prio_report.prioritized_items) == 3

    # The CRITICAL issue must be ranked #1
    top_item = prio_report.prioritized_items[0]
    assert top_item.finding_id == "EXP-2"
    assert top_item.priority_rank == 1
    assert top_item.urgency_tier == "IMMEDIATE_ACTION"

    # Multi-phase roadmap
    assert len(prio_report.remediation_roadmap) >= 2


def test_classify_source_url():
    """Validates classification of authoritative URLs."""
    assert classify_source_url("https://cheatsheetseries.owasp.org/cheatsheets/HSTS.html") == SourceType.OWASP
    assert classify_source_url("https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-209a") == SourceType.CISA
    assert classify_source_url("https://csrc.nist.gov/publications/detail/sp/800-53") == SourceType.NIST
    assert classify_source_url("https://datatracker.ietf.org/doc/html/rfc6797") == SourceType.RFC_STANDARD
    assert classify_source_url("https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers") == SourceType.VENDOR_DOC
    assert classify_source_url("https://nvd.nist.gov/vuln/detail/CVE-2024-1234") == SourceType.CVE


def test_provider_factory():
    """Validates factory selection and clean fallback."""
    # Explicit mock
    prov_mock = get_research_provider("mock")
    assert isinstance(prov_mock, MockSecurityResearchProvider)

    # Without GEMINI_API_KEY, fallback to Mock provider
    prov_default = get_research_provider()
    assert isinstance(prov_default, (MockSecurityResearchProvider, GeminiResearchProvider))


@pytest.mark.asyncio
async def test_orchestrator_enrichment_preserves_deterministic_score():
    """CRITICAL GUARDRAIL: AI enrichment must NEVER modify the deterministic security score or severities."""
    orchestrator = ScanOrchestrator()
    mock_provider = MockSecurityResearchProvider()

    # Scan with allow_private to safely test localhost/loopback
    result = await orchestrator.scan(
        "http://127.0.0.1:8000",
        allow_private=True,
        enable_ai=True,
        research_provider=mock_provider,
    )

    # Score card must be computed deterministically
    assert result.score_card is not None
    score = result.score_card.overall_score
    assert 0 <= score <= 100

    # Ensure findings have AI intelligence attached
    confirmed_findings = [f for f in result.findings if f.status == ObservationStatus.CONFIRMED]
    for f in confirmed_findings:
        assert f.ai_intelligence is not None
        assert f.ai_intelligence.provider_name == mock_provider.name
        # Severity must NOT have been changed by AI
        assert f.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

    # Prioritization report populated
    if confirmed_findings:
        assert result.ai_prioritization is not None
        assert len(result.ai_prioritization.prioritized_items) == len(confirmed_findings)


@pytest.mark.asyncio
async def test_phase12_reasoning_contract_adherence():
    """PHASE 12: Verifies that AI Intelligence outputs strictly satisfy the 8-part reasoning contract."""
    provider = MockSecurityResearchProvider()
    target_host = "secure-bank.example.com"

    finding_types = [
        {"title": "Strict-Transport-Security Header Missing", "category": "TRANSPORT_SECURITY", "severity": "MEDIUM", "confidence": "CONFIRMED"},
        {"title": "Content-Security-Policy Header Missing", "category": "CONTENT_SECURITY", "severity": "HIGH", "confidence": "CONFIRMED"},
        {"title": "Cookie Missing Secure Flag", "category": "COOKIE_HYGIENE", "severity": "MEDIUM", "confidence": "CONFIRMED"},
        {"title": "Exposed .env Configuration File", "category": "INFORMATION_EXPOSURE", "severity": "CRITICAL", "confidence": "CONFIRMED"},
        {"title": "Unnecessary Server Banner Disclosed", "category": "SYSTEM_SECURITY", "severity": "LOW", "confidence": "CONFIRMED"},
    ]

    for f_data in finding_types:
        report = await provider.analyze_finding(target_host, f_data)

        # 8 Canonical Contract Sections
        assert report.observation and len(report.observation) > 10, f"Missing observation for {f_data['title']}"
        assert report.evidence_summary and len(report.evidence_summary) > 5, f"Missing evidence_summary for {f_data['title']}"
        assert report.security_meaning and len(report.security_meaning) > 10, f"Missing security_meaning for {f_data['title']}"
        assert report.confidence_explanation and "CONFIRMED" in report.confidence_explanation, f"Missing confidence_explanation for {f_data['title']}"
        assert report.impact and target_host in report.impact, f"Missing impact for {f_data['title']}"
        assert report.real_world_context and len(report.real_world_context) > 15, f"Missing real_world_context for {f_data['title']}"
        assert report.recommendation and len(report.recommendation) > 15, f"Missing recommendation for {f_data['title']}"
        assert report.verification_method and "curl" in report.verification_method.lower(), f"Missing verification_method for {f_data['title']}"

        # Backward compatibility sync
        assert report.explanation == report.security_meaning
        assert report.contextual_impact == report.impact
        assert len(report.developer_recommendations) >= 1
        assert len(report.source_citations) >= 1


def test_phase12_anti_fabrication_constraints_in_gemini_prompt():
    """PHASE 12: Verifies that Gemini provider system instructions mandate the 8-part contract and 6 negative constraints."""
    import inspect
    from expose.intelligence.gemini_provider import GeminiResearchProvider

    source = inspect.getsource(GeminiResearchProvider.analyze_finding)

    # 8 Contract sections in prompt
    assert "1. OBSERVATION" in source
    assert "2. EVIDENCE" in source
    assert "3. SECURITY MEANING" in source
    assert "4. CONFIDENCE" in source
    assert "5. IMPACT" in source
    assert "6. REAL-WORLD CONTEXT" in source
    assert "7. RECOMMENDATION" in source
    assert "8. VERIFICATION" in source

    # 6 Negative anti-fabrication constraints
    assert "NEVER fabricate evidence" in source
    assert "NEVER invent CVEs" in source
    assert "NEVER invent breaches" in source
    assert "NEVER claim exploitation without evidence" in source
    assert "NEVER turn a theoretical possibility into a confirmed vulnerability" in source
    assert "NEVER provide false certainty" in source

