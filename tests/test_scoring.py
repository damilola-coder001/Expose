"""Unit tests for the deterministic security scoring engine and assessment boundaries."""

import pytest
from expose.core.models import (
    Category,
    Confidence,
    Evidence,
    EvidenceType,
    Finding,
    ObservationStatus,
    Severity,
)
from expose.core.scoring import (
    calculate_letter_grade,
    calculate_score_card,
    SEVERITY_DEDUCTIONS,
)


def create_dummy_finding(
    category: Category,
    severity: Severity,
    status: ObservationStatus = ObservationStatus.CONFIRMED,
    title: str = "Test Issue",
) -> Finding:
    return Finding(
        id=f"EXP-TEST-{severity.value}",
        probe="test_probe",
        target="https://example.com",
        category=category,
        severity=severity,
        confidence=Confidence.CONFIRMED,
        status=status,
        title=title,
        description="Test description",
        remediation="Test remediation",
        evidence=Evidence(type=EvidenceType.RAW_SOCKET, summary="Evidence proof"),
    )


def test_perfect_score_when_no_confirmed_issues():
    # Only positive OBSERVED attributes
    findings = [
        create_dummy_finding(Category.CRYPTOGRAPHY, Severity.INFO, status=ObservationStatus.OBSERVED, title="Valid Cert"),
        create_dummy_finding(Category.TRANSPORT_SECURITY, Severity.INFO, status=ObservationStatus.OBSERVED, title="TLS 1.3"),
    ]
    card = calculate_score_card(findings)
    assert card.overall_score == 100
    assert card.letter_grade == "A+"
    assert card.confirmed_flaws_count == 0
    assert card.observed_properties_count == 2
    assert len(card.not_assessed_boundaries) > 0


def test_deductions_applied_for_confirmed_issues():
    # 1 CRITICAL issue in CRYPTOGRAPHY (-35 pts in 15% weight category)
    findings = [
        create_dummy_finding(Category.CRYPTOGRAPHY, Severity.CRITICAL, status=ObservationStatus.CONFIRMED, title="Expired Cert")
    ]
    card = calculate_score_card(findings)
    assert card.score_version == "1.0"
    transport_score = card.category_scores["Transport Security"].score
    assert transport_score == 65
    # Overall score: 65 * 0.15 + 100 * 0.85 = 9.75 + 85 = 94.75 -> 95
    assert card.overall_score == 95
    assert card.letter_grade == "A+"
    assert card.confirmed_flaws_count == 1


def test_letter_grade_thresholds():
    assert calculate_letter_grade(98) == "A+"
    assert calculate_letter_grade(95) == "A+"
    assert calculate_letter_grade(94) == "A"
    assert calculate_letter_grade(90) == "A"
    assert calculate_letter_grade(89) == "B"
    assert calculate_letter_grade(80) == "B"
    assert calculate_letter_grade(79) == "C"
    assert calculate_letter_grade(70) == "C"
    assert calculate_letter_grade(69) == "D"
    assert calculate_letter_grade(60) == "D"
    assert calculate_letter_grade(59) == "F"
    assert calculate_letter_grade(0) == "F"


def test_not_assessed_boundaries_included():
    card = calculate_score_card([])
    areas = [b.area for b in card.not_assessed_boundaries]
    assert any("Authentication" in a for a in areas)
    assert any("Business Logic" in a for a in areas)
    assert any("Injection" in a for a in areas)
    assert any("Internal Infrastructure" in a for a in areas)
    assert any("Source Code" in a for a in areas)
