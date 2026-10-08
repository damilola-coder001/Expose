"""Unit tests for Phase 9 Deterministic Security Scoring Engine v1.0.

Verifies:
- 9 canonical scoring categories with weights summing to 100%
- Score versioning (score_version = "1.0")
- Deterministic reproducibility (zero randomness, pure mathematical evaluation)
- Confidence weighting multipliers
- Bound checks (scores clamped between 0 and 100)
- Informational findings zero deduction guarantee
"""

import random
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
    CATEGORY_MAPPING,
    CONFIDENCE_MULTIPLIERS,
    SCORE_VERSION,
    SEVERITY_DEDUCTIONS,
    calculate_letter_grade,
    calculate_score_card,
)


def make_finding(
    category: Category,
    severity: Severity,
    confidence: Confidence = Confidence.CONFIRMED,
    status: ObservationStatus = ObservationStatus.CONFIRMED,
    rule_id: str = "TEST_RULE",
) -> Finding:
    return Finding(
        id=f"EXP-{rule_id}-{severity.value}",
        probe="test_probe",
        target="https://example.com",
        category=category,
        severity=severity,
        confidence=confidence,
        status=status,
        title=f"Test Finding {rule_id}",
        description="Detailed description for testing",
        remediation="Remediation instructions",
        evidence=Evidence(type=EvidenceType.RAW_SOCKET, summary="Evidence proof"),
    )


def test_canonical_categories_and_weights_sum_to_100():
    expected_categories = [
        ("Transport Security", 15),
        ("Browser Security", 15),
        ("Cookie & Session Security", 10),
        ("Configuration", 10),
        ("Attack Surface", 10),
        ("Information Exposure", 10),
        ("API Security", 10),
        ("Third-Party Resources", 10),
        ("Authentication", 10),
    ]

    assert len(CATEGORY_MAPPING) == 9
    total_weight = 0

    for name, expected_wt in expected_categories:
        assert name in CATEGORY_MAPPING, f"Missing canonical category: {name}"
        actual_wt = CATEGORY_MAPPING[name]["weight"]
        assert actual_wt == expected_wt, f"Weight mismatch for {name}: expected {expected_wt}, got {actual_wt}"
        total_weight += actual_wt

    assert total_weight == 100


def test_score_versioning():
    card = calculate_score_card([])
    assert card.score_version == "1.0"
    assert SCORE_VERSION == "1.0"


def test_deterministic_reproducibility():
    findings = [
        make_finding(Category.TRANSPORT_SECURITY, Severity.HIGH, Confidence.CONFIRMED, rule_id="TLS_LEGACY"),
        make_finding(Category.HTTP_HEADERS, Severity.MEDIUM, Confidence.LIKELY, rule_id="MISSING_CSP"),
        make_finding(Category.COOKIE_SECURITY, Severity.LOW, Confidence.CONFIRMED, rule_id="COOKIE_SAMESITE"),
        make_finding(Category.ATTACK_SURFACE, Severity.INFO, Confidence.INFORMATIONAL, rule_id="SURFACE_MAP"),
        make_finding(Category.INFORMATION_EXPOSURE, Severity.MEDIUM, Confidence.CONFIRMED, rule_id="ROBOTS_ADMIN"),
    ]

    base_card = calculate_score_card(findings)

    # Run 50 iterations with shuffled finding ordering
    for i in range(50):
        shuffled = list(findings)
        random.shuffle(shuffled)
        iteration_card = calculate_score_card(shuffled)

        assert iteration_card.overall_score == base_card.overall_score
        assert iteration_card.letter_grade == base_card.letter_grade
        assert iteration_card.score_version == base_card.score_version
        assert iteration_card.confirmed_flaws_count == base_card.confirmed_flaws_count

        for cat_name, base_cat in base_card.category_scores.items():
            iter_cat = iteration_card.category_scores[cat_name]
            assert iter_cat.score == base_cat.score
            assert iter_cat.findings_count == base_cat.findings_count
            assert iter_cat.confirmed_issues_count == base_cat.confirmed_issues_count


def test_confidence_multiplier_deductions():
    # 1 HIGH in Browser Security (weight 15%):
    # SEVERITY_DEDUCTIONS[HIGH] = 20
    # Confirmed: 20 * 1.0 = 20 deduction -> category score 80
    card_confirmed = calculate_score_card([
        make_finding(Category.BROWSER_SECURITY, Severity.HIGH, Confidence.CONFIRMED, rule_id="CSP_1")
    ])
    assert card_confirmed.category_scores["Browser Security"].score == 80

    # Likely: 20 * 0.75 = 15 deduction -> category score 85
    card_likely = calculate_score_card([
        make_finding(Category.BROWSER_SECURITY, Severity.HIGH, Confidence.LIKELY, rule_id="CSP_2")
    ])
    assert card_likely.category_scores["Browser Security"].score == 85

    # Potential: round(20 * 0.35) = 7 deduction -> category score 93
    card_potential = calculate_score_card([
        make_finding(Category.BROWSER_SECURITY, Severity.HIGH, Confidence.POTENTIAL, rule_id="CSP_3")
    ])
    assert card_potential.category_scores["Browser Security"].score == 93

    # Informational: 20 * 0.0 = 0 deduction -> category score 100
    card_info = calculate_score_card([
        make_finding(Category.BROWSER_SECURITY, Severity.HIGH, Confidence.INFORMATIONAL, rule_id="CSP_4")
    ])
    assert card_info.category_scores["Browser Security"].score == 100
    assert card_info.overall_score == 100


def test_zero_deduction_for_info_severity():
    findings = [
        make_finding(Category.TRANSPORT_SECURITY, Severity.INFO, Confidence.CONFIRMED, ObservationStatus.OBSERVED, "TLS_13"),
        make_finding(Category.BROWSER_SECURITY, Severity.INFO, Confidence.CONFIRMED, ObservationStatus.OBSERVED, "HSTS_OK"),
        make_finding(Category.ATTACK_SURFACE, Severity.INFO, Confidence.INFORMATIONAL, ObservationStatus.OBSERVED, "INVENTORY"),
    ]
    card = calculate_score_card(findings)
    assert card.overall_score == 100
    assert card.letter_grade == "A+"
    assert card.confirmed_flaws_count == 0
    assert card.observed_properties_count == 3


def test_score_clamping_prevents_negative_values():
    # 5 CRITICAL findings in one category (5 * 35 = 175 pts deduction)
    # Must clamp at 0, not go negative
    findings = [
        make_finding(Category.TRANSPORT_SECURITY, Severity.CRITICAL, Confidence.CONFIRMED, rule_id=f"CRIT_{i}")
        for i in range(5)
    ]
    card = calculate_score_card(findings)
    assert card.category_scores["Transport Security"].score == 0

    # Overall score: 0 * 0.15 + 100 * 0.85 = 85
    assert card.overall_score == 85
    assert card.letter_grade == "B"
