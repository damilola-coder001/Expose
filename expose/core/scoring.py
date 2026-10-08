"""Deterministic security scoring engine and assessment boundary declarations for Expose.

Translates verified empirical findings into a PageSpeed-style 0-100 Security Score.
"""

from typing import Dict, List, Optional, Tuple
from expose.core.models import (
    Category,
    CategoryScore,
    Confidence,
    Finding,
    HeaderTestResult,
    NotAssessedArea,
    ObservationStatus,
    ScoreCard,
    Severity,
)

SCORE_VERSION = "1.0"

# Standard penalty deductions per confirmed issue severity
SEVERITY_DEDUCTIONS = {
    Severity.CRITICAL: 35,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

CONFIDENCE_MULTIPLIERS = {
    Confidence.CONFIRMED: 1.0,
    Confidence.LIKELY: 0.75,
    Confidence.POTENTIAL: 0.35,
    Confidence.INFORMATIONAL: 0.0,
}

# The 9 canonical Phase 9 scoring categories (weights sum to 100%)
CATEGORY_MAPPING = {
    "Transport Security": {
        "categories": {Category.TRANSPORT_SECURITY, Category.CRYPTOGRAPHY},
        "weight": 15,
    },
    "Browser Security": {
        "categories": {Category.BROWSER_SECURITY, Category.HTTP_HEADERS},
        "weight": 15,
    },
    "Cookie & Session Security": {
        "categories": {Category.COOKIE_SESSION_SECURITY, Category.COOKIE_SECURITY},
        "weight": 10,
    },
    "Configuration": {
        "categories": {
            Category.CONFIGURATION,
            Category.SECURITY_METADATA,
            Category.DNS_CONFIGURATION,
            Category.EMAIL_SECURITY,
            Category.NETWORK_POSTURE,
        },
        "weight": 10,
    },
    "Attack Surface": {
        "categories": {Category.ATTACK_SURFACE, Category.CLIENT_SIDE_SECURITY},
        "weight": 10,
    },
    "Information Exposure": {
        "categories": {Category.INFORMATION_EXPOSURE, Category.INFORMATION_DISCLOSURE},
        "weight": 10,
    },
    "API Security": {
        "categories": {Category.API_SECURITY},
        "weight": 10,
    },
    "Third-Party Resources": {
        "categories": {Category.THIRD_PARTY_RESOURCES, Category.EXTERNAL_EXPOSURE},
        "weight": 10,
    },
    "Authentication": {
        "categories": {Category.AUTHENTICATION},
        "weight": 10,
    },
}

DEFAULT_NOT_ASSESSED_AREAS: List[NotAssessedArea] = [
    NotAssessedArea(
        area="Authentication & Session Management",
        reason="Requires authenticated credentials, user accounts, and active session tokens.",
        explanation=(
            "External unauthenticated scanning cannot evaluate password complexity enforcement, "
            "credential stuffing defenses, MFA workflows, or session hijacking vulnerabilities."
        )
    ),
    NotAssessedArea(
        area="Business Logic & Workflow Integrity",
        reason="Requires context on business workflows, transaction logic, and multi-tenant authorization matrices.",
        explanation=(
            "Logic flaws such as Insecure Direct Object References (IDOR), price manipulation, and race conditions "
            "cannot be observed from passive external surface analysis."
        )
    ),
    NotAssessedArea(
        area="Active Code Injection (SQLi, RCE, Command Injection)",
        reason="Invasive attack payloads are strictly prohibited in safe external intelligence assessments.",
        explanation=(
            "Expose operates safely without sending destructive or intrusive payloads. Active exploit testing "
            "requires explicit authorization and dedicated penetration testing engagements."
        )
    ),
    NotAssessedArea(
        area="Internal Infrastructure & Private VPC",
        reason="Protected behind edge firewalls, NAT gateways, and private network segmentation.",
        explanation=(
            "Internal microservices, private databases, and cloud metadata services cannot be directly observed "
            "from the public internet."
        )
    ),
    NotAssessedArea(
        area="Source Code & Repository Dependencies",
        reason="Requires direct access to source code repositories, lockfiles, and CI/CD pipelines.",
        explanation=(
            "Public web endpoints only expose runtime responses, not underlying repository source code or build artifacts."
        )
    ),
]


def calculate_letter_grade(score: int) -> str:
    """Calculates letter grade corresponding to numerical score."""
    if score >= 95:
        return "A+"
    elif score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"


def calculate_score_card(findings: List[Finding], header_matrix: Optional[List[HeaderTestResult]] = None) -> ScoreCard:
    """Computes transparent, deterministic Mozilla Observatory-calibrated security scorecard.
    
    Baseline 100 points with direct modifier deductions/bonuses from the HTTP Header Test Matrix,
    plus confirmed vulnerability deductions across all probe categories.
    """
    confirmed_findings = [
        f for f in findings 
        if f.status == ObservationStatus.CONFIRMED and f.confidence == Confidence.CONFIRMED and f.severity != Severity.INFO
    ]
    observed_findings = [f for f in findings if f not in confirmed_findings]

    category_scores: Dict[str, CategoryScore] = {}

    # 1. Evaluate Header Test Matrix modifiers if provided
    matrix_modifiers = 0
    if header_matrix:
        for test in header_matrix:
            matrix_modifiers += test.score_modifier

    # 2. Compute category scores
    for group_name, group_cfg in CATEGORY_MAPPING.items():
        matched_cats = group_cfg["categories"]
        weight = group_cfg["weight"]

        group_confirmed = [
            f for f in confirmed_findings
            if f.category in matched_cats
        ]

        group_findings_for_deduction = [
            f for f in findings
            if f.category in matched_cats and f.severity != Severity.INFO and f.status == ObservationStatus.CONFIRMED
        ]
        
        # Calculate standard deduction for non-header findings or blended
        deduction = sum(
            int(round(SEVERITY_DEDUCTIONS.get(f.severity, 0) * CONFIDENCE_MULTIPLIERS.get(f.confidence, 0.5)))
            for f in group_findings_for_deduction
        )
        
        # If Browser Security or Transport Security and matrix is present, incorporate test modifiers
        if header_matrix and group_name == "Browser Security":
            browser_test_deductions = abs(sum(t.score_modifier for t in header_matrix if t.score_modifier < 0 and t.id in ("content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy")))
            deduction = max(deduction, browser_test_deductions)
        elif header_matrix and group_name == "Transport Security":
            transport_test_deductions = abs(sum(t.score_modifier for t in header_matrix if t.score_modifier < 0 and t.id in ("strict-transport-security", "redirection")))
            deduction = max(deduction, transport_test_deductions)

        raw_score = max(0, 100 - deduction)

        all_group_findings = [f for f in findings if f.category in matched_cats]

        category_scores[group_name] = CategoryScore(
            category_name=group_name,
            score=int(round(raw_score)),
            weight_percentage=weight,
            findings_count=len(all_group_findings),
            confirmed_issues_count=len(group_confirmed),
        )

    # 3. Compute overall posture score as deterministic weighted sum across all 9 canonical categories
    total_weighted_score = sum(cs.score * (cs.weight_percentage / 100.0) for cs in category_scores.values())
    final_score = int(round(max(0, min(100, total_weighted_score))))

    letter_grade = calculate_letter_grade(final_score)

    return ScoreCard(
        score_version=SCORE_VERSION,
        overall_score=final_score,
        letter_grade=letter_grade,
        category_scores=category_scores,
        confirmed_flaws_count=len(confirmed_findings),
        observed_properties_count=len(observed_findings),
        not_assessed_boundaries=DEFAULT_NOT_ASSESSED_AREAS,
        header_test_matrix=header_matrix or [],
    )
