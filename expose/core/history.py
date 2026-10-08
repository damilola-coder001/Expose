"""Target security history tracking and continuous monitoring security diff engine (Phase 16).

Maintains a timeline of scans for targets and computes exact security diffs:
- NEW (+): Newly discovered findings or exposed endpoints
- FIXED (✓): Previously confirmed weaknesses that have been remediated
- CHANGED (~): Findings with modified attributes or changed severity
- UNCHANGED: Persisting findings across scans
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from expose.core.models import Finding, ObservationStatus, ScanResult, Severity


class FindingDiffType(str, Enum):
    NEW = "NEW"              # + Newly discovered flaw/exposure
    FIXED = "FIXED"          # ✓ Weakness resolved/remediated
    CHANGED = "CHANGED"      # ~ Weakness modified (e.g. severity changed)
    UNCHANGED = "UNCHANGED"  # Persisting unchanged


class FindingDiffItem(BaseModel):
    """Represents a single finding difference between two scans."""
    finding_id: str
    rule_id: Optional[str] = None
    title: str
    category: str
    diff_type: FindingDiffType
    severity_current: Optional[Severity] = None
    severity_previous: Optional[Severity] = None
    detail: str


class ScanHistoryItem(BaseModel):
    """Summarized historical snapshot of a target scan."""
    scan_id: str
    target: str
    timestamp: datetime
    score: int
    letter_grade: str
    confirmed_flaws_count: int
    duration_seconds: Optional[float] = None


class SecurityDiff(BaseModel):
    """Full security diff between two chronological scans of a target."""
    target: str
    current_scan_id: str
    previous_scan_id: Optional[str] = None
    score_current: int
    score_previous: Optional[int] = None
    score_delta: int
    new_findings: List[FindingDiffItem] = Field(default_factory=list, description="New findings (+)")
    fixed_findings: List[FindingDiffItem] = Field(default_factory=list, description="Remediated findings (✓)")
    changed_findings: List[FindingDiffItem] = Field(default_factory=list, description="Modified findings (~)")
    unchanged_findings: List[FindingDiffItem] = Field(default_factory=list, description="Unchanged findings")
    summary: str


def _finding_fingerprint(f: Finding) -> str:
    """Generates a stable fingerprint to correlate findings across scans."""
    if f.rule_id:
        return f"rule:{f.rule_id}"
    return f"cat:{f.category.value}:title:{f.title.lower().strip()}"


class TargetHistoryStore:
    """Stores scan history indexed by normalized target domain and computes security diffs."""

    def __init__(self):
        # target_host -> list of ScanResult sorted chronologically
        self._store: Dict[str, List[ScanResult]] = {}

    def normalize_host(self, host: str) -> str:
        return host.strip().lower().split(":")[0]

    def record_scan(self, scan: ScanResult) -> None:
        """Appends a completed scan to the target's historical timeline."""
        host = self.normalize_host(scan.target.host)
        if host not in self._store:
            self._store[host] = []
        
        # Avoid duplicate scan_id appends
        existing_idx = next((i for i, s in enumerate(self._store[host]) if s.scan_id == scan.scan_id), None)
        if existing_idx is not None:
            self._store[host][existing_idx] = scan
        else:
            self._store[host].append(scan)
            self._store[host].sort(key=lambda s: s.start_time)

    def get_history(self, target_host: str) -> List[ScanHistoryItem]:
        """Returns the chronological history snapshots for a target."""
        host = self.normalize_host(target_host)
        scans = self._store.get(host, [])
        items = []
        for s in scans:
            score = s.score_card.overall_score if s.score_card else 0
            grade = s.score_card.letter_grade if s.score_card else "F"
            flaws = sum(1 for f in s.findings if f.status == ObservationStatus.CONFIRMED and f.severity != Severity.INFO)
            items.append(
                ScanHistoryItem(
                    scan_id=s.scan_id,
                    target=s.target.host,
                    timestamp=s.start_time,
                    score=score,
                    letter_grade=grade,
                    confirmed_flaws_count=flaws,
                    duration_seconds=s.duration_seconds,
                )
            )
        return items

    def get_previous_scan(self, current_scan: ScanResult) -> Optional[ScanResult]:
        """Finds the immediately preceding scan for the same target."""
        host = self.normalize_host(current_scan.target.host)
        scans = self._store.get(host, [])
        prev: Optional[ScanResult] = None
        for s in scans:
            if s.scan_id == current_scan.scan_id:
                break
            prev = s
        return prev

    def get_latest_scan(self, target_host: str) -> Optional[ScanResult]:
        """Returns the most recent ScanResult for the given target host."""
        host = self.normalize_host(target_host)
        scans = self._store.get(host, [])
        return scans[-1] if scans else None

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        """Finds a ScanResult by scan_id across all recorded targets."""
        for scans in self._store.values():
            for s in scans:
                if s.scan_id == scan_id:
                    return s
        return None

    def compute_diff(
        self,
        current_scan: ScanResult,
        previous_scan: Optional[ScanResult] = None,
    ) -> SecurityDiff:
        """Computes security diff between current scan and previous scan."""
        if previous_scan is None:
            previous_scan = self.get_previous_scan(current_scan)

        score_curr = current_scan.score_card.overall_score if current_scan.score_card else 0
        score_prev = previous_scan.score_card.overall_score if previous_scan and previous_scan.score_card else None
        score_delta = (score_curr - score_prev) if score_prev is not None else 0

        if not previous_scan:
            # Baseline initial scan: all confirmed flaws are NEW
            new_items = []
            for f in current_scan.findings:
                if f.status == ObservationStatus.CONFIRMED and f.severity != Severity.INFO:
                    new_items.append(
                        FindingDiffItem(
                            finding_id=f.id,
                            rule_id=f.rule_id,
                            title=f.title,
                            category=f.category.value,
                            diff_type=FindingDiffType.NEW,
                            severity_current=f.severity,
                            severity_previous=None,
                            detail=f"Discovered in baseline scan: {f.title}",
                        )
                    )
            return SecurityDiff(
                target=current_scan.target.host,
                current_scan_id=current_scan.scan_id,
                previous_scan_id=None,
                score_current=score_curr,
                score_previous=None,
                score_delta=0,
                new_findings=new_items,
                fixed_findings=[],
                changed_findings=[],
                unchanged_findings=[],
                summary=f"Initial baseline scan for {current_scan.target.host}. Score: {score_curr}/100.",
            )

        # Index findings by fingerprint
        curr_map = {_finding_fingerprint(f): f for f in current_scan.findings}
        prev_map = {_finding_fingerprint(f): f for f in previous_scan.findings}

        new_findings: List[FindingDiffItem] = []
        fixed_findings: List[FindingDiffItem] = []
        changed_findings: List[FindingDiffItem] = []
        unchanged_findings: List[FindingDiffItem] = []

        all_keys = set(curr_map.keys()).union(set(prev_map.keys()))

        for key in sorted(all_keys):
            f_curr = curr_map.get(key)
            f_prev = prev_map.get(key)

            if f_curr and not f_prev:
                # Exists in current but not previous
                if f_curr.status == ObservationStatus.CONFIRMED and f_curr.severity != Severity.INFO:
                    new_findings.append(
                        FindingDiffItem(
                            finding_id=f_curr.id,
                            rule_id=f_curr.rule_id,
                            title=f_curr.title,
                            category=f_curr.category.value,
                            diff_type=FindingDiffType.NEW,
                            severity_current=f_curr.severity,
                            severity_previous=None,
                            detail=f"+ New issue detected: {f_curr.title}",
                        )
                    )
            elif f_prev and not f_curr:
                # Existed in previous but no longer present
                if f_prev.status == ObservationStatus.CONFIRMED and f_prev.severity != Severity.INFO:
                    fixed_findings.append(
                        FindingDiffItem(
                            finding_id=f_prev.id,
                            rule_id=f_prev.rule_id,
                            title=f_prev.title,
                            category=f_prev.category.value,
                            diff_type=FindingDiffType.FIXED,
                            severity_current=None,
                            severity_previous=f_prev.severity,
                            detail=f"✓ Remediated: {f_prev.title}",
                        )
                    )
            elif f_curr and f_prev:
                # Exists in both
                is_curr_confirmed = (f_curr.status == ObservationStatus.CONFIRMED and f_curr.severity != Severity.INFO)
                is_prev_confirmed = (f_prev.status == ObservationStatus.CONFIRMED and f_prev.severity != Severity.INFO)

                if is_prev_confirmed and not is_curr_confirmed:
                    # Status transitioned to FIXED or OBSERVED
                    fixed_findings.append(
                        FindingDiffItem(
                            finding_id=f_curr.id,
                            rule_id=f_curr.rule_id,
                            title=f_curr.title,
                            category=f_curr.category.value,
                            diff_type=FindingDiffType.FIXED,
                            severity_current=f_curr.severity,
                            severity_previous=f_prev.severity,
                            detail=f"✓ Remediated: {f_curr.title}",
                        )
                    )
                elif not is_prev_confirmed and is_curr_confirmed:
                    # Re-opened or new flaw
                    new_findings.append(
                        FindingDiffItem(
                            finding_id=f_curr.id,
                            rule_id=f_curr.rule_id,
                            title=f_curr.title,
                            category=f_curr.category.value,
                            diff_type=FindingDiffType.NEW,
                            severity_current=f_curr.severity,
                            severity_previous=f_prev.severity,
                            detail=f"+ Re-emerged or new flaw: {f_curr.title}",
                        )
                    )
                elif is_curr_confirmed and is_prev_confirmed:
                    if f_curr.severity != f_prev.severity:
                        changed_findings.append(
                            FindingDiffItem(
                                finding_id=f_curr.id,
                                rule_id=f_curr.rule_id,
                                title=f_curr.title,
                                category=f_curr.category.value,
                                diff_type=FindingDiffType.CHANGED,
                                severity_current=f_curr.severity,
                                severity_previous=f_prev.severity,
                                detail=f"~ Severity changed from {f_prev.severity.value} to {f_curr.severity.value}",
                            )
                        )
                    elif f_curr.description != f_prev.description or f_curr.evidence.summary != f_prev.evidence.summary:
                        changed_findings.append(
                            FindingDiffItem(
                                finding_id=f_curr.id,
                                rule_id=f_curr.rule_id,
                                title=f_curr.title,
                                category=f_curr.category.value,
                                diff_type=FindingDiffType.CHANGED,
                                severity_current=f_curr.severity,
                                severity_previous=f_prev.severity,
                                detail=f"~ Finding evidence or details updated",
                            )
                        )
                    else:
                        unchanged_findings.append(
                            FindingDiffItem(
                                finding_id=f_curr.id,
                                rule_id=f_curr.rule_id,
                                title=f_curr.title,
                                category=f_curr.category.value,
                                diff_type=FindingDiffType.UNCHANGED,
                                severity_current=f_curr.severity,
                                severity_previous=f_prev.severity,
                                detail="Unchanged",
                            )
                        )

        summary_parts = []
        if score_delta > 0:
            summary_parts.append(f"Score improved by +{score_delta} points ({score_prev} → {score_curr})")
        elif score_delta < 0:
            summary_parts.append(f"Score dropped by {score_delta} points ({score_prev} → {score_curr})")
        else:
            summary_parts.append(f"Score unchanged at {score_curr}")

        summary_parts.append(f"{len(new_findings)} new, {len(fixed_findings)} fixed, {len(changed_findings)} changed.")
        summary_text = ". ".join(summary_parts)

        return SecurityDiff(
            target=current_scan.target.host,
            current_scan_id=current_scan.scan_id,
            previous_scan_id=previous_scan.scan_id,
            score_current=score_curr,
            score_previous=score_prev,
            score_delta=score_delta,
            new_findings=new_findings,
            fixed_findings=fixed_findings,
            changed_findings=changed_findings,
            unchanged_findings=unchanged_findings,
            summary=summary_text,
        )


# Global singleton instance
_GLOBAL_HISTORY_STORE = TargetHistoryStore()


def get_history_store() -> TargetHistoryStore:
    return _GLOBAL_HISTORY_STORE
