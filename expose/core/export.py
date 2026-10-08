"""Report export utilities for Expose (Phases 25 & 26).

Supports:
- Sanitized shareable JSON export with zero backend secret leakage (Phase 25)
- OASIS SARIF v2.1.0 export for CI/CD, GitHub Code Scanning, GitLab CI (Phase 26)
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import json

from expose import __version__
from expose.core.models import Finding, ObservationStatus, ScanResult, Severity

SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def generate_sanitized_json_report(scan: ScanResult) -> Dict[str, Any]:
    """Generates a shareable, sanitized JSON security report (Phase 25).
    
    Guarantees:
    - Zero backend secrets (database, redis, api keys, aws secrets) are included
    - Full technical transparency with verified evidence
    - Includes deterministic scorecard, category breakdowns, and AI reasoning
    """
    confirmed = [f for f in scan.findings if f.status == ObservationStatus.CONFIRMED]
    remediated = [f for f in scan.findings if f.status == ObservationStatus.REMEDIATED]

    findings_data = []
    for f in confirmed:
        finding_dict = {
            "id": f.id,
            "probe": f.probe,
            "title": f.title,
            "severity": f.severity.value,
            "category": f.category.value,
            "confidence": f.confidence.value,
            "status": f.status.value,
            "description": f.description,
            "remediation": f.remediation,
            "evidence": f.evidence.model_dump(mode="json") if hasattr(f.evidence, "model_dump") else dict(f.evidence),
            "standards": {
                "owasp_top_10": f.owasp_top10,
                "owasp_asvs": f.owasp_asvs,
                "cwe": f.cwe_id,
                "cve": f.cve_id,
            },
        }
        if f.ai_intelligence:
            finding_dict["ai_intelligence"] = (
                f.ai_intelligence.model_dump(mode="json")
                if hasattr(f.ai_intelligence, "model_dump")
                else f.ai_intelligence
            )
        findings_data.append(finding_dict)

    remediated_data = []
    for f in remediated:
        remediated_data.append({
            "id": f.id,
            "title": f.title,
            "category": f.category.value,
            "status": f.status.value,
        })

    crit_count = sum(1 for f in confirmed if f.severity == Severity.CRITICAL)
    high_count = sum(1 for f in confirmed if f.severity == Severity.HIGH)
    med_count = sum(1 for f in confirmed if f.severity == Severity.MEDIUM)
    low_count = sum(1 for f in confirmed if f.severity == Severity.LOW)

    target_url = getattr(scan.target, "normalized_url", None) or f"https://{scan.target.host}/"
    primary_ip = scan.target.resolved_ips[0] if getattr(scan.target, "resolved_ips", None) else None

    return {
        "expose_version": __version__,
        "report_type": "security_intelligence_report",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_metadata": {
            "scan_id": scan.scan_id,
            "target": {
                "host": scan.target.host,
                "url": target_url,
                "ip": primary_ip,
                "scheme": scan.target.scheme,
                "port": scan.target.port,
                "domain_verified": getattr(scan, "domain_verified", False),
                "domain_ownership_proof": getattr(scan, "domain_ownership_proof", None),
            },
            "started_at": scan.start_time.isoformat() if scan.start_time else None,
            "completed_at": scan.end_time.isoformat() if scan.end_time else None,
            "duration_seconds": scan.duration_seconds,
        },
        "score_card": scan.score_card.model_dump(mode="json"),
        "summary": {
            "total_findings": len(confirmed),
            "critical": crit_count,
            "high": high_count,
            "medium": med_count,
            "low": low_count,
            "remediated": len(remediated),
            "overall_score": scan.score_card.overall_score,
            "score_display": f"{scan.score_card.overall_score} / 100",
            "score_philosophy": scan.score_card.score_philosophy,
            "grade": getattr(scan.score_card, "letter_grade", "N/A"),
        },
        "findings": findings_data,
        "remediated_findings": remediated_data,
        "attack_surface_summary": {
            "pages_count": len(scan.attack_surface.pages) if scan.attack_surface else 0,
            "apis_count": len(scan.attack_surface.apis) if scan.attack_surface else 0,
            "scripts_count": len(scan.attack_surface.scripts) if scan.attack_surface else 0,
            # AttackSurface currently inventories pages, APIs, assets, scripts, forms,
            # and dependencies. Older scan records may additionally include a
            # technologies field, so preserve it when present without making JSON
            # export depend on a non-existent model attribute.
            "technologies": [
                t.model_dump(mode="json") if hasattr(t, "model_dump") else t
                for t in getattr(scan.attack_surface, "technologies", [])
            ] if scan.attack_surface else [],
        },
        "ai_prioritization": (
            scan.ai_prioritization.model_dump(mode="json")
            if hasattr(scan.ai_prioritization, "model_dump")
            else scan.ai_prioritization
        ),
    }


def generate_sarif_report(scan: ScanResult) -> Dict[str, Any]:
    """Generates an OASIS SARIF v2.1.0 compliant security report (Phase 26).
    
    Compatible with:
    - GitHub Code Scanning (actions/upload-sarif)
    - GitLab CI SAST / DAST reports
    - SonarQube, DefectDojo, and Azure DevOps
    """
    confirmed = [f for f in scan.findings if f.status == ObservationStatus.CONFIRMED]

    rules_map: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []

    target_uri = getattr(scan.target, "normalized_url", None) or f"https://{scan.target.host}/"

    for f in confirmed:
        # Build SARIF Rule
        if f.id not in rules_map:
            rule_tags = [f.category.value, f"severity:{f.severity.value}"]
            if f.owasp_top10:
                rule_tags.append(f"owasp:{f.owasp_top10}")
            if f.cwe_id:
                rule_tags.append(f"cwe:{f.cwe_id}")

            rule_entry = {
                "id": f.id,
                "name": f.title.replace(" ", "_").replace(":", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description or f.title},
                "properties": {
                    "tags": rule_tags,
                    "precision": "high" if f.confidence.value == "CONFIRMED" else "medium",
                    "security-severity": "9.0" if f.severity == Severity.CRITICAL else (
                        "7.5" if f.severity == Severity.HIGH else (
                            "5.0" if f.severity == Severity.MEDIUM else "2.5"
                        )
                    ),
                }
            }
            if f.remediation:
                rule_entry["help"] = {
                    "text": f"Remediation:\n{f.remediation}",
                    "markdown": f"### Remediation\n{f.remediation}",
                }
            rules_map[f.id] = rule_entry

        # Build SARIF Result
        sarif_level = SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning")
        result_entry = {
            "ruleId": f.id,
            "level": sarif_level,
            "message": {
                "text": f"[{f.severity.value.upper()}] {f.title}: {f.description or f.title}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": target_uri,
                        },
                        "region": {
                            "startLine": 1,
                        }
                    }
                }
            ],
            "properties": {
                "category": f.category.value,
                "confidence": f.confidence.value,
                "evidence": f.evidence.model_dump(mode="json") if hasattr(f.evidence, "model_dump") else dict(f.evidence),
            }
        }
        sarif_results.append(result_entry)

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Expose",
                        "fullName": "Expose Security Intelligence Platform",
                        "semanticVersion": __version__,
                        "informationUri": "https://github.com/expose/expose",
                        "rules": list(rules_map.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": scan.start_time.isoformat() if scan.start_time else None,
                        "endTimeUtc": scan.end_time.isoformat() if scan.end_time else None,
                    }
                ],
                "results": sarif_results,
            }
        ]
    }


def generate_executive_html_report(scan: ScanResult) -> str:
    """Generates a standalone, self-contained executive HTML report (Phase 29).
    
    Zero external network dependencies (no remote CDNs, scripts, or fonts required).
    Print-optimized for direct PDF conversion or executive distribution.
    """
    import html

    score = scan.score_card.overall_score if scan.score_card else 0
    grade = scan.score_card.letter_grade if scan.score_card else "N/A"
    flaws = scan.score_card.confirmed_flaws_count if scan.score_card else 0
    controls = scan.score_card.observed_properties_count if scan.score_card else 0

    score_color = "#10b981" if score >= 90 else "#06b6d4" if score >= 75 else "#f59e0b" if score >= 60 else "#ef4444"
    score_bg = "rgba(16, 185, 129, 0.1)" if score >= 90 else "rgba(6, 182, 212, 0.1)" if score >= 75 else "rgba(245, 158, 11, 0.1)" if score >= 60 else "rgba(239, 68, 68, 0.1)"

    host = html.escape(scan.target.host if scan.target else "Unknown")
    url = html.escape(scan.target.normalized_url if scan.target else "")
    scan_id = html.escape(scan.scan_id or "")
    duration = f"{scan.duration_seconds:.2f}s" if scan.duration_seconds is not None else "N/A"
    timestamp = scan.start_time.strftime("%Y-%m-%d %H:%M:%S UTC") if scan.start_time else "N/A"
    ips = html.escape(", ".join(scan.target.resolved_ips)) if (scan.target and scan.target.resolved_ips) else "N/A"

    is_verified = getattr(scan, "domain_verified", False)
    proof = html.escape(getattr(scan, "domain_ownership_proof", "") or "")

    verified_badge = (
        f'<span class="badge badge-verified">✓ VERIFIED DOMAIN OWNER</span>'
        if is_verified
        else '<span class="badge badge-passive">PASSIVE EXTERNAL AUDIT</span>'
    )

    # Categories rows
    category_rows = []
    if scan.score_card and scan.score_card.category_scores:
        for cat_name, cat_data in scan.score_card.category_scores.items():
            cat_score = cat_data.score
            cat_color = "#10b981" if cat_score >= 90 else "#06b6d4" if cat_score >= 75 else "#f59e0b" if cat_score >= 60 else "#ef4444"
            category_rows.append(f"""
            <tr>
              <td><strong>{html.escape(cat_name)}</strong></td>
              <td><span style="color: {cat_color}; font-weight: bold;">{cat_score} / 100</span></td>
              <td>{cat_data.weight_percentage}%</td>
              <td>{cat_data.confirmed_issues_count}</td>
            </tr>
            """)

    categories_html = "".join(category_rows)

    # Findings blocks
    confirmed_findings = [f for f in scan.findings if f.status == ObservationStatus.CONFIRMED]
    findings_blocks = []

    sev_colors = {
        Severity.CRITICAL: ("#ef4444", "rgba(239, 68, 68, 0.15)"),
        Severity.HIGH: ("#f97316", "rgba(249, 115, 22, 0.15)"),
        Severity.MEDIUM: ("#f59e0b", "rgba(245, 158, 11, 0.15)"),
        Severity.LOW: ("#3b82f6", "rgba(59, 130, 246, 0.15)"),
        Severity.INFO: ("#64748b", "rgba(100, 116, 139, 0.15)"),
    }

    for f in confirmed_findings:
        sev_color, sev_bg = sev_colors.get(f.severity, ("#64748b", "rgba(100, 116, 139, 0.15)"))
        standards = []
        if f.owasp_top10:
            standards.append(f'<span class="std-pill">OWASP: {html.escape(f.owasp_top10)}</span>')
        if f.owasp_asvs:
            standards.append(f'<span class="std-pill">ASVS: {html.escape(f.owasp_asvs)}</span>')
        if f.cwe_id:
            standards.append(f'<span class="std-pill">{html.escape(f.cwe_id)}</span>')

        evidence_str = ""
        if f.evidence:
            if hasattr(f.evidence, "model_dump_json"):
                raw_ev = f.evidence.model_dump_json(indent=2)
            else:
                raw_ev = str(f.evidence)
            evidence_str = f'<div class="evidence-box"><div class="evidence-label">Verifiable Wire Evidence:</div><pre><code>{html.escape(raw_ev)}</code></pre></div>'

        remediation_str = ""
        if f.remediation:
            remediation_str = f'<div class="remediation-box"><div class="remediation-label">Remediation Recommendation:</div><p>{html.escape(f.remediation)}</p></div>'

        findings_blocks.append(f"""
        <div class="finding-card">
          <div class="finding-header">
            <span class="sev-badge" style="color: {sev_color}; background: {sev_bg}; border-color: {sev_color};">{f.severity.value}</span>
            <span class="finding-title">{html.escape(f.title)}</span>
            <span class="finding-category">{html.escape(f.category.value)}</span>
          </div>
          <div class="standards-row">
            {" ".join(standards)}
          </div>
          <p class="finding-desc">{html.escape(f.description)}</p>
          {evidence_str}
          {remediation_str}
        </div>
        """)

    findings_html = "".join(findings_blocks) if findings_blocks else '<p class="clean-posture">✓ No confirmed security flaws were observed on the wire.</p>'

    summary_text = html.escape(
        scan.risk_assessment.posture_summary
        if scan.risk_assessment
        else f"Security posture scored at {score}/100 with {flaws} confirmed findings."
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Intelligence Report — {host}</title>
  <style>
    :root {{
      --bg: #090b0e;
      --card-bg: #0d1117;
      --border: #202735;
      --text: #e2e8f0;
      --text-muted: #94a3b8;
      --accent: #06b6d4;
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    }}
    @media (prefers-color-scheme: light) {{
      :root {{
        --bg: #f8fafc;
        --card-bg: #ffffff;
        --border: #e2e8f0;
        --text: #0f172a;
        --text-muted: #64748b;
      }}
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: var(--font-sans);
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 2rem 1rem;
    }}
    .container {{
      max-width: 960px;
      margin: 0 auto;
    }}
    header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 2px solid var(--border);
      padding-bottom: 1.25rem;
      margin-bottom: 1.75rem;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }}
    .logo {{
      background: #10b981;
      color: #090b0e;
      font-family: var(--font-mono);
      font-weight: 800;
      font-size: 1.1rem;
      padding: 0.25rem 0.6rem;
      border-radius: 4px;
    }}
    .brand-title {{
      font-family: var(--font-mono);
      font-weight: 700;
      font-size: 1.15rem;
      letter-spacing: 0.05em;
    }}
    .brand-tag {{
      font-size: 0.75rem;
      color: var(--text-muted);
      font-family: var(--font-mono);
    }}
    .meta-bar {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem 1.25rem;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
      font-size: 0.85rem;
    }}
    .meta-item label {{
      display: block;
      color: var(--text-muted);
      font-size: 0.75rem;
      font-family: var(--font-mono);
      text-transform: uppercase;
      margin-bottom: 0.2rem;
    }}
    .meta-item value {{
      font-family: var(--font-mono);
      font-weight: 600;
      word-break: break-all;
    }}
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      font-weight: 700;
    }}
    .badge-verified {{
      background: rgba(16, 185, 129, 0.15);
      color: #10b981;
      border: 1px solid rgba(16, 185, 129, 0.3);
    }}
    .badge-passive {{
      background: rgba(6, 182, 212, 0.15);
      color: #06b6d4;
      border: 1px solid rgba(6, 182, 212, 0.3);
    }}
    .hero-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.5rem;
      display: grid;
      grid-template-columns: 140px 1fr;
      gap: 1.5rem;
      align-items: center;
      margin-bottom: 2rem;
    }}
    @media (max-width: 640px) {{
      .hero-card {{ grid-template-columns: 1fr; }}
    }}
    .score-gauge {{
      width: 140px;
      height: 140px;
      border-radius: 8px;
      border: 2px solid {score_color};
      background: {score_bg};
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      font-family: var(--font-mono);
    }}
    .score-val {{
      font-size: 2.75rem;
      font-weight: 800;
      color: {score_color};
      line-height: 1;
    }}
    .score-max {{
      font-size: 0.8rem;
      color: var(--text-muted);
      margin-top: 0.2rem;
    }}
    .hero-info h2 {{
      font-size: 1.1rem;
      font-family: var(--font-mono);
      margin-bottom: 0.5rem;
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }}
    .grade-pill {{
      background: var(--bg);
      border: 1px solid var(--border);
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      font-size: 0.8rem;
      color: var(--text);
    }}
    .summary-text {{
      font-size: 0.9rem;
      color: var(--text-muted);
      line-height: 1.6;
    }}
    .stats-row {{
      display: flex;
      gap: 1.5rem;
      margin-top: 0.75rem;
      font-family: var(--font-mono);
      font-size: 0.8rem;
    }}
    .section-title {{
      font-family: var(--font-mono);
      font-size: 1rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin: 2rem 0 1rem 0;
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.4rem;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      font-size: 0.85rem;
      margin-bottom: 2rem;
    }}
    th, td {{
      padding: 0.75rem 1rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }}
    th {{
      font-family: var(--font-mono);
      text-transform: uppercase;
      font-size: 0.75rem;
      color: var(--text-muted);
      background: var(--bg);
    }}
    .finding-card {{
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1.25rem;
      margin-bottom: 1rem;
    }}
    .finding-header {{
      display: flex;
      align-items: center;
      gap: 0.75rem;
      margin-bottom: 0.5rem;
      flex-wrap: wrap;
    }}
    .sev-badge {{
      font-family: var(--font-mono);
      font-size: 0.7rem;
      font-weight: 800;
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
      border: 1px solid;
    }}
    .finding-title {{
      font-weight: 700;
      font-size: 0.95rem;
    }}
    .finding-category {{
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: var(--text-muted);
      margin-left: auto;
    }}
    .standards-row {{
      display: flex;
      gap: 0.4rem;
      flex-wrap: wrap;
      margin-bottom: 0.6rem;
    }}
    .std-pill {{
      font-family: var(--font-mono);
      font-size: 0.7rem;
      background: var(--bg);
      border: 1px solid var(--border);
      padding: 0.1rem 0.4rem;
      border-radius: 3px;
      color: var(--text-muted);
    }}
    .finding-desc {{
      font-size: 0.85rem;
      color: var(--text-muted);
      margin-bottom: 0.75rem;
      line-height: 1.5;
    }}
    .evidence-box, .remediation-box {{
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.75rem;
      margin-top: 0.5rem;
      font-size: 0.8rem;
    }}
    .evidence-label, .remediation-label {{
      font-family: var(--font-mono);
      font-size: 0.7rem;
      color: var(--accent);
      text-transform: uppercase;
      font-weight: 700;
      margin-bottom: 0.3rem;
    }}
    pre {{
      font-family: var(--font-mono);
      overflow-x: auto;
      font-size: 0.75rem;
      white-space: pre-wrap;
      word-break: break-all;
    }}
    .clean-posture {{
      padding: 1.5rem;
      text-align: center;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: #10b981;
      font-family: var(--font-mono);
      font-weight: 600;
    }}
    footer {{
      margin-top: 3rem;
      border-top: 1px solid var(--border);
      padding-top: 1.5rem;
      font-size: 0.75rem;
      color: var(--text-muted);
      font-family: var(--font-mono);
      text-align: center;
      line-height: 1.8;
    }}
    @media print {{
      body {{ background: #ffffff; color: #000000; padding: 0; }}
      .meta-bar, .hero-card, table, .finding-card {{ border: 1px solid #ccc; background: #fff; break-inside: avoid; }}
      .badge-verified {{ border: 1px solid #10b981; color: #10b981; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <span class="logo">E</span>
        <div>
          <div class="brand-title">EXPOSE SECURITY INTELLIGENCE</div>
          <div class="brand-tag">EVIDENCE FIRST. INTELLIGENCE SECOND.</div>
        </div>
      </div>
      <div>
        {verified_badge}
      </div>
    </header>

    <div class="meta-bar">
      <div class="meta-item">
        <label>Target Host</label>
        <value>{host}</value>
      </div>
      <div class="meta-item">
        <label>Resolved IP(s)</label>
        <value>{ips}</value>
      </div>
      <div class="meta-item">
        <label>Audit Date</label>
        <value>{timestamp}</value>
      </div>
      <div class="meta-item">
        <label>Duration / Scan ID</label>
        <value>{duration} | {scan_id}</value>
      </div>
    </div>

    <div class="hero-card">
      <div class="score-gauge">
        <div class="score-val">{score}</div>
        <div class="score-max">/ 100</div>
      </div>
      <div class="hero-info">
        <h2>
          <span>Security Posture Evaluation</span>
          <span class="grade-pill">GRADE {grade}</span>
        </h2>
        <p class="summary-text">{summary_text}</p>
        <div class="stats-row">
          <span>Confirmed Flaws: <strong style="color: #ef4444;">{flaws}</strong></span>
          <span>Security Controls: <strong style="color: #10b981;">{controls}</strong></span>
        </div>
      </div>
    </div>

    <h3 class="section-title">Evaluation Categories & Weights</h3>
    <table>
      <thead>
        <tr>
          <th>Category</th>
          <th>Score</th>
          <th>Weight</th>
          <th>Confirmed Flaws</th>
        </tr>
      </thead>
      <tbody>
        {categories_html}
      </tbody>
    </table>

    <h3 class="section-title">Confirmed Security Findings ({len(confirmed_findings)})</h3>
    {findings_html}

    <footer>
      <p>Report generated by EXPOSE v{__version__} | Standards: OWASP Top 10:2025, OWASP ASVS 5.0, OASIS SARIF v2.1.0</p>
      <p>Principle: Evidence first. Intelligence second. All observations derived from reproducible wire evidence.</p>
    </footer>
  </div>
</body>
</html>
"""
