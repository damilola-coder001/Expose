"""Rich terminal formatting and reporting for the Expose CLI.

Presents a PageSpeed-style security posture assessment with explicit boundaries:
CONFIRMED, OBSERVED, and NOT ASSESSED.
"""

import json
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
from rich import box

from expose.core.attack_surface import AttackSurface
from expose.core.models import Confidence, Finding, ObservationStatus, ScanResult, Severity

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
    Severity.INFO: "bold blue",
}

CONFIDENCE_STYLES = {
    Confidence.CONFIRMED: "bold green",
    Confidence.LIKELY: "bold cyan",
    Confidence.POTENTIAL: "bold yellow",
    Confidence.INFORMATIONAL: "dim",
}

STATUS_STYLES = {
    ObservationStatus.CONFIRMED: "bold red",
    ObservationStatus.OBSERVED: "bold green",
    ObservationStatus.INFERRED: "bold yellow",
    ObservationStatus.NOT_ASSESSED: "bold dim",
}


class ReportFormatter:
    """Renders formatted security intelligence reports to console or files."""

    def __init__(self, console: Console = None):
        self.console = console or Console()

    def print_banner(self) -> None:
        banner = Text()
        banner.append("EXPOSE ", style="bold magenta")
        banner.append("v0.1.0 ", style="dim")
        banner.append("| See what your website exposes.", style="italic cyan")
        self.console.print(banner)
        self.console.print("[dim]Evidence first. Intelligence second. Unauthenticated external assessment.[/dim]\n")

    def render_scan_summary(self, result: ScanResult) -> None:
        """Renders comprehensive PageSpeed-style score card, target scope, attack surface, and findings breakdown."""
        target = result.target
        card = result.score_card

        # 1. Target Scope & Score Gauge Panel
        if card:
            score = card.overall_score
            grade = card.letter_grade
            if score >= 90:
                score_color = "bold green"
            elif score >= 75:
                score_color = "bold yellow"
            elif score >= 60:
                score_color = "bold orange3"
            else:
                score_color = "bold red"

            gauge_table = Table.grid(padding=(0, 3))
            gauge_table.add_column("Metric", justify="center")
            gauge_table.add_column("Details")

            gauge_text = Text()
            gauge_text.append(f"\n  {score} / 100  \n", style=f"{score_color} reverse")
            gauge_text.append(f"  GRADE: {grade}  ", style=f"{score_color} bold")

            meta_text = Text()
            meta_text.append(f"Target: {target.normalized_url}\n", style="bold white")
            meta_text.append(f"Host: {target.host} | Port: {target.port} ({target.scheme.upper()})\n", style="dim")
            meta_text.append(f"Resolved IP(s): {', '.join(target.resolved_ips)}\n", style="dim")
            meta_text.append(f"Scan Duration: {result.duration_seconds}s | Scan ID: {result.scan_id}\n", style="dim")
            meta_text.append(
                f"Score Model: v{card.score_version} | Confirmed Flaws: {card.confirmed_flaws_count} | Observed Attributes: {card.observed_properties_count}\n",
                style="cyan"
            )
            meta_text.append(
                "This score reflects the externally observable security controls and findings assessed by Expose.\n"
                "The score is not a guarantee that a website is secure.",
                style="italic dim"
            )

            gauge_table.add_row(gauge_text, meta_text)
            self.console.print(Panel(gauge_table, title=f"[bold cyan]Security Posture Assessment (Engine v{card.score_version})[/bold cyan]", border_style="cyan"))

            # 2. Canonical Category Sub-Scores Table (Phase 9 - 9 Canonical Categories)
            cat_table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
            cat_table.add_column("Assessment Category", style="bold white")
            cat_table.add_column("Category Score", justify="center")
            cat_table.add_column("Weight", justify="center", style="dim")
            cat_table.add_column("Findings", justify="center")
            cat_table.add_column("Confirmed Flaws", justify="center")

            for name, cat in card.category_scores.items():
                c_score = cat.score
                c_color = "green" if c_score >= 90 else ("yellow" if c_score >= 70 else "red")
                cat_table.add_row(
                    name,
                    f"[{c_color}]{c_score} / 100[/{c_color}]",
                    f"{cat.weight_percentage}%",
                    str(cat.findings_count),
                    f"[red]{cat.confirmed_issues_count}[/red]" if cat.confirmed_issues_count > 0 else "[green]0[/green]",
                )
            self.console.print(cat_table)

        # 3. Phase 8 Attack Surface Hierarchy Tree
        if result.attack_surface:
            self.render_attack_surface(result.attack_surface)

        # 3. Confirmed Security Deficiencies Table
        confirmed_findings = [f for f in result.findings if f.status == ObservationStatus.CONFIRMED]
        if confirmed_findings:
            f_table = Table(box=box.MINIMAL_DOUBLE_HEAD, show_header=True, header_style="bold red")
            f_table.add_column("ID", style="dim", no_wrap=True)
            f_table.add_column("Severity", justify="center", no_wrap=True)
            f_table.add_column("Confidence", justify="center", no_wrap=True)
            f_table.add_column("Confirmed Issue Title", style="bold")
            f_table.add_column("OWASP (2025)", style="magenta", no_wrap=True)
            f_table.add_column("ASVS 5.0", style="yellow", no_wrap=True)
            f_table.add_column("CWE", style="cyan", no_wrap=True)

            for f in confirmed_findings:
                sev_style = SEVERITY_STYLES.get(f.severity, "white")
                conf_style = CONFIDENCE_STYLES.get(f.confidence, "white")
                owasp_short = f.owasp_top10.split(" - ")[0] if f.owasp_top10 else "N/A"
                f_table.add_row(
                    f.id,
                    f"[{sev_style}]{f.severity.value}[/{sev_style}]",
                    f"[{conf_style}]{f.confidence.value}[/{conf_style}]",
                    f.title,
                    owasp_short,
                    f.owasp_asvs or "N/A",
                    f.cwe_id or "N/A",
                )
            self.console.print(Panel(f_table, title="[bold red]Confirmed Security Deficiencies (OWASP Top 10:2025 & ASVS 5.0 Mapped)[/bold red]", border_style="red"))
        else:
            self.console.print(Panel("[bold green][OK] No confirmed security deficiencies discovered by active probes.[/bold green]"))

        # 4. Observed Technical Properties (Positive/Neutral)
        observed_findings = [f for f in result.findings if f.status == ObservationStatus.OBSERVED]
        if observed_findings:
            o_table = Table(box=box.SIMPLE, show_header=True, header_style="bold green")
            o_table.add_column("ID", style="dim", no_wrap=True)
            o_table.add_column("Observed Security Attribute", style="bold white")
            o_table.add_column("Category", style="dim")

            for f in observed_findings:
                o_table.add_row(f.id, f.title, f.category.value)
            self.console.print(Panel(o_table, title="[bold green]Observed Technical Properties[/bold green]", border_style="green"))

        # 5. Explicit NOT ASSESSED Boundaries
        if card and card.not_assessed_boundaries:
            b_table = Table(box=box.SIMPLE, show_header=True, header_style="bold yellow")
            b_table.add_column("Security Boundary (NOT ASSESSED)", style="bold yellow")
            b_table.add_column("Constraint Rationale", style="dim")

            for b in card.not_assessed_boundaries:
                b_table.add_row(b.area, b.reason)
            self.console.print(Panel(b_table, title="[bold yellow]Assessment Boundaries (Out of Scope for External Scan)[/bold yellow]", border_style="yellow"))

        # 6. AI Prioritization Roadmap (Phases 11 & 18)
        if result.ai_prioritization:
            prio = result.ai_prioritization
            p_table = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta")
            p_table.add_column("Rank", justify="center", no_wrap=True)
            p_table.add_column("Urgency Tier", justify="center", no_wrap=True)
            p_table.add_column("Finding ID", style="dim", no_wrap=True)
            p_table.add_column("Title", style="bold")
            p_table.add_column("Remediation Justification")

            for item in prio.prioritized_items:
                urgency_color = "red" if "IMMEDIATE" in item.urgency_tier else ("yellow" if "HIGH" in item.urgency_tier else "cyan")
                p_table.add_row(
                    str(item.priority_rank),
                    f"[{urgency_color}]{item.urgency_tier}[/{urgency_color}]",
                    item.finding_id,
                    item.title,
                    item.justification,
                )

            summary_text = f"[bold white]{prio.executive_summary}[/bold white]\n\n"
            if prio.remediation_roadmap:
                summary_text += "[bold yellow]Remediation Engineering Roadmap:[/bold yellow]\n"
                for step in prio.remediation_roadmap:
                    summary_text += f"  • {step}\n"

            self.console.print(
                Panel(
                    Group(Text.from_markup(summary_text), p_table),
                    title="[bold magenta]AI Security Intelligence: Fix Prioritization & Remediation Roadmap[/bold magenta]",
                    border_style="magenta"
                )
            )

        self.console.print("[dim]Use [bold]expose inspect <report_file> <finding_id>[/bold] to view complete technical evidence and verification commands.[/dim]\n")

    def render_finding_detail(self, finding: Finding) -> None:
        """Renders deep technical breakdown, evidence, and verification command for a single finding."""
        sev_style = SEVERITY_STYLES.get(finding.severity, "white")
        stat_style = STATUS_STYLES.get(finding.status, "white")

        detail_table = Table.grid(padding=(0, 2))
        detail_table.add_column(style="bold dim")
        detail_table.add_column()

        detail_table.add_row("Finding ID:", f"[bold]{finding.id}[/bold]")
        detail_table.add_row("Status:", f"[{stat_style}]{finding.status.value}[/{stat_style}]")
        detail_table.add_row("Severity:", f"[{sev_style}]{finding.severity.value}[/{sev_style}]")
        detail_table.add_row("Confidence:", f"[bold green]{finding.confidence.value}[/bold green]")
        detail_table.add_row("Category:", finding.category.value)
        detail_table.add_row("Target:", finding.target)
        detail_table.add_row("Probe:", finding.probe)
        if finding.owasp_top10:
            detail_table.add_row("OWASP Top 10 (2025):", f"[bold magenta]{finding.owasp_top10}[/bold magenta]")
        if finding.owasp_asvs:
            detail_table.add_row("OWASP ASVS 5.0:", f"[bold yellow]{finding.owasp_asvs}[/bold yellow]")
        if finding.cwe_id:
            detail_table.add_row("CWE Classification:", f"[cyan]{finding.cwe_id}[/cyan]")
        if finding.cve_id:
            detail_table.add_row("CVE ID:", f"[bold red]{finding.cve_id}[/bold red]")

        detail_panel = Panel(
            detail_table,
            title=f"[{sev_style}]{finding.title}[/{sev_style}]",
            border_style="cyan"
        )
        self.console.print(detail_panel)

        # --- DUAL VIEW 1: SIMPLE EXPLANATION (For Site Owners / Ordinary Developers) ---
        simple_text = [
            f"[bold cyan]What we observed:[/bold cyan] {finding.ai_intelligence.observation if (finding.ai_intelligence and finding.ai_intelligence.observation) else finding.description}\n",
            f"[bold yellow]Why this matters to you:[/bold yellow] {finding.ai_intelligence.impact if (finding.ai_intelligence and finding.ai_intelligence.impact) else (finding.impact_explanation or 'This misconfiguration exposes your site or visitors to potential eavesdropping or attack.')}\n",
            f"[bold green]What you should do:[/bold green] {finding.ai_intelligence.recommendation if (finding.ai_intelligence and finding.ai_intelligence.recommendation) else finding.remediation}",
        ]
        self.console.print(
            Panel(
                "".join(simple_text),
                title="[bold yellow]Simple Explanation (For Site Owners & Developers)[/bold yellow]",
                border_style="yellow"
            )
        )

        # --- DUAL VIEW 2: DEVELOPER DETAILS (For Security Engineers) ---
        dev_parts = [
            f"[bold cyan]What We Found:[/bold cyan]\n{finding.description}\n",
            f"[bold cyan]Why It Matters:[/bold cyan]\n{finding.ai_intelligence.security_meaning if (finding.ai_intelligence and finding.ai_intelligence.security_meaning) else (finding.impact_explanation or 'Security control absent.')}\n",
            f"[bold cyan]Potential Impact:[/bold cyan]\n{finding.ai_intelligence.impact if (finding.ai_intelligence and finding.ai_intelligence.impact) else (finding.impact_explanation or 'Risk of unauthorized access or interception.')}\n",
            f"[bold cyan]Real-World Context:[/bold cyan]\n{finding.ai_intelligence.real_world_context if (finding.ai_intelligence and finding.ai_intelligence.real_world_context) else 'Documented in industry standards and CVE records.'}\n",
            f"[bold green]Recommended Remediation:[/bold green]\n{finding.remediation}\n",
        ]

        if finding.verification_command:
            dev_parts.append(
                f"[bold cyan]How To Verify (Independent Command):[/bold cyan]\n[bold green]{finding.verification_command}[/bold green]\n"
            )

        self.console.print(
            Panel(
                "".join(dev_parts),
                title="[bold cyan]Developer Details (Technical Breakdown)[/bold cyan]",
                border_style="cyan"
            )
        )

        # Verifiable Technical Wire Evidence
        ev = finding.evidence
        evidence_content = [f"[bold yellow]Summary:[/bold yellow] {ev.summary}\n"]
        evidence_content.append(f"[bold dim]Evidence Type:[/bold dim] {ev.type.value}")
        evidence_content.append(f"[bold dim]Captured At:[/bold dim] {ev.timestamp.isoformat()}\n")

        if ev.request:
            evidence_content.append("[bold cyan]Request:[/bold cyan]")
            evidence_content.append(json.dumps(ev.request, indent=2))
        if ev.response:
            evidence_content.append("\n[bold cyan]Response Evidence:[/bold cyan]")
            evidence_content.append(json.dumps(ev.response, indent=2))
        if ev.raw_data:
            evidence_content.append("\n[bold cyan]Raw Wire / Protocol Metadata:[/bold cyan]")
            evidence_content.append(json.dumps(ev.raw_data, indent=2))

        self.console.print(
            Panel("\n".join(evidence_content), title="[bold green]Verifiable Technical Evidence[/bold green]", border_style="green")
        )

        # Grounded AI Security Intelligence Reasoning Contract (Phase 12)
        if finding.ai_intelligence:
            ai = finding.ai_intelligence
            ai_parts = [
                f"[bold cyan]Research Provider:[/bold cyan] {ai.provider_name} | [dim]Grounded: {'Yes (Live Web Search)' if ai.is_grounded else 'Local Standard'}[/dim]\n",
                f"[bold magenta]1. OBSERVATION:[/bold magenta] {ai.observation or finding.title}",
                f"[bold magenta]2. EVIDENCE:[/bold magenta] {ai.evidence_summary or ev.summary}",
                f"[bold magenta]3. SECURITY MEANING:[/bold magenta] {ai.security_meaning or ai.explanation}",
                f"[bold magenta]4. CONFIDENCE:[/bold magenta] {ai.confidence_explanation or finding.confidence.value}",
                f"[bold magenta]5. IMPACT:[/bold magenta] {ai.impact or ai.contextual_impact}",
                f"[bold magenta]6. REAL-WORLD CONTEXT:[/bold magenta] {ai.real_world_context or ai.comparative_examples}",
                f"[bold magenta]7. RECOMMENDATION:[/bold magenta] {ai.recommendation or (ai.developer_recommendations and ' '.join(ai.developer_recommendations)) or finding.remediation}",
                f"[bold magenta]8. VERIFICATION:[/bold magenta] {ai.verification_method or finding.verification_command or 'Re-run scan probe'}\n",
            ]

            if ai.developer_recommendations:
                ai_parts.append("[bold green]Actionable Developer Remediation Steps:[/bold green]")
                for step in ai.developer_recommendations:
                    ai_parts.append(f"  • {step}")
                ai_parts.append("")

            if ai.source_citations:
                ai_parts.append("[bold magenta]Verified Authoritative Sources & Citations:[/bold magenta]")
                for sc in ai.source_citations:
                    snip = f" — [italic dim]\"{sc.snippet}\"[/italic dim]" if sc.snippet else ""
                    ai_parts.append(f"  • [{sc.source_type.value}] [bold underline cyan]{sc.title}[/bold underline cyan]\n    {sc.url}{snip}")

            self.console.print(
                Panel(
                    "\n".join(ai_parts),
                    title="[bold magenta]AI Security Intelligence (Phase 12 Reasoning Contract)[/bold magenta]",
                    border_style="magenta"
                )
            )

    def render_attack_surface(self, surface: AttackSurface) -> None:
        """Renders Phase 8 attack surface hierarchy tree answering: What does this website expose publicly?"""
        root_tree = Tree(
            f"[bold cyan]{surface.target}[/bold cyan] [dim]— {surface.exposure_summary}[/dim]",
            guide_style="bold blue",
        )

        # 1. Pages
        pages_branch = root_tree.add(f"[bold white]Pages[/bold white] [dim]({len(surface.pages)})[/dim]")
        for p in surface.pages[:6]:
            code_str = f" [green][{p.status_code}][/green]" if p.status_code else ""
            title_str = f" [italic dim]\"{p.title}\"[/italic dim]" if p.title and p.title != "Untitled Document" else ""
            via_str = f" [dim]({p.discovered_via})[/dim]"
            pages_branch.add(f"{p.path}{code_str}{title_str}{via_str}")
        if len(surface.pages) > 6:
            pages_branch.add(f"[dim]... (+{len(surface.pages) - 6} more pages)[/dim]")

        # 2. APIs
        apis_branch = root_tree.add(f"[bold white]APIs & Endpoints[/bold white] [dim]({len(surface.apis)})[/dim]")
        if surface.apis:
            for api in surface.apis[:6]:
                apis_branch.add(f"[cyan]{api.method}[/cyan] [bold]{api.path}[/bold]")
            if len(surface.apis) > 6:
                apis_branch.add(f"[dim]... (+{len(surface.apis) - 6} more endpoints)[/dim]")
        else:
            apis_branch.add("[dim]None publicly observed[/dim]")

        # 3. Forms
        forms_branch = root_tree.add(f"[bold white]Submission Forms[/bold white] [dim]({len(surface.forms)})[/dim]")
        if surface.forms:
            for f in surface.forms[:4]:
                sec_badge = "[green][HTTPS][/green]" if f.is_secure_action else "[red][INSECURE HTTP][/red]"
                pw_badge = " [yellow](Password Form)[/yellow]" if f.has_password else ""
                form_node = forms_branch.add(f"{f.method} [bold]{f.action}[/bold] {sec_badge}{pw_badge}")
                if f.inputs:
                    inp_summary = ", ".join(f"{i.name}:{i.input_type}" for i in f.inputs[:5])
                    form_node.add(f"[dim]Fields: {inp_summary}[/dim]")
            if len(surface.forms) > 4:
                forms_branch.add(f"[dim]... (+{len(surface.forms) - 4} more forms)[/dim]")
        else:
            forms_branch.add("[dim]None observed on entry pages[/dim]")

        # 4. Scripts & Bundles
        scripts_branch = root_tree.add(f"[bold white]Scripts[/bold white] [dim]({len(surface.scripts)})[/dim]")
        for s in surface.scripts[:5]:
            sri_str = "[green][SRI][/green]" if s.has_sri else "[dim][No SRI][/dim]"
            cdn_str = f" [cyan]({s.cdn_provider})[/cyan]" if s.cdn_provider else ""
            scripts_branch.add(f"{s.url.split('/')[-1]} {sri_str}{cdn_str} [dim]<{s.url}>[/dim]")
        if len(surface.scripts) > 5:
            scripts_branch.add(f"[dim]... (+{len(surface.scripts) - 5} more scripts)[/dim]")

        # 5. Static Assets
        assets_branch = root_tree.add(f"[bold white]Assets[/bold white] [dim]({len(surface.assets)})[/dim]")
        for a in surface.assets[:4]:
            assets_branch.add(f"[{a.asset_type}] {a.url.split('/')[-1]} [dim]<{a.url}>[/dim]")
        if len(surface.assets) > 4:
            assets_branch.add(f"[dim]... (+{len(surface.assets) - 4} more assets)[/dim]")

        # 6. External Dependencies
        deps_branch = root_tree.add(f"[bold white]External Dependencies[/bold white] [dim]({len(surface.external_dependencies)})[/dim]")
        if surface.external_dependencies:
            for dep in surface.external_dependencies[:6]:
                deps_branch.add(f"[bold magenta]{dep.origin}[/bold magenta] [yellow]({dep.category})[/yellow] [dim]— {dep.resource_count} resource(s)[/dim]")
            if len(surface.external_dependencies) > 6:
                deps_branch.add(f"[dim]... (+{len(surface.external_dependencies) - 6} more dependencies)[/dim]")
        else:
            deps_branch.add("[dim]Zero external origins (self-contained)[/dim]")

        # 7. Robots & Sitemaps
        if surface.robots_txt and surface.robots_txt.is_present:
            robots_branch = root_tree.add("[bold white]robots.txt Directives[/bold white]")
            robots_branch.add(f"[dim]Disallowed rules: {len(surface.robots_txt.disallowed_paths)} | Allowed: {len(surface.robots_txt.allowed_paths)}[/dim]")
            if surface.robots_txt.disallowed_paths:
                for d in surface.robots_txt.disallowed_paths[:3]:
                    robots_branch.add(f"[red]Disallow: {d}[/red]")
                if len(surface.robots_txt.disallowed_paths) > 3:
                    robots_branch.add(f"[dim]... (+{len(surface.robots_txt.disallowed_paths) - 3} more)[/dim]")

        self.console.print(Panel(root_tree, title="[bold cyan]Attack Surface Discovery (Phase 8)[/bold cyan]", border_style="cyan"))

    def render_batch_summary(self, batch_summary) -> None:
        """Renders enterprise portfolio multi-target batch summary table."""
        table = Table(
            title="Enterprise Security Portfolio Assessment",
            box=box.ROUNDED,
            header_style="bold magenta",
            show_header=True,
        )
        table.add_column("Target Host", style="bold white", min_width=24)
        table.add_column("Score", justify="center", min_width=8)
        table.add_column("Grade", justify="center", min_width=8)
        table.add_column("Findings", justify="center", min_width=10)
        table.add_column("Critical / High", justify="center", min_width=15)
        table.add_column("Duration", justify="right", min_width=10)
        table.add_column("Status", justify="center", min_width=10)

        for item in batch_summary.items:
            grade_color = {
                "A": "bold green",
                "B": "bold cyan",
                "C": "bold yellow",
                "D": "bold red",
                "F": "bold white on red",
            }.get(item.letter_grade, "dim")

            crit_high_str = (
                f"[bold red]{item.critical_count}[/bold red] / [bold yellow]{item.high_count}[/bold yellow]"
                if (item.critical_count > 0 or item.high_count > 0)
                else "[green]0 / 0[/green]"
            )
            status_str = (
                "[bold green]COMPLETE[/bold green]"
                if item.status == "completed"
                else f"[bold red]{item.status.upper()}[/bold red]"
            )

            table.add_row(
                item.target,
                f"[{grade_color}]{item.score}[/{grade_color}]" if item.score is not None else "-",
                f"[{grade_color}]{item.letter_grade}[/{grade_color}]",
                str(item.findings_count),
                crit_high_str,
                f"{item.duration_seconds:.1f}s",
                status_str,
            )

        self.console.print(table)
        portfolio_score_color = (
            "bold green"
            if batch_summary.portfolio_average_score >= 80
            else ("bold yellow" if batch_summary.portfolio_average_score >= 60 else "bold red")
        )
        self.console.print(
            f"\n[bold]Portfolio Overview:[/bold] [white]{batch_summary.total_targets} targets scanned[/white] | "
            f"Average Score: [{portfolio_score_color}]{batch_summary.portfolio_average_score}/100[/{portfolio_score_color}] | "
            f"Total Findings: [yellow]{batch_summary.total_findings}[/yellow] "
            f"([red]{batch_summary.total_critical} Critical[/red], [yellow]{batch_summary.total_high} High[/yellow])\n"
        )


