"""Expose command-line interface entrypoint."""

import asyncio
import json
import sys
from typing import Optional
import click
from rich.console import Console

from expose.core.orchestrator import ScanOrchestrator
from expose.core.safety import SecurityScopeError
from expose.cli.formatter import ReportFormatter

console = Console()
formatter = ReportFormatter(console)


@click.group()
@click.version_option(version="0.1.0", prog_name="Expose")
def cli():
    """Expose: Production-oriented Website Security Intelligence Platform."""
    pass


@cli.command("scan")
@click.argument("target", required=True)
@click.option("--allow-private", is_flag=True, default=False, help="Permit scanning RFC1918/loopback private targets.")
@click.option("--ai", is_flag=True, default=False, help="Enable AI Security Intelligence and Grounded Web Research.")
@click.option("--json-out", is_flag=True, default=False, help="Output raw JSON to stdout.")
@click.option("--output", "-o", type=click.Path(writable=True), help="Save scan results to a JSON file.")
@click.option("--sarif", type=click.Path(writable=True), help="Save results in OASIS SARIF v2.1.0 format for CI/CD.")
@click.option("--html-out", type=click.Path(writable=True), help="Save executive self-contained HTML report with CSS/SVG.")
@click.option("--multi-region", is_flag=True, default=False, help="Perform comparative global vantage point audits (US, EU, AP).")
@click.option("--min-score", type=int, default=None, help="Fail (exit 1) if overall security score is below this threshold.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Display full technical evidence for all findings.")
def scan_cmd(
    target: str,
    allow_private: bool,
    ai: bool,
    json_out: bool,
    output: Optional[str],
    sarif: Optional[str],
    html_out: Optional[str],
    multi_region: bool,
    min_score: Optional[int],
    verbose: bool,
):
    """Perform a security intelligence scan against TARGET (URL or domain)."""
    if not json_out:
        formatter.print_banner()
        ai_notice = " [dim](AI Security Intelligence Active)[/dim]" if ai else ""
        console.print(f"[bold cyan]Initiating security intelligence scan for:[/bold cyan] [white]{target}[/white]{ai_notice}...")

    orchestrator = ScanOrchestrator()

    try:
        result = asyncio.run(orchestrator.scan(target, allow_private=allow_private, enable_ai=ai))
    except SecurityScopeError as e:
        if json_out:
            click.echo(json.dumps({"error": str(e)}, indent=2))
        else:
            console.print(f"\n[bold red]Safety Policy Violation:[/bold red] {e}")
        sys.exit(2)
    except Exception as e:
        if json_out:
            click.echo(json.dumps({"error": f"Scan failed: {str(e)}"}, indent=2))
        else:
            console.print(f"\n[bold red]Scan Execution Error:[/bold red] {e}")
        sys.exit(1)

    result_dict = result.model_dump(mode="json")

    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(result_dict, f, indent=2)
        if not json_out:
            console.print(f"[bold green][OK] Report saved to:[/bold green] {output}\n")

    if sarif:
        from expose.core.export import generate_sarif_report
        sarif_data = generate_sarif_report(result)
        with open(sarif, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2)
        if not json_out:
            console.print(f"[bold green][OK] OASIS SARIF v2.1.0 saved to:[/bold green] {sarif}\n")

    if html_out:
        from expose.core.export import generate_executive_html_report
        html_content = generate_executive_html_report(result)
        with open(html_out, "w", encoding="utf-8") as f:
            f.write(html_content)
        if not json_out:
            console.print(f"[bold green][OK] Executive HTML report saved to:[/bold green] {html_out}\n")

    if json_out:
        click.echo(json.dumps(result_dict, indent=2))
    else:
        if multi_region:
            from expose.core.multi_region import MultiRegionOrchestrator
            console.print("[cyan]Probing target across global vantage points (US-East, EU-Central, AP-Southeast)...[/cyan]")
            mr_orchestrator = MultiRegionOrchestrator()
            mr_comp = asyncio.run(mr_orchestrator.audit_target(target))
            console.print(f"[bold green]Multi-Region Analysis:[/bold green] {mr_comp.summary}")
            for obs in mr_comp.observations:
                status_icon = "✓" if obs.reachable else "✗"
                console.print(f"  [{'green' if obs.reachable else 'red'}]{status_icon} {obs.vantage_point_name}[/]: IP={obs.resolved_ip or 'N/A'}, Latency={obs.latency_ms:.1f}ms, Status={obs.http_status or 'N/A'}")
            console.print()

        formatter.render_scan_summary(result)
        if verbose:
            for f in result.findings:
                console.print()
                formatter.render_finding_detail(f)

    if min_score is not None and result.score_card.overall_score < min_score:
        if not json_out:
            console.print(
                f"\n[bold red][CI POLICY BREACH][/bold red] Security score {result.score_card.overall_score} "
                f"fell below minimum required score {min_score}!"
            )
        sys.exit(1)


@cli.command("inspect")
@click.argument("report_file", type=click.Path(exists=True))
@click.argument("finding_id", required=False)
def inspect_cmd(report_file: str, finding_id: Optional[str]):
    """Inspect verifiable technical evidence from a saved scan JSON report."""
    formatter.print_banner()
    with open(report_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = data.get("findings", [])
    if not findings:
        console.print("[yellow]No findings contained in this report.[/yellow]")
        return

    if finding_id:
        target_finding = next((f for f in findings if f["id"].upper() == finding_id.upper()), None)
        if not target_finding:
            console.print(f"[red]Finding ID '{finding_id}' not found in {report_file}.[/red]")
            return
        from expose.core.models import Finding
        formatter.render_finding_detail(Finding.model_validate(target_finding))
    else:
        from expose.core.models import Finding
        for f in findings:
            formatter.render_finding_detail(Finding.model_validate(f))
            console.print()


@cli.command("serve")
@click.option("--host", default="127.0.0.1", help="API server bind host.")
@click.option("--port", default=8000, type=int, help="API server port.")
@click.option("--reload", is_flag=True, default=False, help="Enable auto-reload for development.")
def serve_cmd(host: str, port: int, reload: bool):
    """Start the Expose FastAPI REST API server."""
    import uvicorn
    formatter.print_banner()
    console.print(f"[bold green]Starting Expose REST API at http://{host}:{port} ...[/bold green]")
    uvicorn.run("expose.api.app:app", host=host, port=port, reload=reload)


@cli.command("verify-fix")
@click.argument("report_file", type=click.Path(exists=True))
@click.argument("finding_id", required=True)
@click.option("--json-out", is_flag=True, default=False, help="Output raw JSON verification result.")
def verify_fix_cmd(report_file: str, finding_id: str, json_out: bool):
    """Re-verify a single finding to confirm whether a security fix was effective."""
    with open(report_file, "r", encoding="utf-8") as f:
        scan_data = json.load(f)

    from expose.core.models import Finding, ScanResult
    from expose.core.verifier import FindingVerifier

    scan_result = ScanResult.model_validate(scan_data)
    target_finding = next((f for f in scan_result.findings if f.id.upper() == finding_id.upper()), None)
    if not target_finding:
        if json_out:
            click.echo(json.dumps({"error": f"Finding ID '{finding_id}' not found in {report_file}"}, indent=2))
        else:
            console.print(f"[bold red]Finding ID '{finding_id}' not found in report.[/bold red]")
        sys.exit(1)

    if not json_out:
        formatter.print_banner()
        console.print(f"[bold cyan]Re-verifying finding:[/bold cyan] {target_finding.title} ([dim]{target_finding.id}[/dim]) on [white]{scan_result.target.host}[/white]...")

    verifier = FindingVerifier()
    try:
        verif_result = asyncio.run(verifier.verify_finding(target_finding, scan_result))
    except Exception as e:
        if json_out:
            click.echo(json.dumps({"error": f"Verification failed: {str(e)}"}, indent=2))
        else:
            console.print(f"[bold red]Verification execution error:[/bold red] {e}")
        sys.exit(1)

    if json_out:
        click.echo(json.dumps(verif_result.model_dump(mode="json"), indent=2))
    else:
        console.print()
        if verif_result.is_fixed:
            console.print(f"[bold green]✓ REMEDIATED / FIXED:[/bold green] {verif_result.explanation}")
        else:
            console.print(f"[bold red]✗ STILL VULNERABLE:[/bold red] {verif_result.explanation}")
        if verif_result.recalculated_score is not None:
            console.print(f"[cyan]Recalculated Score:[/cyan] [bold]{verif_result.recalculated_score}/100[/bold]")


@cli.group("domain")
def domain_group():
    """Domain ownership verification and proof-of-control challenges."""
    pass


@domain_group.command("challenge")
@click.argument("domain", required=True)
@click.option("--json-out", is_flag=True, default=False, help="Output raw JSON challenge instructions.")
def domain_challenge_cmd(domain: str, json_out: bool):
    """Generate a domain ownership proof challenge token for DOMAIN."""
    from expose.core.ownership import get_ownership_verifier

    verifier = get_ownership_verifier()
    challenge = verifier.get_challenge(domain)

    if json_out:
        click.echo(json.dumps(challenge.model_dump(mode="json"), indent=2))
    else:
        formatter.print_banner()
        console.print(f"[bold cyan]Domain Ownership Challenge for:[/bold cyan] [white]{domain}[/white]")
        console.print(f"[dim]Expires at: {challenge.expires_at}[/dim]\n")
        console.print("[bold yellow]Option 1: DNS TXT Record (Recommended)[/bold yellow]")
        console.print(f"Record Name:  [bold white]{challenge.dns_record_name}[/bold white]")
        console.print(f"Record Value: [bold green]{challenge.dns_record_value}[/bold green]\n")
        console.print("[bold yellow]Option 2: HTTP Well-Known Endpoint[/bold yellow]")
        console.print(f"Endpoint URL: [bold white]{challenge.http_url}[/bold white]")
        console.print(f"File Body:    [bold green]{challenge.http_expected_content}[/bold green]\n")


@domain_group.command("verify")
@click.argument("domain", required=True)
@click.option("--method", type=click.Choice(["dns-txt", "http-well-known", "any"]), default="any", help="Verification challenge method.")
@click.option("--json-out", is_flag=True, default=False, help="Output raw JSON verification result.")
def domain_verify_cmd(domain: str, method: str, json_out: bool):
    """Verify domain ownership proof challenge for DOMAIN."""
    from expose.core.ownership import get_ownership_verifier, VerificationMethod

    verifier = get_ownership_verifier()
    if method == "dns-txt":
        verif_method = VerificationMethod.DNS_TXT
    elif method == "http-well-known":
        verif_method = VerificationMethod.HTTP_WELL_KNOWN
    else:
        verif_method = VerificationMethod.ANY

    if not json_out:
        formatter.print_banner()
        console.print(f"[bold cyan]Validating ownership proof for:[/bold cyan] [white]{domain}[/white] ([dim]{method}[/dim])...")

    success, msg, record = asyncio.run(verifier.verify_domain(domain, method=verif_method))

    if json_out:
        res = {
            "verified": success,
            "domain": domain,
            "message": msg,
            "record": record.model_dump(mode="json") if record else None,
        }
        click.echo(json.dumps(res, indent=2))
    else:
        console.print()
        if success and record:
            console.print(f"[bold green]✓ DOMAIN VERIFIED:[/bold green] Domain ownership confirmed for [white]{domain}[/white] via {record.verification_method}.")
            console.print(f"[dim]Proof: {msg}[/dim]")
            console.print(f"[dim]Valid until: {record.expires_at}[/dim]")
        else:
            console.print(f"[bold red]✗ VERIFICATION FAILED:[/bold red] {msg}")
            console.print("[yellow]Ensure DNS TXT record has propagated or HTTP endpoint is publicly reachable.[/yellow]")


@domain_group.command("status")
@click.argument("domain", required=True)
@click.option("--json-out", is_flag=True, default=False, help="Output raw JSON status.")
def domain_status_cmd(domain: str, json_out: bool):
    """Check current cached verification status for DOMAIN."""
    from expose.core.ownership import get_ownership_verifier

    verifier = get_ownership_verifier()
    record = verifier.get_record(domain)

    if json_out:
        click.echo(json.dumps(record.model_dump(mode="json") if record else {"verified": False, "domain": domain}, indent=2))
    else:
        formatter.print_banner()
        if record and record.verified:
            console.print(f"[bold green]✓ VERIFIED OWNER:[/bold green] [white]{domain}[/white]")
            console.print(f"Method: {record.verification_method} | Verified at: {record.verified_at}")
        else:
            console.print(f"[yellow]UNVERIFIED:[/yellow] No active ownership record cached for [white]{domain}[/white].")


@cli.command("batch")
@click.argument("targets", required=True)
@click.option("--concurrency", "-c", type=int, default=5, help="Maximum concurrent scans (default: 5).")
@click.option("--allow-private", is_flag=True, default=False, help="Permit scanning RFC1918/loopback private targets.")
@click.option("--ai", is_flag=True, default=False, help="Enable AI Security Intelligence.")
@click.option("--json-out", is_flag=True, default=False, help="Output raw JSON batch summary.")
@click.option("--output", "-o", type=click.Path(writable=True), help="Save batch summary JSON to file.")
@click.option("--min-score", type=int, default=None, help="Fail if any target score or portfolio average falls below this.")
def batch_cmd(
    targets: str,
    concurrency: int,
    allow_private: bool,
    ai: bool,
    json_out: bool,
    output: Optional[str],
    min_score: Optional[int],
):
    """Scan multiple targets in parallel. TARGETS can be a comma-separated list or path to a file containing targets."""
    import os
    from expose.core.orchestrator import ScanOrchestrator

    target_list = []
    if os.path.exists(targets):
        with open(targets, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    target_list.append(stripped)
    else:
        target_list = [t.strip() for t in targets.split(",") if t.strip()]

    if not target_list:
        console.print("[bold red]Error: No valid targets provided.[/bold red]")
        sys.exit(1)

    if not json_out:
        formatter.print_banner()
        console.print(f"[bold cyan]Launching portfolio batch scan across {len(target_list)} targets[/bold cyan] (concurrency={concurrency})...\n")

    orchestrator = ScanOrchestrator()
    summary = asyncio.run(orchestrator.scan_batch(
        targets=target_list,
        concurrency=concurrency,
        allow_private=allow_private,
        enable_ai=ai,
    ))

    summary_dict = summary.model_dump(mode="json")

    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(summary_dict, f, indent=2)
        if not json_out:
            console.print(f"[bold green][OK] Batch summary saved to:[/bold green] {output}\n")

    if json_out:
        click.echo(json.dumps(summary_dict, indent=2))
    else:
        formatter.render_batch_summary(summary)

    if min_score is not None:
        failed_targets = [it.target for it in summary.items if it.score is not None and it.score < min_score]
        if failed_targets or summary.portfolio_average_score < min_score:
            if not json_out:
                console.print(f"[bold red][CI POLICY BREACH][/bold red] Target(s) fell below min score {min_score}: {', '.join(failed_targets)}")
            sys.exit(1)


@cli.command("worker")
@click.option("--poll-interval", type=float, default=10.0, help="Scheduler poll interval in seconds.")
@click.option("--once", is_flag=True, default=False, help="Run due scheduled scans once and exit.")
def worker_cmd(poll_interval: float, once: bool):
    """Run the continuous monitoring scheduler daemon."""
    from expose.core.worker import MonitoringSchedulerDaemon

    formatter.print_banner()
    console.print(f"[bold green]Starting Expose Continuous Monitoring Worker Daemon[/bold green] (poll: {poll_interval}s) ...")
    daemon = MonitoringSchedulerDaemon(poll_interval_seconds=poll_interval)

    if once:
        console.print("[cyan]Running one-shot scheduler pass...[/cyan]")
        scans = asyncio.run(daemon.run_due_schedules_once())
        console.print(f"[bold green][OK] One-shot cycle complete. Executed {len(scans)} scheduled scan(s).[/bold green]")
    else:
        try:
            asyncio.run(daemon.start())
        except KeyboardInterrupt:
            console.print("\n[yellow]Worker daemon stopped by user.[/yellow]")


@cli.group("shield")
def shield_group():
    """Expose Shield: Inline WAF, attack inspection, and adaptive banning."""
    pass


@shield_group.command("start")
@click.option("--upstream", required=True, help="Target upstream application URL (e.g. http://127.0.0.1:3000).")
@click.option("--host", default="0.0.0.0", help="Shield bind address.")
@click.option("--port", default=8080, type=int, help="Shield listening port.")
def shield_start_cmd(upstream: str, host: str, port: int):
    """Start the Expose Shield Inline WAF reverse proxy in front of UPSTREAM."""
    import uvicorn
    from starlette.applications import Starlette
    from starlette.requests import Request
    from expose.shield.proxy import ShieldReverseProxy

    formatter.print_banner()
    console.print(f"[bold green]Starting Expose Shield WAF on http://{host}:{port}[/bold green] -> [cyan]{upstream}[/cyan]")
    console.print("[dim]Active protections: SQLi, XSS, Path Traversal/LFI, RCE, Hostile Scanners, Dynamic Banning[/dim]\n")

    proxy = ShieldReverseProxy(upstream_url=upstream)
    app = Starlette()

    @app.route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    async def proxy_handler(request: Request):
        client_ip = request.client.host if request.client else "127.0.0.1"
        body = await request.body()
        return await proxy.handle_request(
            method=request.method,
            path=request.url.path,
            query_string=str(request.query_params),
            headers=dict(request.headers),
            body=body,
            client_ip=client_ip,
        )

    uvicorn.run(app, host=host, port=port)


@shield_group.command("bans")
@click.option("--json-out", is_flag=True, default=False, help="Output raw JSON ban list.")
def shield_bans_cmd(json_out: bool):
    """List all currently active IP and device fingerprint bans."""
    from expose.shield.ban_manager import get_ban_manager
    manager = get_ban_manager()
    bans = manager.list_active_bans()

    if json_out:
        click.echo(json.dumps([b.model_dump(mode="json") for b in bans], indent=2))
    else:
        formatter.print_banner()
        console.print(f"[bold cyan]Active Expose Shield Bans ({len(bans)}):[/bold cyan]\n")
        if not bans:
            console.print("[green]No active bans. Zero malicious hosts currently blocked.[/green]")
            return

        from rich.table import Table
        from rich import box
        table = Table(box=box.ROUNDED, header_style="bold magenta")
        table.add_column("Identifier", style="bold white")
        table.add_column("Type", style="cyan")
        table.add_column("Threat Score", justify="center")
        table.add_column("Reason")
        table.add_column("Expires At", style="dim")

        for b in bans:
            exp_str = b.expires_at.strftime("%Y-%m-%d %H:%M:%S UTC") if b.expires_at else "Permanent"
            table.add_row(b.identifier, b.target_type, str(b.threat_score), b.reason, exp_str)

        console.print(table)


@shield_group.command("unban")
@click.argument("identifier", required=True)
def shield_unban_cmd(identifier: str):
    """Manually remove an IP address or device fingerprint from active bans."""
    from expose.shield.ban_manager import get_ban_manager
    manager = get_ban_manager()
    success = manager.unban(identifier)
    if success:
        console.print(f"[bold green]✓ Unbanned:[/bold green] Successfully removed ban on [white]{identifier}[/white]")
    else:
        console.print(f"[yellow]Identifier [white]{identifier}[/white] is not actively banned.[/yellow]")


@cli.group("threat-intel")
def threat_intel_group():
    """Live Threat Intelligence and CISA KEV exploitation feed."""
    pass


@threat_intel_group.command("sync")
def threat_intel_sync_cmd():
    """Synchronize the latest CISA Known Exploited Vulnerabilities catalog."""
    from expose.intelligence.threat_intel import get_threat_intel
    store = get_threat_intel()
    formatter.print_banner()
    console.print("[cyan]Synchronizing live feed from US CISA KEV endpoint...[/cyan]")
    success, msg, count = asyncio.run(store.sync_live_feed())
    if success:
        console.print(f"[bold green]✓ {msg}[/bold green]")
        console.print(f"[dim]Total indexed actively exploited CVEs: {count}[/dim]")
    else:
        console.print(f"[bold yellow]Notice:[/bold yellow] {msg}")
        console.print(f"[dim]Retained {count} cached/bundled KEV records.[/dim]")


@threat_intel_group.command("search")
@click.argument("query", required=True)
@click.option("--json-out", is_flag=True, default=False, help="Output raw JSON results.")
def threat_intel_search_cmd(query: str, json_out: bool):
    """Search CISA KEV active exploits by vendor or product name."""
    from expose.intelligence.threat_intel import get_threat_intel
    store = get_threat_intel()
    results = store.search_by_product(query)

    if json_out:
        click.echo(json.dumps([r.model_dump() for r in results], indent=2))
    else:
        formatter.print_banner()
        console.print(f"[bold cyan]CISA KEV Exploits matching '{query}' ({len(results)}):[/bold cyan]\n")
        for r in results[:10]:
            console.print(f"[bold red]{r.cve_id}[/bold red] - [white]{r.vendor_project} {r.product}[/white]: {r.vulnerability_name}")
            console.print(f"  [dim]Added: {r.date_added} | Remediation Deadline: {r.due_date} | Ransomware: {r.known_ransomware_campaign_use}[/dim]")
            console.print(f"  [yellow]Required Action:[/yellow] {r.required_action}\n")


@cli.group("queue")
def queue_group():
    """Distributed task queue fleet management."""
    pass


@queue_group.command("status")
def queue_status_cmd():
    """Display distributed queue health metrics."""
    from expose.core.queue import get_task_queue
    queue = get_task_queue()
    stats = asyncio.run(queue.get_stats())
    formatter.print_banner()
    console.print("[bold cyan]Distributed Scan Task Queue Status:[/bold cyan]\n")
    console.print(f"  Queued:      [bold yellow]{stats.queued_count}[/bold yellow]")
    console.print(f"  Leased:      [bold cyan]{stats.leased_count}[/bold cyan]")
    console.print(f"  Completed:   [bold green]{stats.completed_count}[/bold green]")
    console.print(f"  Failed:      [bold red]{stats.failed_count}[/bold red]")
    console.print(f"  Dead Letter: [bold magenta]{stats.dead_letter_count}[/bold magenta]\n")


if __name__ == "__main__":
    cli()

