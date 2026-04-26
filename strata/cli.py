"""CLI entrypoint for strata."""
from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(asctime)s %(name)s %(levelname)s %(message)s")


@click.group()
@click.version_option("0.1.0", prog_name="strata")
def main():
    """
    STRATA — Active Directory Auditing.

    Read-only Kerberos GSSAPI connection. Runs 87 security checks across
    8 categories, scores the forest 0-100, and produces an HTML report with
    a prioritised Remediation Roadmap and PowerShell remediation scripts.
    Tracks results over time for trend analysis.

    \b
    Prerequisites:
      - Valid Kerberos TGT: kinit user@DOMAIN.COM
      - LDAPS reachable (port 636) or use --no-ssl for lab
    """


# ---------------------------------------------------------------------------
# tui
# ---------------------------------------------------------------------------

@main.command()
@click.option("--dc", "dc_host", default=None, help="DC hostname (prompted in TUI if omitted).")
@click.option("--no-ssl", is_flag=True)
@click.option("--no-verify-ssl", is_flag=True)
@click.option("--principal", "-p", default=None)
@click.option("--verbose", "-v", is_flag=True)
def tui(dc_host, no_ssl, no_verify_ssl, principal, verbose):
    """Launch the interactive TUI."""
    _setup_logging(verbose)
    from .tui.app import run_tui
    run_tui(
        dc_host=dc_host,
        use_ssl=not no_ssl,
        verify_ssl=not no_verify_ssl,
        kerberos_principal=principal,
        results_root=Path.cwd() / "results",
    )


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@main.command()
@click.argument("dc_host")
@click.option("--principal", "-p", default=None, help="Kerberos UPN (default: ticket cache).")
@click.option("--no-ssl", is_flag=True, help="Use plain LDAP port 389 (lab only).")
@click.option("--no-verify-ssl", is_flag=True, help="Skip TLS cert verification (self-signed certs).")
@click.option("--verbose", "-v", is_flag=True)
def scan(dc_host, principal, no_ssl, no_verify_ssl, verbose):
    """
    Run a headless scan and write results to results/<forest>_<timestamp>/.

    \b
    Examples:
      strata scan dc01.contoso.com
      strata scan dc01.corp.local --no-ssl --verbose
      strata scan dc01.contoso.com --principal admin@CONTOSO.COM
    """
    _setup_logging(verbose)
    use_ssl = not no_ssl
    verify_ssl = not no_verify_ssl

    from .collector.connection import LDAPConnectionError, ldap_connect
    from .collector.forest import discover_domains
    from .collector.checks import (
        accounts, acls, certificates, delegation, gpo, infrastructure, passwords, trusts,
    )
    from .models import Snapshot
    from .scoring import compute_score
    from .trend import save_snapshot
    from .reporter.html import generate_html_report
    from .reporter.log import write_scan_log
    from .reporter.ps import write_ps_scripts
    from .log_capture import capture_scan_log

    console.print(f"[bold cyan]STRATA[/bold cyan] — Connecting to [bold]{dc_host}[/bold]")

    def _prog(msg: str):
        console.print(f"  [dim]{msg}[/dim]")

    captured_log: list = []
    try:
        with capture_scan_log() as captured_log:
            _prog("Discovering forest topology...")
            with ldap_connect(dc_host, use_ssl=use_ssl, verify_ssl=verify_ssl, kerberos_principal=principal) as conn:
                domains = discover_domains(conn)

            forest_root = domains[0].forest if domains else dc_host
            console.print(f"  Forest: [bold]{forest_root}[/bold]  |  {len(domains)} domain(s)")

            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_forest = forest_root.replace(".", "_")
            # Always write under the project root (parent of the hardening package), not cwd
            project_root = Path(__file__).resolve().parent.parent
            results_dir = project_root / "results" / f"{safe_forest}_{ts}"
            results_dir.mkdir(parents=True, exist_ok=True)

            all_results = []
            check_modules = [accounts, delegation, passwords, trusts, acls, gpo, infrastructure, certificates]

            for domain in domains:
                _prog(f"Scanning {domain.name} via {domain.dc_hostname}...")
                try:
                    with ldap_connect(domain.dc_hostname, use_ssl=use_ssl, verify_ssl=verify_ssl, kerberos_principal=principal) as conn:
                        for mod in check_modules:
                            try:
                                results = mod.run_checks(conn, domain, use_ssl, verify_ssl, principal)
                                all_results.extend(results)
                                passed = sum(1 for r in results if r.passed)
                                _prog(f"  [{mod.__name__.split('.')[-1]}] {passed}/{len(results)} checks passed")
                            except Exception as exc:
                                logging.getLogger("strata.cli").warning("Check module %s failed: %s", mod.__name__, exc)
                                console.print(f"  [yellow]Warning:[/yellow] {mod.__name__.split('.')[-1]} failed: {exc}")
                except LDAPConnectionError as exc:
                    logging.getLogger("strata.cli").error("Connection failed for %s: %s", domain.name, exc)
                    console.print(f"  [red]Connection failed for {domain.name}:[/red] {exc}")

            score, band = compute_score(all_results)
            snapshot = Snapshot(
                timestamp=datetime.now(),
                forest_root=forest_root,
                domains=domains,
                results=all_results,
                score=score,
                score_band=band,
            )

    except Exception as exc:
        console.print(f"[bold red]ERROR:[/bold red] {exc}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    _print_summary(snapshot)

    snap_path = results_dir / "snapshot.json"
    save_snapshot(snapshot, snap_path)

    log_path = results_dir / "scan.log"
    write_scan_log(snapshot, log_path, trace=captured_log)

    html_path = results_dir / "report.html"
    generate_html_report(snapshot, html_path)

    ps_path = results_dir / "ps"
    write_ps_scripts(snapshot, ps_path)

    console.print(f"\n[green]Results:[/green]     {results_dir.resolve()}/")
    console.print(f"[green]HTML report:[/green] {html_path.resolve()}")
    console.print(f"[green]PS scripts:[/green]  {ps_path.resolve()}/")
    console.print(f"[green]Snapshot:[/green]    {snap_path.resolve()}")
    console.print(f"[green]Log:[/green]         {log_path.resolve()}")


# ---------------------------------------------------------------------------
# compare
# ---------------------------------------------------------------------------

@main.command()
@click.argument("snapshot_a", type=click.Path(exists=True))
@click.argument("snapshot_b", type=click.Path(exists=True))
def compare(snapshot_a, snapshot_b):
    """Compare two snapshot.json files and show what changed."""
    from .trend import load_snapshot, compare_snapshots

    old = load_snapshot(Path(snapshot_a))
    new = load_snapshot(Path(snapshot_b))
    trend = compare_snapshots(old, new)

    delta_color = "green" if trend.score_delta >= 0 else "red"
    delta_str = f"+{trend.score_delta}" if trend.score_delta >= 0 else str(trend.score_delta)

    console.print(f"\n[bold]Score:[/bold] {old.score} ({old.score_band}) → {new.score} ({new.score_band})  "
                  f"[{delta_color}]{delta_str}[/{delta_color}]")

    if trend.mitigated:
        console.print(f"\n[green]Mitigated ({len(trend.mitigated)}):[/green]")
        for r in trend.mitigated:
            console.print(f"  [green]✓[/green] {r.check_id} — {r.name} ({r.domain})")

    if trend.new_failures:
        console.print(f"\n[red]New failures ({len(trend.new_failures)}):[/red]")
        for r in trend.new_failures:
            console.print(f"  [red]✗[/red] {r.check_id} — {r.name} ({r.domain})")

    if trend.still_failing:
        console.print(f"\n[yellow]Still failing ({len(trend.still_failing)}):[/yellow]")
        for r in trend.still_failing:
            console.print(f"  [yellow]·[/yellow] {r.check_id} — {r.name} ({r.domain})")

    console.print(f"\n[dim]Still passing: {len(trend.still_passing)}[/dim]")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _print_summary(snapshot) -> None:
    from .models import Severity, Category, CATEGORY_LABELS
    from .scoring import score_color

    score_hex = score_color(snapshot.score)
    console.print(f"\n[bold]Score: {snapshot.score}/100[/bold] — {snapshot.score_band}")

    sev_counts: dict = {}
    for f in snapshot.findings():
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

    sev_styles = {
        Severity.CRITICAL: "red", Severity.HIGH: "dark_orange",
        Severity.MEDIUM: "yellow", Severity.LOW: "green", Severity.INFO: "dim",
    }
    table = Table(title="Findings by Severity", show_header=True, header_style="bold")
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        count = sev_counts.get(sev, 0)
        if count:
            table.add_row(Text(sev.value.upper(), style=sev_styles[sev]), str(count))
    console.print(table)

    cat_table = Table(title="Category Summary", show_header=True, header_style="bold")
    cat_table.add_column("Category")
    cat_table.add_column("Passed", justify="right")
    cat_table.add_column("Total", justify="right")
    for cat in Category:
        passed, total = snapshot.category_score(cat)
        if total:
            style = "green" if passed == total else ("red" if passed < total // 2 else "yellow")
            cat_table.add_row(Text(CATEGORY_LABELS[cat], style=style), str(passed), str(total))
    console.print(cat_table)

    console.print(f"\n[bold]{len(snapshot.findings())}[/bold] findings across {len(snapshot.results)} checks.")
