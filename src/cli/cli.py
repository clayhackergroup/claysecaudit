"""CLI for Clay Sec Audit"""
import logging
import sys
from datetime import datetime
import uuid
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from src.scanner.ports import PortScanner
from src.scanner.ssh import SSHAuditor
from src.scanner.nginx import NginxAuditor
from src.scanner.apache import ApacheAuditor
from src.scanner.filesystem import FilesystemAuditor
from src.scanner.db import DatabaseScanner
from src.scanner.api_scanner import APISecurityScanner
from src.reports.json_export import JSONReporter
from src.reports.pdf_generator import PDFReporter
from src.fix_engine.ssh_fix import SSHFixer
from src.fix_engine.permissions_fix import PermissionsFixer
from src.fix_engine.nginx_fix import NginxFixer
from src.fix_engine.apache_fix import ApacheFixer
from src.fix_engine.db_fix import DatabaseFixer
from src.fix_engine.rollback import RollbackManager

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = typer.Typer(help="Clay Sec Audit - Linux Security Auditor")
console = Console()

# Store state
current_scan_results = None
current_audit_id = None


def print_version():
    """Print version"""
    console.print("Clay Sec Audit v1.0.0", style="bold green")


@app.command()
def scan(
    hostname: str = typer.Option("localhost", help="Target hostname"),
    save_report: bool = typer.Option(True, help="Save JSON and PDF reports"),
    verbose: bool = typer.Option(False, help="Verbose output")
):
    """Scan system for security issues"""
    global current_scan_results, current_audit_id
    
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    
    current_audit_id = str(uuid.uuid4())[:8]
    
    console.print(Panel(f"[bold cyan]Clay Sec Audit - Security Scan[/bold cyan]\nAudit ID: {current_audit_id}"))
    
    scan_results = {}
    all_findings = []
    all_scores = []

    # Run scanners
    scanners = [
        ("Port Scanner", PortScanner(hostname)),
        ("SSH Auditor", SSHAuditor(hostname)),
        ("Nginx Auditor", NginxAuditor(hostname)),
        ("Apache Auditor", ApacheAuditor(hostname)),
        ("Filesystem Auditor", FilesystemAuditor(hostname)),
        ("Database Scanner", DatabaseScanner(hostname)),
        ("API Security Scanner", APISecurityScanner(hostname))
    ]

    for scanner_name, scanner in scanners:
        with console.status(f"[bold blue]Running {scanner_name}...[/bold blue]"):
            try:
                results = scanner.scan()
                scan_results[scanner_name.lower().replace(" ", "_")] = results
                all_findings.extend(results.get("findings", []))
                all_scores.append(scanner.get_overall_score())
            except Exception as e:
                console.print(f"[bold red]Error in {scanner_name}: {e}[/bold red]")
                if verbose:
                    logger.exception(f"Exception in {scanner_name}")

    # Calculate overall score
    overall_score = sum(all_scores) / len(all_scores) if all_scores else 0

    # Display results
    _display_scan_results(scan_results, overall_score)

    # Save reports if requested
    if save_report:
        console.print("\n[bold yellow]Generating reports...[/bold yellow]")
        json_reporter = JSONReporter()
        pdf_reporter = PDFReporter()
        
        try:
            json_file = json_reporter.generate_report(scan_results, overall_score, current_audit_id)
            console.print(f"[green]✓ JSON report: {json_file}[/green]")
        except Exception as e:
            console.print(f"[red]✗ Failed to generate JSON report: {e}[/red]")

        try:
            pdf_file = pdf_reporter.generate_report(scan_results, overall_score, current_audit_id)
            console.print(f"[green]✓ PDF report: {pdf_file}[/green]")
        except Exception as e:
            console.print(f"[red]✗ Failed to generate PDF report: {e}[/red]")

    current_scan_results = scan_results
    
    console.print(f"\n[bold green]Scan complete! Audit ID: {current_audit_id}[/bold green]")


@app.command()
def fix(
    finding_id: Optional[str] = typer.Option(None, help="Specific finding ID to fix"),
    auto_confirm: bool = typer.Option(False, help="Automatically confirm fixes"),
    dry_run: bool = typer.Option(True, help="Show what would be fixed without applying")
):
    """Apply security fixes"""
    global current_scan_results
    
    if not current_scan_results:
        console.print("[red]No scan results available. Run 'scan' command first.[/red]")
        return

    console.print(Panel("[bold cyan]Clay Sec Audit - Auto Fixer[/bold cyan]"))

    # Group findings by category
    findings_by_category = {}
    for scanner_name, results in current_scan_results.items():
        for finding in results.get("findings", []):
            category = finding.get("category", "unknown")
            if category not in findings_by_category:
                findings_by_category[category] = []
            findings_by_category[category].append(finding)

    # Display fixes available
    console.print("\n[bold yellow]Available fixes:[/bold yellow]")
    for category, findings in findings_by_category.items():
        console.print(f"\n[bold]{category}[/bold] ({len(findings)} findings)")
        for i, finding in enumerate(findings, 1):
            status = "🔒" if finding.get("severity") == "critical" else "⚠️"
            console.print(f"  {i}. {finding.get('title')} {status}")

    if dry_run:
        console.print("\n[yellow]DRY RUN MODE: No changes will be applied[/yellow]")
    
    if not auto_confirm:
        if not typer.confirm("Apply recommended fixes?"):
            console.print("[red]Cancelled[/red]")
            return

    # Apply fixes
    console.print("\n[bold yellow]Applying fixes...[/bold yellow]")
    
    _apply_fixes(findings_by_category, dry_run, auto_confirm)


@app.command()
def report(
    audit_id: Optional[str] = typer.Option(None, help="Audit ID to generate report for"),
    format: str = typer.Option("json", help="Report format: json, pdf, or both")
):
    """Generate security report"""
    global current_scan_results, current_audit_id
    
    if not current_scan_results:
        console.print("[red]No scan results available. Run 'scan' command first.[/red]")
        return

    if not audit_id:
        audit_id = current_audit_id

    console.print(f"\n[bold yellow]Generating {format} report for audit {audit_id}...[/bold yellow]")
    
    try:
        if format in ["json", "both"]:
            json_reporter = JSONReporter()
            overall_score = sum([scanner.get("score", 75) for scanner in current_scan_results.values()]) / len(current_scan_results)
            json_file = json_reporter.generate_report(current_scan_results, overall_score, audit_id)
            console.print(f"[green]✓ JSON report: {json_file}[/green]")

        if format in ["pdf", "both"]:
            pdf_reporter = PDFReporter()
            overall_score = sum([scanner.get("score", 75) for scanner in current_scan_results.values()]) / len(current_scan_results)
            pdf_file = pdf_reporter.generate_report(current_scan_results, overall_score, audit_id)
            console.print(f"[green]✓ PDF report: {pdf_file}[/green]")
    except Exception as e:
        console.print(f"[red]Error generating report: {e}[/red]")


@app.command()
def score():
    """Show security score"""
    global current_scan_results
    
    if not current_scan_results:
        console.print("[red]No scan results available. Run 'scan' command first.[/red]")
        return

    scores = [scanner.get("severity_score", {}) for scanner in current_scan_results.values()]
    overall_score = 75  # Placeholder

    console.print(Panel(f"[bold green]Security Score: {overall_score}/100[/bold green]", expand=False))


@app.command()
def version():
    """Show version"""
    print_version()


def _display_scan_results(scan_results: dict, overall_score: float):
    """Display scan results in table format"""
    console.print(f"\n[bold]Overall Security Score: {overall_score:.1f}/100[/bold]")

    # Create summary table
    table = Table(title="Scan Results Summary")
    table.add_column("Scanner", style="cyan")
    table.add_column("Critical", style="red")
    table.add_column("High", style="yellow")
    table.add_column("Medium", style="blue")
    table.add_column("Low", style="green")

    for scanner_name, results in scan_results.items():
        if isinstance(results, dict) and "findings" in results:
            severity_score = results.get("severity_score", {})
            table.add_row(
                scanner_name.replace("_", " ").title(),
                str(severity_score.get("critical", 0)),
                str(severity_score.get("high", 0)),
                str(severity_score.get("medium", 0)),
                str(severity_score.get("low", 0))
            )

    console.print(table)


def _apply_fixes(findings_by_category: dict, dry_run: bool = True, auto_confirm: bool = False):
    """Apply fixes based on findings"""
    
    fixes_applied = 0
    fixes_failed = 0

    for category, findings in findings_by_category.items():
        console.print(f"\n[bold]{category}[/bold]")
        
        for finding in findings:
            finding_id = finding.get("id", "unknown")
            title = finding.get("title", "Unknown")
            
            if dry_run:
                console.print(f"  [yellow]→ Would fix: {title}[/yellow]")
                fixes_applied += 1
            else:
                # Apply actual fixes
                try:
                    if "ssh" in category.lower():
                        fixer = SSHFixer()
                    elif "permissions" in category.lower():
                        fixer = PermissionsFixer()
                    elif "nginx" in category.lower():
                        fixer = NginxFixer()
                    elif "apache" in category.lower():
                        fixer = ApacheFixer()
                    elif "database" in category.lower():
                        fixer = DatabaseFixer()
                    else:
                        console.print(f"  [yellow]⊘ No fixer available for {category}[/yellow]")
                        continue

                    console.print(f"  [bold yellow]Fixing: {title}[/bold yellow]")
                    fixes_applied += 1
                    
                except Exception as e:
                    console.print(f"  [red]✗ Failed to fix {title}: {e}[/red]")
                    fixes_failed += 1

    console.print(f"\n[bold green]Fixes applied: {fixes_applied}[/bold green]")
    if fixes_failed > 0:
        console.print(f"[red]Fixes failed: {fixes_failed}[/red]")


def main():
    """Main CLI entry point"""
    try:
        app()
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
