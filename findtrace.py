import asyncio
import click
import sys
import os
import json
import questionary
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.config import BANNER, BINARIES
from core.manager import InvestigationManager
from core.checker import get_missing_dependencies
from core.validators import is_valid_domain, detect_target_type
from core.scoring import GlobalScoringEngine

# Tools
from tools.dns_checker import get_dns_records
from tools.port_scanner import scan_ports
from tools.web_prober import probe_web
from tools.whois_parser import get_whois_info
from tools.ssl_history import get_ssl_history
from tools.sub_discovery import discover_subdomains

console = Console()

async def run_batch(domain: str, export: bool, abuse: bool):
    manager = InvestigationManager(domain)
    
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task1 = progress.add_task("[cyan]Scanning DNS, Ports, Web, WHOIS...", total=4)
        
        # Parallel Async Execution
        results = await asyncio.gather(
            get_dns_records(domain),
            scan_ports(domain),
            probe_web(domain),
            get_whois_info(domain)
        )
        
    manager.root.add_finding("dns", results[0], "DNS Records")
    manager.root.add_finding("ports", results[1], "Open Ports")
    manager.root.add_finding("web", results[2], "Web Probe")
    manager.root.add_finding("whois", results[3], "WHOIS Info")
    
    # Calculate Risk (FindTrace 2.0)
    findings_str = manager._get_all_findings_text()
    manager.scam_score, manager.observations = GlobalScoringEngine.calculate_risk(findings_str)
    
    # Simple report display
    console.print(Panel(f"[bold]Target:[/bold] {domain}\n[bold]Risk Score:[/bold] {manager.scam_score}/1000", title="Investigation Result"))
    for obs in manager.observations:
        console.print(f"[*] {obs}")
        
    if export:
        path = manager.export_report()
        console.print(f"[success]Report exported to {path}[/success]")

@click.command()
@click.argument('target', required=False)
@click.option('--batch', is_flag=True)
@click.option('--export', is_flag=True)
def main(target, batch, export):
    # Dependency Check
    missing = get_missing_dependencies(BINARIES)
    if missing:
        console.print(f"[bold red][!] Warning: Missing system dependencies: {', '.join(missing)}[/bold red]")
        console.print("[yellow][*] Some tools may not function correctly.[/yellow]\n")

    if not target:
        target = questionary.text("Target (Domain/IP/Email/Username):").ask()
    
    if not target: return

    # Universal Target Detection
    target_type = detect_target_type(target)
    console.print(f"[info][*] Auto-detected target type: [bold]{target_type}[/bold][/info]")

    if batch:
        asyncio.run(run_batch(target, export, False))
    else:
        manager = InvestigationManager(target, target_type)
        asyncio.run(manager.interactive_loop())

if __name__ == "__main__":
    console.print(BANNER)
    missing = get_missing_dependencies(BINARIES)
    if missing:
        console.print(f"[danger]Missing dependencies: {', '.join(missing)}[/danger]")
    main()
