import click
import json
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

from ironflow.core.engine import IronEngine
from ironflow.core.config import config
from ironflow.core.logger import logger, print_banner, console
from ironflow.core.error_handler import handle_exception
from ironflow.risk.scorer import RiskScorer
from ironflow.topology.graph_builder import TopologyMapper
from ironflow.discovery.active import ActiveDiscovery
from ironflow.discovery.passive import PassiveDiscovery
from ironflow.core.database import AssetDatabase
from ironflow.reporting.generator import ReportGenerator

@click.group()
@click.version_option(version="0.1.0")
@click.option("--debug", is_flag=True, help="Enable debug logging")
def cli(debug):
    """IRONFLOW - Enterprise OT/ICS Security Analysis Platform"""
    if debug:
        import logging
        from ironflow.core.logger import setup_logger
        setup_logger(level=logging.DEBUG)
    
    # Print the premium banner on start
    print_banner()

@cli.command()
@click.option("--target", required=True, help="Target IP or CIDR")
@click.option("--protocol", type=click.Choice(["modbus", "s7", "dnp3", "bacnet", "ethernetip", "iec104", "opcua", "all"]), default="all")
@click.option("--dangerous", is_flag=True, help="Disable SAFE_MODE (Allows write operations)")
@click.option("--no-db", is_flag=True, help="Skip saving to local database")
@click.option("--report", is_flag=True, help="Generate HTML report")
def scan(target, protocol, dangerous, no_db, report):
    """Scan targets for ICS protocols and assets"""
    if dangerous:
        if click.confirm("⚠️ [bold red]WARNING:[/] Dangerous mode will disable safety guards. Are you sure?", abort=True):
            config.disable_safe_mode()

    engine = IronEngine()
    engine.discover_plugins(package_paths=["ironflow.plugins", "ironflow.protocols"])
    
    active = ActiveDiscovery(engine)
    protocols = None if protocol == "all" else [protocol]
    
    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        progress.add_task(description=f"Scanning {target}...", total=None)
        results = active.scan_network(target, protocols)
    
    # Enrichment: Run risk assessment on each result
    scorer = RiskScorer()
    db = None if no_db else AssetDatabase()
    
    table = Table(title=f"Scan Results for {target}", box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Target", style="cyan")
    table.add_column("Protocol", style="green")
    table.add_column("Risk Score", justify="right")
    table.add_column("Severity", justify="center")
    
    for res in results:
        assessment = scorer.calculate_risk([res])
        res["risk"] = assessment
        if db:
            db.save_asset(res["target"], res)
        
        severity_style = "bold red" if assessment["severity"] == "High" else "yellow" if assessment["severity"] == "Medium" else "green"
        table.add_row(
            res["target"],
            res["protocol"],
            str(assessment["score"]),
            f"[{severity_style}]{assessment['severity']}[/]"
        )
            
    if results:
        console.print(table)
        if report:
            rep_gen = ReportGenerator()
            rep_gen.generate_html({"results": results})
            rep_gen.generate_json({"results": results})
            console.print(f"\n[bold green]✓[/] Reports generated successfully.")
    else:
        logger.warning("No assets identified.")

@cli.command()
@click.option("--pcap", required=True, type=click.Path(exists=True), help="PCAP file to analyze")
@click.option("--report", is_flag=True, help="Generate HTML report")
def analyze(pcap, report):
    """Analyze PCAP file for ICS traffic (Passive Discovery)"""
    passive = PassiveDiscovery()
    
    with console.status(f"[bold green]Analyzing {pcap}...") as status:
        results = passive.analyze_pcap(pcap)
    
    if results:
        table = Table(title="Passive Analysis Findings", box=box.ROUNDED)
        table.add_column("Target", style="cyan")
        table.add_column("Protocol", style="magenta")
        table.add_column("Source", style="dim")
        
        for res in results:
            table.add_row(res["target"], res["protocol"], res["source"])
            
        console.print(table)
        if report:
            rep_gen = ReportGenerator()
            rep_gen.generate_html({"results": results})
            console.print(f"\n[bold green]✓[/] HTML Report generated.")
    else:
        logger.warning("No ICS traffic identified in PCAP.")

@cli.command()
@click.option("--target", required=True, help="Target IP or CIDR to assess")
def risk(target):
    """Assess risk level for a specific target"""
    engine = IronEngine()
    engine.discover_plugins(package_paths=["ironflow.plugins", "ironflow.protocols"])
    
    findings = []
    protocols = ["modbus", "s7", "dnp3", "bacnet", "ethernetip", "iec104", "opcua"]
    
    with console.status(f"[bold yellow]Performing risk assessment on {target}...") as status:
        for protocol in protocols:
            res = engine.run_plugin(protocol, target)
            if res and res.get("online"):
                findings.append(res)
            
    scorer = RiskScorer()
    assessment = scorer.calculate_risk(findings)
    
    severity_style = "bold red" if assessment["severity"] == "High" else "yellow" if assessment["severity"] == "Medium" else "green"
    
    risk_summary = f"[bold]Score:[/] {assessment['score']}/10.0\n[bold]Severity:[/] [{severity_style}]{assessment['severity']}[/]\n\n[bold]Applied Rules:[/]"
    for rule in assessment['applied_rules']:
        risk_summary += f"\n • {rule['name']} ([dim]{rule['id']}[/])"

    console.print(Panel(
        risk_summary,
        title=f"Risk Assessment: {target}",
        border_style=severity_style,
        box=box.DOUBLE
    ))

@cli.command()
@click.option("--target", required=True, help="Target network to map")
@click.option("--export", type=click.Path(), help="Path to export JSON topology")
def topology(target, export):
    """Map network topology based on active discovery"""
    engine = IronEngine()
    engine.discover_plugins(package_paths=["ironflow.plugins", "ironflow.protocols"])
    
    findings = []
    protocols = ["modbus", "s7", "dnp3", "bacnet", "ethernetip", "iec104", "opcua"]
    
    with console.status(f"[bold cyan]Mapping topology for {target}...") as status:
        for protocol in protocols:
            res = engine.run_plugin(protocol, target)
            if res and res.get("online"):
                findings.append(res)
            
    mapper = TopologyMapper()
    graph = mapper.build_graph(findings)
    
    if export:
        mapper.export_json(graph, export)
        console.print(f"[bold green]✓[/] Topology exported to {export}")
    else:
        console.print(Panel(json.dumps(graph, indent=2), title="Network Topology Graph", border_style="cyan"))

if __name__ == "__main__":
    try:
        cli()
    except Exception as e:
        handle_exception(e)
