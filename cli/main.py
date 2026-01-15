import click
import json
import sys
from core.engine import IronEngine
from core.config import config
from core.logger import logger
from core.error_handler import handle_exception
from risk.scorer import RiskScorer
from topology.graph_builder import TopologyMapper
from discovery.active import ActiveDiscovery
from discovery.passive import PassiveDiscovery
from core.database import AssetDatabase
from reporting.generator import ReportGenerator

@click.group()
@click.version_option(version="0.1.0")
@click.option("--debug", is_flag=True, help="Enable debug logging")
def cli(debug):
    """IRONFLOW - Enterprise OT/ICS Security Analysis Platform"""
    if debug:
        import logging
        from core.logger import setup_logger
        setup_logger(level=logging.DEBUG)
    
    # Initialize engine early if needed, or pass via context
    pass

@cli.command()
@click.option("--target", required=True, help="Target IP or CIDR")
@click.option("--protocol", type=click.Choice(["modbus", "s7", "dnp3", "bacnet", "ethernetip", "iec104", "opcua", "all"]), default="all")
@click.option("--dangerous", is_flag=True, help="Disable SAFE_MODE (Allows write operations)")
@click.option("--no-db", is_flag=True, help="Skip saving to local database")
@click.option("--report", is_flag=True, help="Generate HTML report")
def scan(target, protocol, dangerous, no_db, report):
    """Scan targets for ICS protocols and assets"""
    if dangerous:
        if click.confirm("⚠️ WARNING: Dangerous mode will disable safety guards. Are you sure?", abort=True):
            config.disable_safe_mode()

    engine = IronEngine()
    engine.discover_plugins(package_paths=["ironflow.plugins", "ironflow.protocols"])
    
    active = ActiveDiscovery(engine)
    protocols = None if protocol == "all" else [protocol]
    
    results = active.scan_network(target, protocols)
    
    # Enrichment: Run risk assessment on each result
    scorer = RiskScorer()
    db = None if no_db else AssetDatabase()
    
    for res in results:
        assessment = scorer.calculate_risk([res])
        res["risk"] = assessment
        if db:
            db.save_asset(res["target"], res)
            
    # Output results
    if results:
        click.echo(json.dumps(results, indent=2))
        if report:
            rep_gen = ReportGenerator()
            rep_gen.generate_html({"results": results})
            rep_gen.generate_json({"results": results})
    else:
        logger.warning("No assets identified.")

@cli.command()
@click.option("--pcap", required=True, type=click.Path(exists=True), help="PCAP file to analyze")
@click.option("--report", is_flag=True, help="Generate HTML report")
def analyze(pcap, report):
    """Analyze PCAP file for ICS traffic (Passive Discovery)"""
    passive = PassiveDiscovery()
    results = passive.analyze_pcap(pcap)
    
    if results:
        click.echo(json.dumps(results, indent=2))
        if report:
            rep_gen = ReportGenerator()
            rep_gen.generate_html({"results": results})
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
    for protocol in protocols:
        res = engine.run_plugin(protocol, target)
        if res and res.get("online"):
            findings.append(res)
            
    scorer = RiskScorer()
    assessment = scorer.calculate_risk(findings)
    
    click.echo(f"Risk Assessment for {target}:")
    click.echo(f"Score: {assessment['score']}/10.0")
    click.echo(f"Severity: {assessment['severity']}")
    click.echo("\nApplied Rules:")
    for rule in assessment['applied_rules']:
        click.echo(f" - [{rule['id']}] {rule['name']}: {rule['description']}")

@cli.command()
@click.option("--target", required=True, help="Target network to map")
@click.option("--export", type=click.Path(), help="Path to export JSON topology")
def topology(target, export):
    """Map network topology based on active discovery"""
    engine = IronEngine()
    engine.discover_plugins(package_paths=["ironflow.plugins", "ironflow.protocols"])
    
    # Simulate scanning a small range or just the target
    findings = []
    protocols = ["modbus", "s7", "dnp3", "bacnet", "ethernetip", "iec104", "opcua"]
    for protocol in protocols:
        res = engine.run_plugin(protocol, target)
        if res and res.get("online"):
            findings.append(res)
            
    mapper = TopologyMapper()
    graph = mapper.build_graph(findings)
    
    if export:
        mapper.export_json(graph, export)
    else:
        click.echo(json.dumps(graph, indent=2))

if __name__ == "__main__":
    try:
        cli()
    except Exception as e:
        handle_exception(e)
