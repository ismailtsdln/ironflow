# IRONFLOW

**Enterprise-grade OT/ICS Security Analysis Platform**

## Overview

**IRONFLOW** is a safe-by-design, modular security assessment framework designed specifically for industrial control systems (ICS) and operational technology (OT) environments. It provides deep visibility, risk assessment, and protocol analysis while prioritizing the operational availability and safety of the target environment.

> [!IMPORTANT]
> **Safety First**: IRONFLOW operates in **read-only SAFE MODE** by default. No data is written to the network (other than standard TCP handshakes) and no state-changing commands are sent unless explicitly overridden by the operator.

## Features

- **Multi-protocol ICS Discovery**: Securely identify assets speaking Modbus, S7Comm, and DNP3.
- **Passive & Active Scanning**: Hybrid approach using PCAP analysis and benign active queries.
- **Risk Scoring Engine**: Custom OT-aware risk calculation (not just generic CVSS).
- **Topology Mapping**: Visualize network flows and device relationships.
- **Offline Analysis**: Analyze captured traffic without touching the live network.
- **Safe-by-Design**: Strict safeguards against accidental intrusive actions.
- **Enterprise Ready**: JSON reporting, extensive logging, and integration friendly.

## Installation

```bash
# Clone the repository
git clone https://github.com/ismailtsdln/ironflow.git
cd ironflow

# Install dependencies
pip install -r requirements.txt

# Run the tool
python3 -m ironflow.cli.main --help
```

## Usage

### Basic Asset Scan (Safe Mode)

```bash
ironflow scan --target 192.168.1.0/24 --protocol modbus
```

### Risk Analysis from PCAP

```bash
ironflow analyze --pcap /path/to/capture.pcap --export report.json
```

### Risk Assessment

```bash
ironflow risk --target 192.168.1.10
```

## Architecture

IRONFLOW is built on a modular plugin architecture to ensure extensibility and stability.

- **Core**: Manages configuration, safety state, and plugin orchestration.
- **Protocols**: Independent modules for each ICS protocol (Modbus, S7, DNP3).
- **Discovery**: Modules for passive and safe-active discovery.
- **Risk**: Engine for calculating risk scores based on asset exposure and posture.
- **Plugins**: Extensible interface for adding new capabilities.

## Safety & Legal Disclaimer

**Authorized Use Only.**

This tool is designed for defensive security purposes, such as audits, vulnerability assessments, and blue team operations.

- **Do not use this tool on networks you do not own or have explicit permission to test.**
- **The authors are not responsible for any damage, downtime, or legal consequences resulting from the misuse of this tool.**
- **Always verify the safety of active scanning in your specific OT environment before execution.**

## Contributing

Contributions are welcome! Please ensure all code adheres to the safety-first philosophy and passes the test suite.

## License

MIT License - See LICENSE for details.
