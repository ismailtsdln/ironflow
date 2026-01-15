# 🛡️ IRONFLOW

**Next-Generation Enterprise OT/ICS Security Analysis & Asset Discovery Platform**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10+-brightgreen.svg)](https://www.python.org/)
[![Safety: Default ON](https://img.shields.io/badge/Safety-Default_ON-red.svg)](#safety--legal-disclaimer)

---

## 🚀 Overview

**IRONFLOW** is a production-grade, modular security assessment framework engineered for sensitive Industrial Control Systems (ICS) and Operational Technology (OT). It provides critical visibility, risk quantification, and deep protocol dissection without compromising operational safety or reliability.

> [!IMPORTANT]
> **Safety-by-Design**: IRONFLOW operates in a non-intrusive **SAFE MODE** by default. It utilizes benign protocol handshakes and read-only operations to ensure zero impact on industrial processes.

---

## ✨ Key Features

- **🌐 Comprehensive OT Support**: Native dissection for 7+ protocols (Modbus, S7, DNP3, BACnet, EtherNet/IP, IEC-104, OPC UA).
- **🔍 Hybrid Discovery**: Combined real-time passive PCAP analysis and safe active fingerprinting.
- **📊 OT-Aware Risk Engine**: Sophisticated scoring based on industrial exposure and configuration posture.
- **🗺️ Topology Intelligence**: Automatic mapping of industrial network relationships and protocol flows.
- **🎨 Premium UX**: Modern CLI interface powered by `rich` with colorized tables, progress tracking, and branding.
- **💼 Enterprise Reporting**: High-fidelity HTML and JSON reports for stakeholders and CI/CD integration.

---

## 🛠️ Installation

```bash
# Clone the enterprise repository
git clone https://github.com/ismailtsdln/ironflow.git
cd ironflow

# Set up a clean environment
python3 -m venv venv
source venv/bin/activate

# Install production dependencies
pip install -r requirements.txt
```

---

## 📖 Usage

IRONFLOW is invoked as a standard Python module for maximum portability:

### 📡 Network Asset Discovery
```bash
python3 -m ironflow scan --target 192.168.1.0/24 --report
```

### 📦 Passive Traffic Analysis
```bash
python3 -m ironflow analyze --pcap captures/plant_floor.pcap --report
```

### ⚖️ Rapid Risk Assessment
```bash
python3 -m ironflow risk --target 192.168.1.50
```

### 🗺️ Topology Mapping
```bash
python3 -m ironflow topology --target 192.168.1.0/24 --export network_map.json
```

---

## 🏗️ Architecture

IRONFLOW follows a strictly modular architecture to enable safe expansion:

- **`ironflow.core`**: Safety guards, plugin orchestration, and persistence logic.
- **`ironflow.protocols`**: Isolated protocol engines for safe identification.
- **`ironflow.discovery`**: Orchestration for both active network sweeps and passive capture analysis.
- **`ironflow.risk`**: YAML-driven risk scoring rules and calculation engine.
- **`ironflow.reporting`**: Template-based generator for HTML/JSON security audits.

---

## 🛡️ Safety & Legal Disclaimer

**AUTHORIZED USE ONLY.**

Industrial environments are fragile. IRONFLOW is designed for defensive auditing, blue-teaming, and posture management.

- **Permission**: Ensure you have explicit, written authorization before scanning any OT network.
- **Liability**: The developers assume no responsibility for downtime or damages resulting from improper configuration or use.
- **Warning**: Always use `--dangerous` with extreme caution in production environments.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---
*Developed with focus on Industrial Resilience.*
