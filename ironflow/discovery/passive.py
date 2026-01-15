from typing import List, Dict, Any
from scapy.all import rdpcap, IP, TCP
from ironflow.core.logger import logger

class PassiveDiscovery:
    """
    Passive discovery using PCAP analysis via Scapy.
    """

    def __init__(self):
        self.port_map = {
            502: "Modbus",
            102: "S7Comm",
            20000: "DNP3"
        }

    def analyze_pcap(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Analyze a PCAP/PCAPNG file for OT protocols based on common ports.
        """
        logger.info(f"Analyzing {file_path} for OT traffic...")
        findings = {}

        try:
            packets = rdpcap(file_path)
            for pkt in packets:
                if IP in pkt and TCP in pkt:
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    
                    for port, proto in self.port_map.items():
                        if sport == port or dport == port:
                            target_ip = dst_ip if dport == port else src_ip
                            if target_ip not in findings:
                                findings[target_ip] = {
                                    "target": target_ip,
                                    "protocol": proto,
                                    "source": "passive",
                                    "online": True,
                                    "details": {"identified_via": "port_analysis"}
                                }
        except Exception as e:
            logger.error(f"Error during PCAP analysis: {e}")
            
        return list(findings.values())
