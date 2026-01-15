import ipaddress
from typing import List, Dict, Any
from ironflow.core.engine import IronEngine
from ironflow.core.logger import logger

class ActiveDiscovery:
    """
    Orchestrates safe active discovery of ICS assets.
    """

    def __init__(self, engine: IronEngine):
        self.engine = engine

    def scan_network(self, target_range: str, protocols: List[str] = None) -> List[Dict[str, Any]]:
        """
        Scan a network CIDR or single IP for specified protocols.
        """
        if protocols is None:
            protocols = ["modbus", "s7", "dnp3", "bacnet", "ethernetip", "iec104", "opcua"]
            
        results = []
        
        try:
            targets = [str(ip) for ip in ipaddress.IPv4Network(target_range, strict=False)]
        except ValueError:
            # Fallback for single IP
            targets = [target_range]
            
        logger.info(f"Starting active discovery on {len(targets)} target(s)...")
        
        for target in targets:
            for protocol in protocols:
                res = self.engine.run_plugin(protocol, target)
                if res and res.get("online"):
                    results.append(res)
                
        return results
