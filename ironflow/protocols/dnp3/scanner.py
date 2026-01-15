import socket
from typing import Any, Dict, Optional
from ironflow.plugins.base import ProtocolPlugin
from ironflow.core.logger import logger

class DNP3Scanner(ProtocolPlugin):
    """
    Plugin for DNP3 device discovery and identification.
    Uses basic DNP3 link-layer confirmed user data request logic (benign).
    """

    def __init__(self):
        super().__init__(
            name="DNP3",
            description="DNP3 Protocol Scanner and Identifier"
        )

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        port = kwargs.get("port", 20000)
        logger.info(f"Scanning {target}:{port} for DNP3 services...")
        
        result = {
            "target": target,
            "port": port,
            "protocol": "DNP3",
            "online": False,
            "details": {}
        }
        
        id_info = self.identify(target, port)
        if id_info:
            result["online"] = True
            result["details"] = id_info
            
        return result

    def identify(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Attempt to identify device via DNP3 link layer handshake.
        """
        # DNP3 Link Layer Header (0x05 0x64)
        # Simplified probe
        dnp3_probe = (
            b"\x05\x64"  # Start bytes
            b"\x05\xc9"  # Length and Control
            b"\x00\x00"  # Dest
            b"\x00\x00"  # Source
            b"\x00\x00"  # CRC (simplified/invalid but often triggers response)
        )

        try:
            with socket.create_connection((target, port), timeout=3) as sock:
                sock.sendall(dnp3_probe)
                response = sock.recv(1024)
                
                if response and len(response) >= 2 and response[0:2] == b"\x05\x64":
                    return {
                        "status": "connected",
                        "transport": "TCP",
                        "fingerprint": "DNP3 compatible"
                    }
        except Exception as e:
            logger.debug(f"DNP3 identification failed for {target}: {e}")
            
        return None
