import socket
from typing import Any, Dict, Optional
from ironflow.plugins.base import ProtocolPlugin
from ironflow.core.logger import logger

class IEC104Scanner(ProtocolPlugin):
    """
    Plugin for IEC 60870-5-104 device discovery and identification.
    Uses StartDT act (Start Data Transfer) handshake over TCP 2404.
    """

    def __init__(self):
        super().__init__(
            name="IEC104",
            description="IEC 60870-5-104 Protocol Scanner and Identifier"
        )

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        port = kwargs.get("port", 2404)
        logger.info(f"Scanning {target}:{port} for IEC-104 services...")
        
        result = {
            "target": target,
            "port": port,
            "protocol": "IEC-104",
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
        Attempt to identify device via IEC-104 StartDT handshake.
        """
        # APDU StartDT act: 0x68 (Start), 0x04 (Length), 0x07 (Control), 0x00, 0x00, 0x00
        start_dt_act = b"\x68\x04\x07\x00\x00\x00"

        try:
            with socket.create_connection((target, port), timeout=3) as sock:
                sock.sendall(start_dt_act)
                response = sock.recv(1024)
                
                # Check for StartDT con (Control bit 0x0b)
                if response and len(response) >= 6 and response[0] == 0x68 and (response[2] & 0x0f) == 0x0b:
                    return {
                        "status": "connected",
                        "transport": "TCP",
                        "fingerprint": "IEC-104 compatible",
                        "handshake": "StartDT confirmed"
                    }
        except Exception as e:
            logger.debug(f"IEC-104 identification failed for {target}: {e}")
            
        return None
