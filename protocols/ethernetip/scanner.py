import socket
from typing import Any, Dict, Optional
from plugins.base import ProtocolPlugin
from core.logger import logger

class EthernetIPScanner(ProtocolPlugin):
    """
    Plugin for EtherNet/IP & CIP device discovery and identification.
    Uses "List Identity" request over TCP 44818.
    """

    def __init__(self):
        super().__init__(
            name="EthernetIP",
            description="EtherNet/IP & CIP Protocol Scanner and Identifier"
        )

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        port = kwargs.get("port", 44818)
        logger.info(f"Scanning {target}:{port} for EtherNet/IP services...")
        
        result = {
            "target": target,
            "port": port,
            "protocol": "EtherNet/IP",
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
        Attempt to identify device via EtherNet/IP List Identity request.
        """
        # Encapsulation Header: Command=0x0063 (ListIdentity), Length=0, Session=0, Status=0, SenderContext=0, Options=0
        list_identity_cmd = b"\x63\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

        try:
            with socket.create_connection((target, port), timeout=3) as sock:
                sock.sendall(list_identity_cmd)
                response = sock.recv(1024)
                
                if response and len(response) >= 2 and response[0:2] == b"\x63\x00":
                    return {
                        "status": "connected",
                        "transport": "TCP",
                        "fingerprint": "EtherNet/IP compatible",
                        "response_header": response[:24].hex()
                    }
        except Exception as e:
            logger.debug(f"EtherNet/IP identification failed for {target}: {e}")
            
        return None
