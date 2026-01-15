import socket
from typing import Any, Dict, Optional
from ironflow.plugins.base import ProtocolPlugin
from ironflow.core.logger import logger

class S7Scanner(ProtocolPlugin):
    """
    Plugin for Siemens S7Comm device discovery and identification.
    Uses benign S7 Setup Communication requests.
    """

    def __init__(self):
        super().__init__(
            name="S7",
            description="S7Comm Protocol Scanner and Identifier"
        )

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        port = kwargs.get("port", 102)
        logger.info(f"Scanning {target}:{port} for S7 services...")
        
        result = {
            "target": target,
            "port": port,
            "protocol": "S7Comm",
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
        Attempt to identify device via S7 Setup Communication (COTP Connection Request).
        This is a safe operation used for initial handshake.
        """
        # COTP Connection Request for S7
        # TPKT (4 bytes) + COTP (18 bytes)
        # Simplified handshake probe
        cotp_cr = (
            b"\x03\x00\x00\x16"  # TPKT: Version 3, Reserved 0, Length 22
            b"\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a" # COTP CR
        )

        try:
            with socket.create_connection((target, port), timeout=3) as sock:
                sock.sendall(cotp_cr)
                response = sock.recv(1024)
                
                if response and len(response) >= 4 and response[0] == 0x03:
                    # Successful COTP connection response usually starts with TPKT header
                    # Byte 5 of response often indicates the PDU type. 0xd0 = CC (Connect Confirm)
                    
                    fingerprint = "S7 compatible"
                    model_hint = "S7-300/400"
                    
                    if len(response) > 10:
                        # Simple heuristic for MVP:
                        # Modern S7 (1200/1500) often has different handshake lengths or signatures.
                        fingerprint = "S7-1200/1500 compatible"
                        model_hint = "S7-1200/1500"

                    return {
                        "status": "connected",
                        "transport": "TCP/ISO-on-TCP",
                        "vendor": "Siemens",
                        "model_hint": model_hint,
                        "fingerprint": fingerprint
                    }
        except Exception as e:
            logger.debug(f"S7 identification failed for {target}: {e}")
            
        return None
