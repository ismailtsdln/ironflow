import socket
from typing import Any, Dict, Optional
from ironflow.plugins.base import ProtocolPlugin
from ironflow.core.logger import logger

class BACnetScanner(ProtocolPlugin):
    """
    Plugin for BACnet/IP device discovery and identification.
    Uses BACnet "Who-Is" NPDU over UDP 47808 (BAC0).
    """

    def __init__(self):
        super().__init__(
            name="BACnet",
            description="BACnet/IP Protocol Scanner and Identifier"
        )

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        port = kwargs.get("port", 47808)
        logger.info(f"Scanning {target}:{port} for BACnet services...")
        
        result = {
            "target": target,
            "port": port,
            "protocol": "BACnet/IP",
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
        Attempt to identify device via BACnet Who-Is request.
        """
        # BVLC: Type=0x81 (BACnet/IP), Function=0x0a (Original-Broadcast-NPDU), Length=12
        # NPDU: Version=1, Control=0x20 (Expect response)
        # APDU: Type=0x10 (UnconfirmedRequest), Service=0x08 (Who-Is)
        who_is_payload = (
            b"\x81\x0a\x00\x0c"  # BVLC
            b"\x01\x20\xff\xff\x00\xff" # NPDU
            b"\x10\x08"          # APDU (Who-Is)
        )

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(3)
                sock.sendto(who_is_payload, (target, port))
                response, _ = sock.recvfrom(1024)
                
                if response and len(response) >= 4 and response[0] == 0x81:
                    return {
                        "status": "connected",
                        "transport": "UDP",
                        "fingerprint": "BACnet compatible",
                        "response_len": len(response)
                    }
        except Exception as e:
            logger.debug(f"BACnet identification failed for {target}: {e}")
            
        return None
