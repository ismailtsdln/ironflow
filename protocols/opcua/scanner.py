import socket
from typing import Any, Dict, Optional
from plugins.base import ProtocolPlugin
from core.logger import logger

class OPCUAScanner(ProtocolPlugin):
    """
    Plugin for OPC UA device discovery and identification.
    Uses "Hello" (HEL) message over TCP 4840.
    """

    def __init__(self):
        super().__init__(
            name="OPCUA",
            description="OPC UA Protocol Scanner and Identifier"
        )

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        port = kwargs.get("port", 4840)
        logger.info(f"Scanning {target}:{port} for OPC UA services...")
        
        result = {
            "target": target,
            "port": port,
            "protocol": "OPC UA",
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
        Attempt to identify device via OPC UA Hello handshake.
        """
        # OPC UA HEL Message: 
        # MessageType: HEL (3 bytes)
        # Reserved: F (1 byte)
        # MessageSize: 32 (4 bytes)
        # Version: 0 (4 bytes)
        # ReceiveBufferSize: 65536 (4 bytes)
        # SendBufferSize: 65536 (4 bytes)
        # MaxMessageSize: 0 (4 bytes)
        # MaxChunkCount: 0 (4 bytes)
        hel_msg = b"HELF\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

        try:
            with socket.create_connection((target, port), timeout=3) as sock:
                sock.sendall(hel_msg)
                response = sock.recv(1024)
                
                # Check for ACK (Acknowledge) or ERR (Error)
                if response and len(response) >= 3 and response[0:3] in [b"ACK", b"ERR"]:
                    return {
                        "status": "connected",
                        "transport": "TCP",
                        "fingerprint": "OPC UA compatible",
                        "response_type": response[0:3].decode()
                    }
        except Exception as e:
            logger.debug(f"OPC UA identification failed for {target}: {e}")
            
        return None
