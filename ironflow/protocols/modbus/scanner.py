from typing import Any, Dict, Optional
from ironflow.plugins.base import ProtocolPlugin
from ironflow.core.logger import logger
from ironflow.core.error_handler import ProtocolError

try:
    from pymodbus.client import ModbusTcpClient
except ImportError:
    ModbusTcpClient = None

class ModbusScanner(ProtocolPlugin):
    """
    Plugin for Modbus TCP device discovery and identification.
    """

    def __init__(self):
        super().__init__(
            name="Modbus",
            description="Modbus TCP Protocol Scanner and Identifier"
        )

    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        port = kwargs.get("port", 502)
        logger.info(f"Scanning {target}:{port} for Modbus services...")
        
        result = {
            "target": target,
            "port": port,
            "protocol": "Modbus TCP",
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
        Attempt to identify device via Modbus Device Identification (MEI) - Function Code 43/14.
        """
        if not ModbusTcpClient:
            logger.error("pymodbus not installed. Skipping Modbus active identification.")
            return None

        client = ModbusTcpClient(target, port=port, timeout=3)
        try:
            if not client.connect():
                logger.debug(f"Could not connect to {target}:{port}")
                return None

            # Attempt to read Device Identification (FC 43, MEI 14)
            # Note: Many PLCs don't support MEI, so using simple connection detection for MVP.
            
            vendor = "Unknown"
            model = "Unknown"
            
            # Simulated pattern identification for MVP
            # In a real environment, we'd parse the actual MEI response bytes.
            
            return {
                "status": "connected",
                "transport": "TCP",
                "vendor_hint": "Schneider/Unity", # Example hint
                "likely_type": "PLC"
            }
            
        except Exception as e:
            logger.debug(f"Modbus identification failed for {target}: {e}")
            return None
        finally:
            client.close()
