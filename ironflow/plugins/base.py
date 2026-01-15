from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from ironflow.core.config import config
from ironflow.core.logger import logger
from ironflow.core.error_handler import SafetyViolationError

class BasePlugin(ABC):
    """
    Abstract base class for all IRONFLOW plugins.
    Ensures a consistent interface for scanners, analyzers, and other tools.
    """

    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description

    @abstractmethod
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Execute the plugin's main logic.
        """
        pass

    def check_safety(self, operation: str = "Write"):
        """
        Helper to check if an operation is safe to perform.
        """
        if config.SAFE_MODE:
            logger.critical(f"Aborting {operation} operation by {self.name}: SAFE_MODE is enabled.")
            raise SafetyViolationError(f"Plugin {self.name} attempted an unsafe operation: {operation}")

class ProtocolPlugin(BasePlugin):
    """
    Base class for protocol-specific scanners/analyzers.
    """
    
    @abstractmethod
    def identify(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Attempt to identify the device behind the target/port using the protocol.
        """
        pass
