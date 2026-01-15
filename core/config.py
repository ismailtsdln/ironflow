import os
from dataclasses import dataclass

@dataclass
class IronConfig:
    """
    Global configuration for IRONFLOW.
    """
    SAFE_MODE: bool = True
    LOG_LEVEL: str = "INFO"
    TIMEOUT: int = 5
    RETRIES: int = 2
    
    def __post_init__(self):
        # Allow environment variable override for CI/CD or advanced usage, 
        # but default is always True for safety.
        env_safe = os.getenv("IRONFLOW_SAFE_MODE")
        if env_safe is not None:
            self.SAFE_MODE = env_safe.lower() in ("true", "1", "yes")

    def disable_safe_mode(self):
        """
        Explicitly disable safe mode.
        This should be called only when the user provides a specific flag (e.g., --dangerous).
        """
        import logging
        logger = logging.getLogger("ironflow.core")
        logger.critical("⚠️  SAFE MODE DISABLED! Write operations are now permitted. Proceed with caution.")
        self.SAFE_MODE = False

# Global instance
config = IronConfig()
