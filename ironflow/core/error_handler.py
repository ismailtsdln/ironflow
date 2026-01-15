from .logger import logger

class IronError(Exception):
    """Base exception for IRONFLOW."""
    pass

class ProtocolError(IronError):
    """Raised when a protocol communication fails."""
    pass

class SafetyViolationError(IronError):
    """Raised when an unsafe operation is attempted in SAFE_MODE."""
    pass

class PluginError(IronError):
    """Raised when a plugin fails."""
    pass

class ConfigurationError(IronError):
    """Raised when there is a configuration issue."""
    pass

def handle_exception(exc: Exception, context: str = "General"):
    """
    Centralized exception handler.
    Logs the error appropriately and ensures the application doesn't crash unexpectedly.
    """
    if isinstance(exc, SafetyViolationError):
        logger.critical(f"⛔ SAFETY VIOLATION in {context}: {exc}")
    elif isinstance(exc, ProtocolError):
        logger.warning(f"Protocol Warning in {context}: {exc}")
    elif isinstance(exc, PluginError):
        logger.error(f"Plugin Failure in {context}: {exc}")
    elif isinstance(exc, KeyboardInterrupt):
        logger.info("\nUser handling interrupt. Exiting safely...")
        exit(0)
    else:
        logger.error(f"Unhandled Exception in {context}: {exc}", exc_info=True)
