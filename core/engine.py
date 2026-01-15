import importlib
import pkgutil
from typing import Dict, List, Type
from core.logger import logger
from plugins.base import BasePlugin

class IronEngine:
    """
    Main orchestration engine for IRONFLOW.
    Loads and executes plugins.
    """

    def __init__(self):
        self.plugins: Dict[str, BasePlugin] = {}

    def discover_plugins(self, package_paths: List[str] = ["plugins", "protocols"]):
        """
        Dynamically discover and load plugins from multiple packages.
        """
        for package_path in package_paths:
            logger.info(f"Scanning for plugins in {package_path}...")
            try:
                package = importlib.import_module(package_path)
                # Ensure the package has a __path__
                if not hasattr(package, "__path__"):
                    continue
                    
                for loader, module_name, is_pkg in pkgutil.walk_packages(package.__path__):
                    full_module_name = f"{package_path}.{module_name}"
                    logger.debug(f"Checking module: {full_module_name}")
                    
                    try:
                        module = importlib.import_module(full_module_name)
                        for attribute_name in dir(module):
                            attribute = getattr(module, attribute_name)
                            
                            if (isinstance(attribute, type) and 
                                issubclass(attribute, BasePlugin) and 
                                attribute is not BasePlugin and
                                not attribute.__name__.startswith("Base")):
                                
                                # Instantiate the plugin
                                try:
                                    plugin_instance = attribute()
                                    self.plugins[plugin_instance.name.lower()] = plugin_instance
                                    logger.info(f"Loaded plugin: {plugin_instance.name}")
                                except Exception as e:
                                    # logger.error(f"Failed to load plugin {attribute_name}: {e}")
                                    pass # Might be an abstract class or need args
                    except Exception as e:
                        logger.debug(f"Could not load module {full_module_name}: {e}")
            except Exception as e:
                logger.error(f"Error during plugin discovery in {package_path}: {e}")

    def get_plugin(self, name: str) -> BasePlugin:
        return self.plugins.get(name.lower())

    def run_plugin(self, name: str, target: str, **kwargs):
        plugin = self.get_plugin(name)
        if not plugin:
            logger.error(f"Plugin '{name}' not found.")
            return None
        
        logger.info(f"Running plugin: {plugin.name} on {target}")
        try:
            return plugin.run(target, **kwargs)
        except Exception as e:
            logger.error(f"Error running plugin {name}: {e}")
            return None
