import logging
import sys
from rich.logging import RichHandler
from rich.console import Console
from rich.theme import Theme

# Custom theme for IRONFLOW
iron_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "red",
    "critical": "bold red",
    "success": "green",
    "protocol": "magenta",
})

console = Console(theme=iron_theme)

def setup_logger(name="ironflow", level=logging.INFO):
    """
    Sets up the global logger using Rich for beautiful output.
    """
    # Force rich handler to use our console and theme
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)]
    )
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    return logger

# Create the main logger instance
logger = setup_logger()

def print_banner():
    """Prints a premium ASCII banner for IRONFLOW."""
    from rich.panel import Panel
    from rich.text import Text
    
    banner_text = """
    ██╗██████╗  ██████╗ ███╗   ██╗███████╗██╗      ██████╗ ██╗    ██╗
    ██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝██║     ██╔═══██╗██║    ██║
    ██║██████╔╝██║   ██║██╔██╗ ██║█████╗  ██║     ██║   ██║██║ █╗ ██║
    ██║██╔══██╗██║   ██║██║╚██╗██║██╔══╝  ██║     ██║   ██║██║███╗██║
    ██║██║  ██║╚██████╔╝██║ ╚████║██║     ███████╗╚██████╔╝╚███╔███╔╝
    ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝ 
    """
    
    panel = Panel(
        Text(banner_text, style="bold cyan"),
        subtitle="[bold white]Next-Gen OT/ICS Security Analysis Platform[/]",
        border_style="bright_blue"
    )
    console.print(panel)
