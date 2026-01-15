from typing import List, Dict, Any
import json
import os
from datetime import datetime
from ironflow.core.logger import logger

class ReportGenerator:
    """
    Generates security reports in JSON and HTML formats.
    """

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

    def generate_json(self, data: Dict[str, Any], filename: str = None) -> str:
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=4)
        
        logger.info(f"JSON report generated: {filepath}")
        return filepath

    def generate_html(self, data: Dict[str, Any], filename: str = None) -> str:
        """
        Generates a basic HTML report.
        """
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        filepath = os.path.join(self.output_dir, filename)
        
        # Simple HTML template
        html_content = f"""
        <html>
        <head>
            <title>IRONFLOW Security Report</title>
            <style>
                body {{ font-family: sans-serif; margin: 40px; background: #f4f4f9; }}
                h1 {{ color: #2c3e50; }}
                .summary {{ background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .asset {{ margin-top: 20px; padding: 15px; background: #fff; border-left: 5px solid #3498db; }}
                .Critical {{ border-left-color: #e74c3c; }}
                .High {{ border-left-color: #e67e22; }}
                .Medium {{ border-left-color: #f1c40f; }}
                .Low {{ border-left-color: #27ae60; }}
            </style>
        </head>
        <body>
            <h1>IRONFLOW Security Report</h1>
            <div class="summary">
                <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Total Assets: {len(data.get('results', []))}</p>
            </div>
            <h2>Discovered Assets</h2>
        """
        
        for result in data.get('results', []):
            severity = result.get('risk', {}).get('severity', 'Low')
            html_content += f"""
            <div class="asset {severity}">
                <h3>Target: {result.get('target')}</h3>
                <p>Protocol: {result.get('protocol')}</p>
                <p>Severity: <strong>{severity}</strong> (Score: {result.get('risk', {}).get('score', 0)})</p>
            </div>
            """
            
        html_content += "</body></html>"
        
        with open(filepath, "w") as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {filepath}")
        return filepath
