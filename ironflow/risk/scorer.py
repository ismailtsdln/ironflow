import yaml
import os
from typing import List, Dict, Any
from ironflow.core.logger import logger

class RiskScorer:
    """
    OT-aware risk assessment engine.
    Calculates a risk score based on discovered protocols and identified risks.
    """

    def __init__(self, rules_path: str = None):
        if rules_path is None:
            rules_path = os.path.join(os.path.dirname(__file__), "rules.yaml")
        
        self.rules = self._load_rules(rules_path)

    def _load_rules(self, path: str) -> List[Dict[str, Any]]:
        try:
            with open(path, "r") as f:
                data = yaml.safe_load(f)
                return data.get("rules", [])
        except Exception as e:
            logger.error(f"Failed to load risk rules from {path}: {e}")
            return []

    def calculate_risk(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate overall risk score based on findings.
        """
        score = 0.0
        applied_rules = []
        
        for finding in findings:
            proto = finding.get("protocol", "").lower()
            
            for rule in self.rules:
                # Basic matching logic based on protocol name for now
                if proto in rule.get("name", "").lower():
                    score += rule.get("base_score", 0.0)
                    applied_rules.append(rule)
                    
        # Cap score at 10.0
        final_score = min(score, 10.0)
        
        severity = "Low"
        if final_score >= 9.0:
            severity = "Critical"
        elif final_score >= 7.0:
            severity = "High"
        elif final_score >= 4.0:
            severity = "Medium"
            
        return {
            "score": final_score,
            "severity": severity,
            "applied_rules": applied_rules
        }
