from typing import List, Dict, Any
from ironflow.core.logger import logger

class TopologyMapper:
    """
    Builds a topological representation of the OT network based on findings.
    """

    def __init__(self):
        self.nodes = {}
        self.edges = []

    def build_graph(self, scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Convert scan results into a graph structure (nodes and edges).
        """
        logger.info("Building network topology graph...")
        
        for result in scan_results:
            target = result.get("target")
            protocol = result.get("protocol")
            
            if target not in self.nodes:
                self.nodes[target] = {
                    "id": target,
                    "label": target,
                    "type": "Asset",
                    "protocols": []
                }
            
            if protocol not in self.nodes[target]["protocols"]:
                self.nodes[target]["protocols"].append(protocol)
                
            # For now, we don't have direct edge info (source -> dest) 
            # unless we have PCAP analysis. 
            # This is a simplified asset-centric map.
            
        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges
        }

    def export_json(self, graph_data: Dict[str, Any], path: str):
        """Export the graph data to JSON."""
        import json
        try:
            with open(path, "w") as f:
                json.dump(graph_data, f, indent=2)
            logger.info(f"Topology exported to {path}")
        except Exception as e:
            logger.error(f"Failed to export topology: {e}")
