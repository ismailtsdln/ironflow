import json
import os
from typing import Dict, List, Any
from datetime import datetime
from ironflow.core.logger import logger

class AssetDatabase:
    """
    Persistence layer for discovered ICS assets using a local JSON store.
    """

    def __init__(self, db_path: str = "assets.json"):
        self.db_path = db_path
        self.assets = self._load_db()

    def _load_db(self) -> Dict[str, Any]:
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load asset database: {e}")
        return {"assets": {}, "last_update": None}

    def save_asset(self, target: str, data: Dict[str, Any]):
        """
        Store or update an asset in the database.
        """
        asset_info = {
            "target": target,
            "protocol": data.get("protocol"),
            "details": data.get("details", {}),
            "risk": data.get("risk", {}),
            "last_seen": datetime.now().isoformat()
        }
        
        self.assets["assets"][target] = asset_info
        self.assets["last_update"] = datetime.now().isoformat()
        self._commit()

    def _commit(self):
        try:
            with open(self.db_path, "w") as f:
                json.dump(self.assets, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to commit asset database: {e}")

    def get_all_assets(self) -> List[Dict[str, Any]]:
        return list(self.assets["assets"].values())
