import json
from typing import Optional, Dict, Any
from datetime import datetime, timezone

def parse_metadata_json(metadata_json: Optional[str]) -> Optional[Dict[str, Any]]:
    if not metadata_json:
        return None
    try:
        return json.loads(metadata_json)
    except json.JSONDecodeError:
        return None


