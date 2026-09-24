import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

# Auto-load .env file if present in BASE_DIR
env_file = BASE_DIR / ".env"
if env_file.exists():
    try:
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip("'").strip('"')
                    os.environ.setdefault(k, v)
    except Exception as e:
        print(f"Notice: Failed to parse .env file: {e}")

# TigerGraph Credentials & Settings
TG_HOST = os.environ.get("TG_HOST", "").strip()
TG_GRAPH = os.environ.get("TG_GRAPH", os.environ.get("TG_GRAPHNAME", "FraudGraph")).strip()
TG_GRAPHNAME = TG_GRAPH
TG_USERNAME = os.environ.get("TG_USERNAME", "tigergraph").strip()
TG_PASSWORD = os.environ.get("TG_PASSWORD", "").strip()
TG_SECRET = os.environ.get("TG_SECRET", "").strip()
TG_API_TOKEN = os.environ.get("TG_API_TOKEN", "").strip()

STRICT_TG_REQUIRED = os.environ.get("STRICT_TIGERGRAPH_REQUIRED", "false").lower() == "true"

# Server Configuration
PORT = int(os.environ.get("PORT", "8000"))
HOST = os.environ.get("HOST", "0.0.0.0")

def get_safe_config() -> dict:
    """Returns safe diagnostic view of configuration with all credentials masked."""
    return {
        "TG_HOST": TG_HOST,
        "TG_GRAPH": TG_GRAPH,
        "TG_GRAPHNAME": TG_GRAPHNAME,
        "TG_USERNAME": TG_USERNAME,
        "TG_SECRET": "[CONFIGURED]" if TG_SECRET else "[NOT CONFIGURED]",
        "TG_PASSWORD": "[CONFIGURED]" if TG_PASSWORD else "[NOT CONFIGURED]",
        "TG_API_TOKEN": "[CONFIGURED]" if TG_API_TOKEN else "[NOT CONFIGURED]",
        "STRICT_TIGERGRAPH_REQUIRED": STRICT_TG_REQUIRED,
        "PORT": PORT,
        "HOST": HOST
    }
