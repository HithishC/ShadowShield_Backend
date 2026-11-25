from pathlib import Path
import os

DB_PATH = os.getenv("SHADOWSHIELD_DB_PATH", str(Path(__file__).parent / "shadowshield.db"))
DEFAULT_ALLOWED_PORTS = {53, 80, 123, 443}
RISK_UNKNOWN = 30
RISK_UNEXPECTED_PORT = 20
RISK_CHANGED = 20
RISK_INSUFFICIENT = 10
MIN_IDENTITY_FIELDS = 2
