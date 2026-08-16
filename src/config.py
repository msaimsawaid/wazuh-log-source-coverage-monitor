from dotenv import load_dotenv
import os
from pathlib import Path

# Load the .env file from the project root
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# ============================================
# Wazuh API Configuration
# ============================================

WAZUH_API_URL = os.getenv("WAZUH_API_URL")
WAZUH_USERNAME = os.getenv("WAZUH_USERNAME")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")

VERIFY_SSL = os.getenv("VERIFY_SSL", "False").lower() == "true"
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "10"))

# ============================================
# Monitoring Configuration
# ============================================

CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "30"))          # seconds
HEARTBEAT_THRESHOLD = int(os.getenv("HEARTBEAT_THRESHOLD", "300"))  # seconds
ZERO_EVENT_THRESHOLD = int(os.getenv("ZERO_EVENT_THRESHOLD", "1")) # minutes
