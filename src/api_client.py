import requests
import urllib3
from requests.auth import HTTPBasicAuth

from src.config import (
    WAZUH_API_URL,
    WAZUH_USERNAME,
    WAZUH_PASSWORD,
    VERIFY_SSL,
    REQUEST_TIMEOUT
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhAPI:

    def __init__(self):
        self.base_url = WAZUH_API_URL
        self.token = None

    def authenticate(self):
        """
        Authenticate with the Wazuh API and store the JWT token.
        """

        url = f"{self.base_url}/security/user/authenticate?raw=true"

        response = requests.post(
            url,
            auth=HTTPBasicAuth(WAZUH_USERNAME, WAZUH_PASSWORD),
            verify=VERIFY_SSL,
            timeout=REQUEST_TIMEOUT
        )

        response.raise_for_status()

        self.token = response.text.strip()

        return self.token

    def get_headers(self):
        """
        Return authorization headers.
        """

        if self.token is None:
            self.authenticate()

        return {
            "Authorization": f"Bearer {self.token}"
        }

    def get_agents(self):
        """
        Retrieve all registered agents.
        Automatically re-authenticate if the JWT token expires.
        """

        url = f"{self.base_url}/agents"

        response = requests.get(
            url,
            headers=self.get_headers(),
            verify=VERIFY_SSL,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 401:

            print("[INFO] JWT token expired. Re-authenticating...")

            self.authenticate()

            response = requests.get(
                url,
                headers=self.get_headers(),
                verify=VERIFY_SSL,
                timeout=REQUEST_TIMEOUT
            )

        response.raise_for_status()

        return response.json()

    def get_latest_alert_time(self, agent_id):
        """
        Return the timestamp of the newest alert for an agent
        from the Wazuh alerts index.
        """

        url = f"{self.base_url}/query"

        query = {
            "query": {
                "term": {
                    "agent.id": str(agent_id)
                }
            },
            "size": 1,
            "sort": [
                {
                    "timestamp": {
                        "order": "desc"
                    }
                }
            ]
        }

        response = requests.post(
            url,
            headers=self.get_headers(),
            json={
                "index": "wazuh-alerts-4.x-*",
                "body": query
            },
            verify=VERIFY_SSL,
            timeout=REQUEST_TIMEOUT
        )

        if response.status_code == 401:

            print("[INFO] JWT token expired. Re-authenticating...")

            self.authenticate()

            response = requests.post(
                url,
                headers=self.get_headers(),
                json={
                    "index": "wazuh-alerts-4.x-*",
                    "body": query
                },
                verify=VERIFY_SSL,
                timeout=REQUEST_TIMEOUT
            )

        response.raise_for_status()

        data = response.json()

        hits = data.get("data", {}).get("hits", {}).get("hits", [])

        if not hits:
            return None

        return hits[0]["_source"]["timestamp"]
