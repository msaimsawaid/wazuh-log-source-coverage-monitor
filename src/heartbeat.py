from datetime import datetime, timezone

from src.api_client import WazuhAPI
from src.config import HEARTBEAT_THRESHOLD


class HeartbeatMonitor:

    def __init__(self):
        self.api = WazuhAPI()

    def check_agents(self):

        agents = self.api.get_agents()["data"]["affected_items"]

        results = []

        now = datetime.now(timezone.utc)

        for agent in agents:

            # Skip the manager (Agent 000)
            if agent["id"] == "000":
                continue

            last_keep_alive = datetime.fromisoformat(
                agent["lastKeepAlive"]
            )

            seconds_since = (
                now - last_keep_alive
            ).total_seconds()

            if agent["status"] != "active":
                state = "Disconnected"

            elif seconds_since > HEARTBEAT_THRESHOLD:
                state = "Silent"

            else:
                state = "Healthy"

            results.append({
                "id": agent["id"],
                "name": agent["name"],
                "status": agent["status"],
                "last_keep_alive": agent["lastKeepAlive"],
                "seconds_since": round(seconds_since, 2),
                "state": state
            })

        return results

    def get_agent_states(self):
        """
        Returns a dictionary containing the current state of each agent.
        """

        states = {}

        for agent in self.check_agents():
            states[agent["id"]] = agent

        return states
