import json
import os
import re
from datetime import datetime, timezone


ARCHIVE_FILE = "/var/ossec/logs/archives/archives.json"


class ArchiveReader:

    def __init__(self, file_path=ARCHIVE_FILE):
        self.file_path = file_path

        # Start reading from current end of file for live tailing
        self.file_position = (
            os.path.getsize(file_path)
            if os.path.exists(file_path)
            else 0
        )

        # Latest event timestamp per agent
        self.latest_events = {}
        self.latest_sources = {}
        # Agent IDs that produced a NEW event during current cycle
        self.updated_agents = set()

    def _parse_timestamp(self, timestamp):
        """
        Convert Wazuh timestamp to UTC datetime.
        """

        if timestamp.endswith("Z"):
            dt = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )
        else:
            fixed = re.sub(
                r'([+-]\d{2})(\d{2})$',
                r'\1:\2',
                timestamp
            )

            dt = datetime.fromisoformat(fixed)

        return dt.astimezone(timezone.utc)

    def initialize_last_events(self):
        """
        Read existing events at startup and determine
        the latest known event timestamp for each agent.
        """

        if not os.path.exists(self.file_path):
            return

        print(
            "[INIT] Scanning archives.json for "
            "initial agent timestamps..."
        )

        with open(self.file_path, "r") as f:

            for line in f:

                line = line.strip()

                if not line:
                    continue

                try:
                    event = json.loads(line)

                    agent = event.get("agent")

                    if not agent or "id" not in agent:
                        continue

                    agent_id = str(agent["id"])

                    timestamp = self._parse_timestamp(
                        event["timestamp"]
                    )

                    self.latest_events[agent_id] = timestamp
                    self.latest_sources[agent_id] = {
                        "id": agent_id,
                        "name": agent.get("name", "Unknown"),
                        "ip": agent.get("ip", "Unknown")
                    }     
                except Exception:
                    continue

    def update(self):
        """
        Read only newly appended events.

        Returns:
            set: Agent IDs that produced new events
                 during this cycle.
        """

        # Reset the set for this monitoring cycle
        self.updated_agents = set()

        if not os.path.exists(self.file_path):
            return self.updated_agents

        with open(self.file_path, "r") as f:

            # Continue from the previous file position
            f.seek(self.file_position)

            for line in f:

                line = line.strip()

                if not line:
                    continue

                try:
                    event = json.loads(line)

                    agent = event.get("agent")

                    if not agent:
                        continue

                    agent_id = str(agent["id"])

                    timestamp = self._parse_timestamp(
                        event["timestamp"]
                    )

                    # Update latest event timestamp
                    self.latest_events[agent_id] = timestamp

                    self.latest_sources[agent_id] = {
                        "id": agent_id,
                        "name": agent.get("name", "Unknown"),
                        "ip": agent.get("ip", "Unknown")
                    }
                    # Remember that this agent generated
                    # a new event during this cycle
                    self.updated_agents.add(agent_id)

                except Exception:
                    continue

            # Save position for next cycle
            self.file_position = f.tell()

        return self.updated_agents

    def has_new_event(self, agent_id):
        """
        Check whether an agent produced a new event
        during the current monitoring cycle.
        """

        return str(agent_id) in self.updated_agents

    def get_latest_event(self, agent_id):
        """
        Return the latest known event timestamp
        for the specified agent.
        """

        return self.latest_events.get(str(agent_id))
    def get_latest_source(self, agent_id):
        """
        Return the latest known source metadata
        for the specified agent.
        """

        return self.latest_sources.get(str(agent_id))
