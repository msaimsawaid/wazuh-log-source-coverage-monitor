import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
INVENTORY_FILE = BASE_DIR / "config" / "log_source_inventory.json"


class InventoryManager:
    """
    Manage the approved Wazuh log source inventory.

    Agent ID is the unique identity of a source.
    """

    def __init__(self, file_path=INVENTORY_FILE):
        self.file_path = Path(file_path)

        self.file_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        if not self.file_path.exists():
            self._create_empty_inventory()

    def _create_empty_inventory(self):
        data = {
            "sources": []
        }

        self._save(data)

    def _load(self):
        """
        Load inventory JSON.
        """

        try:
            with open(self.file_path, "r") as f:
                data = json.load(f)

        except (json.JSONDecodeError, FileNotFoundError):
            data = {
                "sources": []
            }

        if "sources" not in data:
            data["sources"] = []

        return data

    def _save(self, data):
        """
        Save inventory JSON.
        """

        temp_file = self.file_path.with_suffix(".tmp")

        with open(temp_file, "w") as f:
            json.dump(
                data,
                f,
                indent=4
            )

        temp_file.replace(self.file_path)

    def get_all(self):
        """
        Return all inventory sources.
        """

        data = self._load()

        return data["sources"]

    def get_by_agent_id(self, agent_id):
        """
        Find a source using Agent ID.
        """

        agent_id = str(agent_id)

        for source in self.get_all():

            if str(source.get("agent_id")) == agent_id:
                return source

        return None

    def exists(self, agent_id):
        """
        Check whether an Agent ID exists.
        """

        return self.get_by_agent_id(agent_id) is not None

    def add_source(self, agent):
        """
        Automatically register a new Wazuh agent.
        """

        data = self._load()

        agent_id = str(agent["id"])

        # Prevent duplicate registration
        for source in data["sources"]:

            if str(source.get("agent_id")) == agent_id:
                return False

        source = {
            "agent_id": agent_id,
            "name": agent.get("name", "Unknown"),
            "ip": agent.get("ip", "Unknown"),
            "status": "active"
        }

        data["sources"].append(source)

        self._save(data)

        return True

    def update_source(self, agent):
        """
        Update existing source metadata.

        Agent ID remains the identity.
        Name/IP are attributes that may change.
        """

        data = self._load()

        agent_id = str(agent["id"])

        for source in data["sources"]:

            if str(source.get("agent_id")) == agent_id:

                changed = False

                new_name = agent.get(
                    "name",
                    source.get("name")
                )

                new_ip = agent.get(
                    "ip",
                    source.get("ip")
                )

                if source.get("name") != new_name:
                    source["name"] = new_name
                    changed = True

                if source.get("ip") != new_ip:
                    source["ip"] = new_ip
                    changed = True

                if source.get("status") != "active":
                    source["status"] = "active"
                    changed = True

                if changed:
                    self._save(data)

                return changed

        return False
