from src.inventory import InventoryManager
from src.logger import write_log


class NewSourceDetector:
    """
    Detect Wazuh agents that are not currently present
    in the approved log source inventory.

    Agent ID is used as the unique identity.
    """

    def __init__(self):
        self.inventory = InventoryManager()

    def check(self, agent, source_info=None):
        """
        Check one Wazuh agent against the inventory.

        source_info contains authoritative metadata
        obtained from Wazuh archives.json.

        Returns:
            True  -> source is new and was registered
            False -> source already exists
        """

        agent_id = str(agent["id"])

        # --------------------------------------------------
        # Build source information
        # --------------------------------------------------

        source_agent = dict(agent)

        if source_info:

            source_agent["id"] = source_info.get(
                "id",
                agent_id
            )

            source_agent["name"] = source_info.get(
                "name",
                agent.get("name", "Unknown")
            )

            source_agent["ip"] = source_info.get(
                "ip",
                agent.get("ip", "Unknown")
            )

        agent_name = source_agent.get(
            "name",
            "Unknown"
        )

        agent_ip = source_agent.get(
            "ip",
            "Unknown"
        )

        # --------------------------------------------------
        # Never treat Wazuh Manager (agent 000) as a source
        # --------------------------------------------------

        if agent_id == "000":
            return False

        # --------------------------------------------------
        # Check whether source already exists
        # --------------------------------------------------

        existing_source = self.inventory.get_by_agent_id(
            agent_id
        )

        # --------------------------------------------------
        # NEW SOURCE
        # --------------------------------------------------

        if existing_source is None:

            added = self.inventory.add_source(
                source_agent
            )

            if added:

                print(
                    f"[NEW SOURCE] {agent_name} "
                    f"(ID={agent_id}, IP={agent_ip}) "
                    f"was automatically registered."
                )

                write_log(
                    level="WARNING",
                    agent_id=agent_id,
                    agent_name=agent_name,
                    message=(
                        f"New Wazuh source automatically "
                        f"registered: {agent_name} "
                        f"({agent_ip})"
                    )
                )

                return True

        # --------------------------------------------------
        # EXISTING SOURCE
        # --------------------------------------------------

        changed = self.inventory.update_source(
            source_agent
        )

        if changed:

            print(
                f"[SOURCE UPDATED] {agent_name} "
                f"(ID={agent_id}) metadata changed."
            )

            write_log(
                level="INFO",
                agent_id=agent_id,
                agent_name=agent_name,
                message=(
                    f"Existing source metadata updated: "
                    f"{agent_name} ({agent_ip})"
                )
            )

        return False
