from datetime import datetime, timezone
from src.config import ZERO_EVENT_THRESHOLD
from src.logger import write_log


class ZeroEventMonitor:
    """
    Monitor whether healthy agents are actively producing events.
    """

    def __init__(self):
        # Last event timestamp seen for each agent
        self.last_event = {}

        # Agents currently marked as silent
        self.silent_agents = set()

    def check(self, agent, archive_reader):
        agent_id = str(agent["id"])
        agent_name = agent["name"]

        # If agent is not Healthy (e.g. Disconnected), reset its tracking
        if agent["state"] != "Healthy":
            self.last_event.pop(agent_id, None)
            self.silent_agents.discard(agent_id)
            return

        # ----------------------------------------------------
        # 1. New event arrived?
        # ----------------------------------------------------
        if archive_reader.has_new_event(agent_id):
            latest = archive_reader.get_latest_event(agent_id)
            self.last_event[agent_id] = latest

            print(f"[EVENT SEEN] {agent_name} ({agent_id}) sent a new log at {latest.strftime('%H:%M:%S')}")

            # If it was previously marked as silent, fire Recovery alert
            if agent_id in self.silent_agents:
                print(f"[RECOVERED] {agent_name} resumed sending logs.")

                write_log(
                    level="INFO",
                    agent_id=agent_id,
                    agent_name=agent_name,
                    zero_event_state="Recovered",
                    message="Log source resumed sending events."
                )

                self.silent_agents.remove(agent_id)

            return

        # ----------------------------------------------------
        # 2. Check if initial history exists from ArchiveReader
        # ----------------------------------------------------
        if agent_id not in self.last_event:
            initial_event = archive_reader.get_latest_event(agent_id)
            if initial_event:
                self.last_event[agent_id] = initial_event
            else:
                # Still never seen any event for this agent
                return

        # ----------------------------------------------------
        # 3. Check for inactivity / silence threshold
        # ----------------------------------------------------
        elapsed = (
            datetime.now(timezone.utc) - self.last_event[agent_id]
        ).total_seconds() / 60

        print(
            f"[ZERO EVENT] "
            f"{agent_name}: "
            f"{elapsed:.1f} min since last event"
        )

        if elapsed >= ZERO_EVENT_THRESHOLD:
            if agent_id not in self.silent_agents:
                print(
                    f"[WARNING] "
                    f"{agent_name} has stopped sending logs."
                )

                write_log(
                    level="WARNING",
                    agent_id=agent_id,
                    agent_name=agent_name,
                    zero_event_state="Silent",
                    message=f"No events received for {elapsed:.1f} minutes"
                )

                self.silent_agents.add(agent_id)
