import time
import traceback

from src.heartbeat import HeartbeatMonitor
from src.zero_event import ZeroEventMonitor
from src.archive_reader import ArchiveReader
from src.new_source_detector import NewSourceDetector

from src.config import CHECK_INTERVAL
from src.logger import write_log


def main():
    print("=" * 60)
    print("Coverage Monitor Service Started")
    print(f"Polling every {CHECK_INTERVAL} seconds")
    print("=" * 60)

    heartbeat_monitor = HeartbeatMonitor()
    zero_event_monitor = ZeroEventMonitor()
    new_source_detector = NewSourceDetector()
    archive_reader = ArchiveReader()

    archive_reader.initialize_last_events()

    previous_states = {}

    while True:
        try:
            current_agents = heartbeat_monitor.get_agent_states()

            updated_agent_ids = archive_reader.update()

            for agent_id, agent in current_agents.items():

                # ==================================================
                # NEW SOURCE DETECTION
                # ==================================================

                if agent_id in updated_agent_ids:

                    source_info = archive_reader.get_latest_source(
                        agent_id
                    )

                    new_source_detector.check(
                        agent=agent,
                        source_info=source_info
                    )
                agent_name = agent["name"]
                state = agent["state"]
                old_state = previous_states.get(agent_id)

                print(
                    f"{agent_name} | "
                    f"Wazuh status={agent['status']} | "
                    f"State={state} | "
                    f"Previous={old_state}"
                )

                # ==================================================
                # HEARTBEAT MONITORING
                # ==================================================

                if old_state is None:

                    previous_states[agent_id] = state

                    print(f"[INIT] {agent_name} -> {state}")

                    if state == "Disconnected":

                        print(
                            f"[STARTUP WARNING] "
                            f"{agent_name} already disconnected"
                        )

                        write_log(
                            level="WARNING",
                            agent_id=agent_id,
                            agent_name=agent_name,
                            heartbeat_state="Disconnected",
                            message=(
                                "Agent was already disconnected "
                                "when Coverage Monitor started"
                            )
                        )

                    elif state == "Silent":

                        print(
                            f"[STARTUP WARNING] "
                            f"{agent_name} already silent"
                        )

                        write_log(
                            level="WARNING",
                            agent_id=agent_id,
                            agent_name=agent_name,
                            heartbeat_state="Silent",
                            message=(
                                "Agent was already silent "
                                "when Coverage Monitor started"
                            )
                        )

                else:

                    if old_state != state:

                        if state == "Disconnected":

                            print(
                                f"[WARNING] "
                                f"{agent_name} disconnected"
                            )

                            write_log(
                                level="WARNING",
                                agent_id=agent_id,
                                agent_name=agent_name,
                                heartbeat_state="Disconnected",
                                message="Agent heartbeat lost"
                            )

                        elif state == "Healthy":

                            print(
                                f"[INFO] "
                                f"{agent_name} reconnected"
                            )

                            write_log(
                                level="INFO",
                                agent_id=agent_id,
                                agent_name=agent_name,
                                heartbeat_state="Connected",
                                message="Agent heartbeat restored"
                            )

                        elif state == "Silent":

                            print(
                                f"[WARNING] "
                                f"{agent_name} silent"
                            )

                            write_log(
                                level="WARNING",
                                agent_id=agent_id,
                                agent_name=agent_name,
                                heartbeat_state="Silent",
                                message="Heartbeat threshold exceeded"
                            )

                        previous_states[agent_id] = state

                # ==================================================
                # ZERO EVENT DETECTION
                # Only check agents that are currently healthy.
                # ==================================================

                if state == "Healthy":

                    zero_event_monitor.check(
                        agent=agent,
                        archive_reader=archive_reader
                    )

            print(
                f"Sleeping {CHECK_INTERVAL} seconds...\n"
            )

            time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:

            print("\nCoverage Monitor stopped.")
            break

        except Exception:

            traceback.print_exc()
            time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
