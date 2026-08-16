import json
from datetime import datetime


LOG_FILE = "logs/coverage_monitor.log"


def write_log(
    level,
    agent_id,
    agent_name,
    message,
    heartbeat_state=None,
    zero_event_state=None
):
    """
    Write Coverage Monitor events as JSON.

    Supports:
    - Heartbeat Monitoring
    - Zero Event Detection
    """

    log = {
        "event": "coverage_monitor",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "level": level,
        "agent_id": str(agent_id),
        "agent_name": agent_name,
        "message": message
    }

    if heartbeat_state is not None:
        log["heartbeat_state"] = heartbeat_state

    if zero_event_state is not None:
        log["zero_event_state"] = zero_event_state

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(log) + "\n")
