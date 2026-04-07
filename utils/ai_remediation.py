import ipaddress
import json
import logging
import os
import subprocess
from datetime import datetime


LOGGER = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(BASE_DIR, "data", "logs.txt")


def _utc_timestamp():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _run_command(command):
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
        return {
            "command": " ".join(command),
            "returncode": completed.returncode,
            "stdout": (completed.stdout or "").strip(),
            "stderr": (completed.stderr or "").strip(),
            "success": completed.returncode == 0,
        }
    except Exception as exc:
        return {
            "command": " ".join(command),
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
            "success": False,
        }


def _append_audit_log(entry):
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
    except Exception:
        LOGGER.exception("Failed to write incident response audit log")


def _valid_ip(ip_value):
    if not ip_value:
        return False
    try:
        ipaddress.ip_address(str(ip_value))
        return True
    except ValueError:
        return False


def _build_rule_name(prefix, value):
    safe_value = str(value).replace(" ", "_").replace(":", "_")
    return f"CyberShield-AI-{prefix}-{safe_value}"


def block_ip(ip_address_value):
    if not _valid_ip(ip_address_value):
        return {
            "type": "block_ip",
            "target": ip_address_value,
            "success": False,
            "details": "Skipped because source IP is missing or invalid.",
            "commands": [],
        }

    inbound_name = _build_rule_name("BlockInboundIP", ip_address_value)
    outbound_name = _build_rule_name("BlockOutboundIP", ip_address_value)
    commands = [
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={inbound_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip_address_value}",
        ],
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={outbound_name}",
            "dir=out",
            "action=block",
            f"remoteip={ip_address_value}",
        ],
    ]
    command_results = [_run_command(command) for command in commands]
    success = all(result["success"] for result in command_results)
    return {
        "type": "block_ip",
        "target": ip_address_value,
        "success": success,
        "details": "Created Windows Firewall rules to block the remote IP."
        if success
        else "Firewall IP block failed. Administrative permissions may be required.",
        "commands": command_results,
    }


def trigger_firewall_rule(port, protocol, attack_type):
    if port in (None, "", 0):
        return {
            "type": "firewall_rule",
            "target": port,
            "success": False,
            "details": "Skipped because no actionable port was provided.",
            "commands": [],
        }

    normalized_protocol = str(protocol or "TCP").upper()
    if normalized_protocol not in {"TCP", "UDP"}:
        normalized_protocol = "TCP"

    rule_name = _build_rule_name(
        "PortBlock",
        f"{attack_type or 'unknown'}-{normalized_protocol}-{port}",
    )
    command = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"protocol={normalized_protocol}",
        f"localport={int(port)}",
    ]
    command_result = _run_command(command)
    return {
        "type": "firewall_rule",
        "target": f"{normalized_protocol}/{port}",
        "success": command_result["success"],
        "details": "Created a Windows Firewall port block rule."
        if command_result["success"]
        else "Firewall port rule failed. Administrative permissions may be required.",
        "commands": [command_result],
    }


def kill_suspicious_process(process_id=None, process_name=None):
    command = None
    target = None
    if process_id not in (None, "", 0):
        target = str(process_id)
        command = ["taskkill", "/F", "/PID", target]
    elif process_name:
        target = str(process_name)
        command = ["taskkill", "/F", "/IM", target]

    if command is None:
        return {
            "type": "kill_process",
            "target": None,
            "success": False,
            "details": "Skipped because no suspicious PID or process name was provided.",
            "commands": [],
        }

    command_result = _run_command(command)
    return {
        "type": "kill_process",
        "target": target,
        "success": command_result["success"],
        "details": "Terminated the suspicious process."
        if command_result["success"]
        else "Process termination failed or the process was not found.",
        "commands": [command_result],
    }


def execute_incident_response(traffic_data, prediction_result=None):
    traffic_data = traffic_data or {}
    prediction_result = prediction_result or {}
    attack_type = traffic_data.get("attack_type") or "unknown"
    source_ip = traffic_data.get("source_ip")
    port = traffic_data.get("port")
    protocol = traffic_data.get("protocol")
    suspicious_pid = traffic_data.get("suspicious_pid")
    suspicious_process_name = traffic_data.get("suspicious_process_name")

    actions = [
        block_ip(source_ip),
        kill_suspicious_process(suspicious_pid, suspicious_process_name),
        trigger_firewall_rule(port, protocol, attack_type),
    ]
    success_count = sum(1 for action in actions if action.get("success"))
    incident_response = {
        "executed_at": _utc_timestamp(),
        "attack_type": attack_type,
        "triggered": True,
        "summary": f"Executed {success_count}/{len(actions)} containment actions.",
        "actions": actions,
    }

    _append_audit_log(
        {
            "event": "incident_response",
            "executed_at": incident_response["executed_at"],
            "attack_type": attack_type,
            "source_ip": source_ip,
            "suspicious_pid": suspicious_pid,
            "suspicious_process_name": suspicious_process_name,
            "prediction": prediction_result.get("prediction"),
            "response_summary": incident_response["summary"],
            "actions": actions,
        }
    )
    return incident_response
