import ipaddress
import os
import re
import subprocess  # nosec[B404]
from typing import Optional

from dotenv import load_dotenv

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "monitor_output.log")


def extract_destination_ip(line: str) -> Optional[str]:
    """
    Extracts the destination IP address from a tcpdump output line.

    Args:
        line (str): A single line of tcpdump output.

    Returns:
        Optional[str]: The destination IP address, or None if not found.
    """
    pattern: str = r'> (\d+\.\d+\.\d+\.\d+)\.\d+:'
    match: Optional[re.Match] = re.search(pattern, line)
    if match:
        return match.group(1)
    return None


def load_allowed_ips() -> set[str]:
    raw = os.getenv("ALLOWED_IPS", "")
    return set(ip.strip() for ip in raw.split(",") if ip.strip())


def run_tcpdump() -> None:
    """
    Executes the tcpdump command and prints destination IPs from output.
    """
    # TODO: refactor to lower cyclomatic complexity
    host = os.getenv("IP_ADDRESS", "")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise ValueError(f"Invalid IP address: {host}")

    command: list[str] = [
        "sudo",
        "tcpdump",
        "-i", os.getenv("NETWORK_INTERFACE", "en1"),
        "-nnA",
        f"host {host} and "
        "(port 25565 or port 19132) and "
        "tcp[tcpflags] & tcp-push != 0 and len > 60"
    ]
    print(f"command: {command}")

    process: subprocess.Popen[str] = subprocess.Popen(
        command,  # nosec[B603]
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )

    try:
        tracked_ips: set[str] = set()
        allowed_ips = load_allowed_ips()
        print(f"Retrieved {len(allowed_ips)} allowed IPs")
        if process.stdout is None:
            raise RuntimeError("Expected process.stdout to be non-None")
        print("Checking each output line")
        for line in process.stdout:
            ip: Optional[str] = extract_destination_ip(line)
            if ip and should_track_ip(ip, tracked_ips, allowed_ips):
                track_ip(ip, tracked_ips, LOG_FILE)
    except KeyboardInterrupt:
        print("\nStopped monitoring.")
        process.terminate()


def should_track_ip(ip: str, tracked: set[str], allowed: set[str]) -> bool:
    return ip not in tracked and ip not in allowed


def track_ip(ip: str, tracked: set[str], log_file: str) -> None:
    tracked.add(ip)
    print(f"Destination IP: {ip}")
    with open(log_file, "a") as f:
        f.write(f"{ip}\n")


if __name__ == "__main__":  # pragma: no cover
    load_dotenv()
    run_tcpdump()
