import ipaddress
import os
import re
import subprocess  # nosec[B404]
from typing import Optional

from dotenv import load_dotenv

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(SCRIPT_DIR, "monitor_output.log")


def build_tcpdump_command(host: str) -> list[str]:
    interface = os.getenv("NETWORK_INTERFACE", "en1")
    return [
        "sudo",
        "tcpdump",
        "-i", interface,
        "-nnA",
        f"host {host} and "
        "(port 25565 or port 19132) and "
        "tcp[tcpflags] & tcp-push != 0 and len > 60"
    ]


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
    return match.group(1) if match else None


def get_host_ip() -> str:
    host = os.getenv("IP_ADDRESS", "")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        raise ValueError(f"Invalid IP address: {host}")


def load_allowed_ips() -> set[str]:
    raw = os.getenv("ALLOWED_IPS", "")
    return set(ip.strip() for ip in raw.split(",") if ip.strip())


def process_tcpdump_output(
    process: subprocess.Popen[str],
    allowed_ips: set[str],
    log_file: str
) -> None:
    tracked_ips: set[str] = set()
    if process.stdout is None:
        raise RuntimeError("Expected process.stdout to be non-None")

    print(f"Retrieved {len(allowed_ips)} allowed IPs")
    print("Checking each output line")

    for line in process.stdout:
        ip = extract_destination_ip(line)
        try:
            ip = validate_ip_for_tracking(ip, tracked_ips, allowed_ips)
        except ValueError:
            continue
        track_ip(ip, tracked_ips, log_file)


def run_tcpdump() -> None:
    """
    Executes the tcpdump command and prints destination IPs from output.
    """
    host = get_host_ip()
    command = build_tcpdump_command(host)
    print(f"command: {command}")

    process: subprocess.Popen[str] = start_tcpdump(command)

    try:
        allowed_ips = load_allowed_ips()
        process_tcpdump_output(process, allowed_ips, LOG_FILE)
    except KeyboardInterrupt:
        print("\nStopped monitoring.")
        process.terminate()


def should_track_ip(ip: str, tracked: set[str], allowed: set[str]) -> bool:
    return ip not in tracked and ip not in allowed


def start_tcpdump(command: list[str]) -> subprocess.Popen[str]:
    return subprocess.Popen(  # nosec[B603]
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )


def track_ip(ip: str, tracked: set[str], log_file: str) -> None:
    tracked.add(ip)
    print(f"Destination IP: {ip}")
    with open(log_file, "a") as f:
        f.write(f"{ip}\n")


def validate_ip_for_tracking(
    ip: Optional[str],
    tracked: set[str],
    allowed: set[str]
) -> str:
    if ip is None:
        raise ValueError("No IP extracted")
    if ip in tracked:
        raise ValueError("IP already tracked")
    if ip in allowed:
        raise ValueError("IP is allowed")
    return ip


if __name__ == "__main__":  # pragma: no cover
    load_dotenv()
    run_tcpdump()
