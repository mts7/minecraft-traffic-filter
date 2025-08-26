import ipaddress
import socket
import subprocess  # nosec[B404]
from datetime import datetime

DOMAINS = [
    "device.auth.xboxlive.com",
    "user.auth.xboxlive.com",
    "xsts.auth.xboxlive.com",
    "login.live.com",
    "minecraftservices.com"
]


def resolve_domain(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def ping(ip: str) -> bool:
    try:
        result = subprocess.run(
            ["/sbin/ping", "-c", "2", "-W", "2", ip],  # nosec[B603]
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception:
        return False


def main():
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"Connectivity Check - {timestamp}\n")
    unreachable = []

    for domain in DOMAINS:
        ip = resolve_domain(domain)
        if not ip:
            print(f"{domain:<30} | Resolution failed")
            unreachable.append(domain)
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip}")

        reachable = ping(ip)
        status = "reachable" if reachable else "unreachable"
        print(f"{domain:<30} | {ip:<15} | {status}")
        if not reachable:
            unreachable.append(domain)

    if unreachable:
        print("\nUnreachable Domains:")
        for domain in unreachable:
            print(f"- {domain}")
    else:
        print("\n✅ All domains reachable.")


if __name__ == "__main__":
    main()
