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


def check_domain(domain: str) -> tuple[str, str, bool]:
    ip = resolve_domain(domain)
    if not ip:
        return domain, "Resolution failed", False

    validate_ip(ip)
    reachable = ping(ip)
    return domain, ip, reachable


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


def print_header() -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"Connectivity Check - {timestamp}\n")


def print_result(domain: str, ip_or_msg: str, reachable: bool) -> None:
    if ip_or_msg == "Resolution failed":
        print(f"{domain:<30} | {ip_or_msg}")
    else:
        status = "reachable" if reachable else "unreachable"
        print(f"{domain:<30} | {ip_or_msg:<15} | {status}")


def print_summary(unreachable: list[str]) -> None:
    if unreachable:
        print("\nUnreachable Domains:")
        for domain in unreachable:
            print(f"- {domain}")
    else:
        print("\n✅ All domains reachable.")


def resolve_domain(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def validate_ip(ip: str) -> None:
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip}")


def main() -> None:
    print_header()
    unreachable: list[str] = []

    for domain in DOMAINS:
        domain, ip_or_msg, reachable = check_domain(domain)
        print_result(domain, ip_or_msg, reachable)
        if not reachable:
            unreachable.append(domain)

    print_summary(unreachable)


if __name__ == "__main__":  # pragma: no cover
    main()
