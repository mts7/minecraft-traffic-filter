import os
import re
import subprocess  # nosec[B404]
import sys

PF_CONF_PATH = "/etc/pf.conf"


class BlockIPError(Exception):
    pass


def is_root() -> bool:
    return os.geteuid() == 0


def validate_ip(ip: str) -> bool:
    pattern = r"^\d{1,3}(\.\d{1,3}){3}(/(\d|[12]\d|3[0-2]))?$"
    return re.match(pattern, ip) is not None


def append_pf_rule(ip: str) -> None:
    rule = f"block drop from {ip} to any\n"
    with open(PF_CONF_PATH, "a") as f:
        f.write(rule)


def reload_pfctl() -> None:
    subprocess.run(["/sbin/pfctl", "-f", PF_CONF_PATH],
                   check=True, shell=False)  # nosec[B603]
    subprocess.run(["/sbin/pfctl", "-E"], check=True,
                   shell=False)  # nosec[B603]


def run_block_ip(argv: list[str]) -> None:
    if not is_root():
        raise BlockIPError("This script must be run as root. "
                           "Use 'sudo python block_ip.py <ip>'")

    if len(argv) != 2:
        raise BlockIPError("Usage: python block_ip.py <ip_address_or_subnet>")

    ip = argv[1]
    if not validate_ip(ip):
        raise BlockIPError(f"Invalid IP format: {ip}")

    print(f"Adding block rule for {ip} to {PF_CONF_PATH}...")
    append_pf_rule(ip)
    reload_pfctl()
    print("Block rule added and pfctl reloaded.")
    subprocess.run(["/sbin/pfctl", "-sr"], shell=False)  # nosec[B603]
    subprocess.run(["/bin/cat", PF_CONF_PATH], shell=False)  # nosec[B603]


def main() -> None:
    run_block_ip(sys.argv)


if __name__ == "__main__":
    try:
        main()
    except BlockIPError as e:
        print(e)
        sys.exit(1)
