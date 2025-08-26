import os
import re
import subprocess  # nosec[B404]
import sys

PF_CONF_PATH = "/etc/pf.conf"


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


def main() -> None:
    if not is_root():
        print("This script must be run as root. "
              "Use 'sudo python block_ip.py <ip>'")
        sys.exit(1)

    if len(sys.argv) != 2:
        print("Usage: python block_ip.py <ip_address_or_subnet>")
        sys.exit(1)

    ip = sys.argv[1]
    if not validate_ip(ip):
        print(f"Invalid IP format: {ip}")
        sys.exit(1)

    print(f"Adding block rule for {ip} to {PF_CONF_PATH}...")
    append_pf_rule(ip)
    reload_pfctl()
    print("Block rule added and pfctl reloaded.")
    subprocess.run(["/sbin/pfctl", "-sr"], shell=False)  # nosec[B603]
    subprocess.run(["/bin/cat", PF_CONF_PATH], shell=False)  # nosec[B603]


if __name__ == "__main__":
    main()
