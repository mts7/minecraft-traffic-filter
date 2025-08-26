import ipaddress
import json
import os

from ipwhois import IPWhois  # type: ignore[import-untyped]
from ipwhois.exceptions import IPDefinedError  # type: ignore[import-untyped]

CACHE_FILE = "cache_rdap.json"


def load_cache() -> dict[str, str]:
    if not os.path.exists(CACHE_FILE):
        return {}
    with open(CACHE_FILE, "r") as f:
        return json.load(f)


def save_cache(cache_contents):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache_contents, f, indent=2)


def get_cidr_ipwhois(ip_address: str, cache_values):
    if ip_address in cache_values:
        print(f"found {ip_address} in cache")
        return cache_values[ip_address]

    try:
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap(depth=1)
        cidr = result.get("asn_cidr")
        if cidr:
            cache_values[ip_address] = cidr
        print(ip_address, cidr)
        return cidr
    except IPDefinedError as e:
        print(f"IPDefinedError with {e}")
        return None
    except Exception as e:
        print(f"Unknown exception: {e}")
        return None


def aggregate_ips(ips: list[str], cache_values: dict):
    unresolved_ips = []
    result = []

    for ip_address in ips:
        if is_cidr(ip_address):
            cidr = ip_address
        else:
            cidr = get_cidr_ipwhois(ip_address, cache_values)
        if cidr:
            result.append(cidr)
        else:
            unresolved_ips.append(ip_address)

    return list(set(result)), unresolved_ips


def format_block_line(cidr: str) -> str:
    return f"block drop from {cidr} to any"


def is_cidr(ip_address: str) -> bool:
    try:
        ipaddress.ip_network(ip_address, strict=False)
        return '/' in ip_address
    except ValueError as e:
        print(f"ValueError: {e}")
        return False


if __name__ == "__main__":
    ip_list = [
        # "20.14.73.238",
        # "20.65.193.35",
        # "20.65.194.162",
        # "23.159.216.40",
        # "23.160.24.166",
        # "23.162.8.84",
        # "23.168.216.40",
        # "23.176.184.152",
        # "23.234.64.0/18",
        # "23.234.88.166",
        # "23.234.100.40",
        # "23.234.103.40",
        # "23.234.116.22",
        # "37.19.200.133",
        # "37.19.200.146",
        # "37.19.210.4",
        # "37.19.221.146",
        # "37.19.221.159",
        # "37.19.221.172",
        # "43.225.189.137",
        # "45.95.147.247",
        # "45.134.142.209",
        # "45.134.142.221",
        # "45.148.10.134",
        # "46.19.136.228",
        # "46.19.140.218",
        # "47.34.15.51",
        # "51.15.34.47",
        # "51.15.229.249",
        # "51.158.174.200",
        # "52.165.90.3",
        # "68.235.46.10",
        # "68.235.46.41",
        # "68.235.46.72",
        # "68.235.46.103",
        # "68.235.46.134",
        # "68.235.46.161",
        # "68.235.46.195",
        # "79.127.217.37",
        # "79.127.222.210",
        # "80.78.27.67",
        # "82.65.101.158",
        # "82.102.19.87",
        # "82.102.19.90",
        # "86.54.31.34",
        # "87.236.176.196",
        # "87.249.134.17",
        # "91.90.44.21",
        # "91.207.57.140",
        # "95.111.227.12",
        # "103.81.230.22",
        # "103.81.230.40",
        # "103.81.230.166",
        # "103.81.231.40",
        # "103.81.231.166",
        # "103.102.246.0/23",
        # "103.251.26.40",
        # "103.251.26.166",
        # "104.36.50.11",
        # "138.199.15.164",
        # "138.199.21.241",
        # "138.199.43.68",
        # "141.98.252.173",
        # "141.98.254.173",
        # "141.98.255.144",
        # "143.244.47.68",
        # "143.244.47.81",
        # "146.70.0.0/16",
        # "146.70.171.142",
        # "147.185.132.42",
        # "149.40.50.102",
        # "155.2.190.13",
        # "155.2.190.48",
        # "155.2.190.118",
        # "155.2.190.188",
        # "155.248.209.22",
        # "156.146.63.150",
        # "161.97.151.83",
        # "162.142.125.206",
        # "167.94.145.104",
        # "167.94.146.63",
        # "172.202.118.46",
        # "176.65.134.5",
        # "176.65.134.6",
        # "176.65.134.6",
        # "176.65.148.0/24",
        # "176.65.148.103",
        # "176.65.148.103",
        # "176.65.148.127",
        # "176.65.148.136",
        # "176.65.148.234",
        # "176.65.148.244",
        # "178.16.54.25",
        # "185.65.134.152",
        # "185.65.135.161",
        # "185.141.119.138",
        # "185.156.46.159",
        # "185.188.61.197",
        # "185.204.1.183",
        # "185.212.149.207",
        # "185.213.154.148",
        # "185.213.155.158",
        # "193.32.126.138",
        # "193.32.126.224",
        # "193.32.127.144",
        # "193.32.127.154",
        # "193.56.135.121",
        # "193.138.7.179",
        # "193.138.218.161",
        # "198.235.24.104",
        # "199.45.155.77",
        # "205.210.31.202",
        # "205.210.31.245",
        # "205.210.171.1",
        # "205.210.171.2",
        # "206.168.34.77",
        # "217.144.184.3",
        # "95.173.222.51",
        # "194.127.199.139",
        # "40.76.116.231",
        # "142.147.89.229",
        # "23.162.40.40",
        # "85.109.153.174",
        "40.80.206.215",
        "51.158.65.133",
        "104.234.115.94",
        "155.2.191.22",
        "155.2.191.72",
        "155.2.191.223",
        "167.94.138.164",
        "185.213.193.166",
        "192.241.179.235",
        "204.76.203.35",
    ]

    cache = load_cache()
    aggregated, failed = aggregate_ips(ip_list, cache)
    save_cache(cache)

    print("\n✅ Aggregated CIDRs and IPs:")
    for entry in sorted(aggregated):
        print(format_block_line(entry))

    if failed:
        print("\n⚠️ Unresolved IPs:")
        for ip in failed:
            print(format_block_line(ip))
