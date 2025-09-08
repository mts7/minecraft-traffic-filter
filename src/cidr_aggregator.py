import os

from ipwhois import IPWhois  # type: ignore

from cidr_resolver import CidrResolver
from utilities.file_cache import FileCache
from utilities.network import WhoisStrategy, format_block_line

script_dir = os.path.dirname(os.path.abspath(__file__))
CACHE_FILE = os.path.join(script_dir, "cache_rdap.json")


def main(ips: list[str], cache: FileCache[str, str],
         strategy: WhoisStrategy) -> None:
    resolver = CidrResolver(cache, strategy)
    aggregated, failed = resolver.aggregate_ips(ips)

    print("\n✅ Aggregated CIDRs and IPs:")
    for entry in sorted(aggregated):
        print(format_block_line(entry))

    if failed:
        print("\n⚠️ Unresolved IPs:")
        for ip in failed:
            print(format_block_line(ip))


if __name__ == "__main__":  # pragma: no cover
    ip_cache = FileCache[str, str](CACHE_FILE)
    whois_strategy = WhoisStrategy(IPWhois)

    ip_list: list[str] = [
        "9.234.8.54",
        "20.14.89.71",
        "20.150.195.172",
        "45.55.185.224",
        "89.213.174.77",
        "103.108.231.59",
        "107.170.65.169",
        "135.119.88.104",
        "146.190.156.6",
        "149.22.91.88",
        "149.88.20.202",
        "149.88.20.215",
        "185.77.218.11",
        "185.195.232.147",
        "185.195.233.155",
        "185.254.75.52",
        "198.44.129.53",
        "198.44.129.117",
        "208.131.130.75",
    ]

    main(ip_list, ip_cache, whois_strategy)
