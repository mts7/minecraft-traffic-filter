import time

from ipwhois import ASNRegistryError, HTTPLookupError

from utilities.file_cache import FileCache
from utilities.network import get_cidr_ipwhois, is_cidr


class CidrResolver:
    def __init__(self, cache: FileCache[str, str]):
        self.cache = cache
        self.requests = 0
        self.batch_size = 10
        self.delay = 5

    def get_cidr(self, ip_address: str) -> str:
        """Get CIDR from cache or lookup if not cached."""
        try:
            if ip_address in self.cache:
                print(f"found {ip_address} in cache")
                return self.cache[ip_address]

            cidr = get_cidr_ipwhois(ip_address)
            self.cache[ip_address] = cidr
            self.requests += 1
            return cidr

        except (HTTPLookupError, ASNRegistryError, ConnectionResetError) as e:
            print(
                f"Recoverable error for {ip_address}: {type(e).__name__}: {e}")
            raise
        except Exception as e:
            print(
                f"Unexpected error for {ip_address}: {type(e).__name__}: {e}")
            raise

    def resolve_ip(self, ip_address: str) -> str:
        """
        Return CIDR if IP, or return the CIDR directly
        if input is already a CIDR.
        """
        return ip_address if is_cidr(ip_address) else self.get_cidr(ip_address)

    def aggregate_ips(self, ips: list[str]) -> tuple[list[str], list[str]]:
        unresolved_ips: list[str] = []
        result: list[str] = []

        for ip_address in ips:
            try:
                cidr = self.resolve_ip(ip_address)
                if cidr:
                    result.append(cidr)
                else:
                    unresolved_ips.append(ip_address)
            except Exception:
                unresolved_ips.append(ip_address)

            check_throttle(self.requests, self.batch_size, self.delay)

        return list(dict.fromkeys(result)), unresolved_ips


def check_throttle(requests: int, size: int, delay: int) -> None:
    if requests % size == 0 and requests > 0:
        time.sleep(delay)
