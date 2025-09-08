import ipaddress

from ipwhois import IPDefinedError  # type: ignore


class WhoisStrategy:
    def __init__(self, whois_factory):
        """
        whois_factory: callable, e.g. IPWhois or a mock for testing
        """
        self.whois_factory = whois_factory

    def get_cidr(self, ip_address: str) -> str:
        """Call IPWhois RDAP lookup and return the ASN CIDR."""
        try:
            obj = self.whois_factory(ip_address)
            result = obj.lookup_rdap(depth=1)
            cidr = result.get("asn_cidr")
            print(ip_address, cidr)
            return cidr
        except IPDefinedError as e:
            print(f"IPDefinedError with {e}")
            raise
        except Exception as e:
            print(f"Unknown exception: {type(e).__name__}: {e}")
            raise


def is_cidr(ip_address: str) -> bool:
    try:
        ipaddress.ip_network(ip_address, strict=False)
        return "/" in ip_address
    except ValueError as e:
        print(f"ValueError: {e}")
        return False


def format_block_line(cidr: str) -> str:
    return f"block drop from {cidr} to any"
