import ipaddress

from ipwhois import IPDefinedError, IPWhois


def get_cidr_ipwhois(ip_address: str) -> str:
    """Call IPWhois RDAP lookup and return the ASN CIDR."""
    try:
        # TODO: use dependency injection with factory pattern
        obj = IPWhois(ip_address)
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
