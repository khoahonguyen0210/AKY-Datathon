"""Address helpers for log fields.

RFC 1918, loopback, and link-local addresses are internal. Documentation
ranges such as TEST-NET are external: current Python marks them private,
and the sample data uses them on purpose.
"""

import ipaddress

_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def is_internal(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local:
        return True
    if addr.version == 4:
        return any(addr in network for network in _RFC1918)
    return bool(addr.is_private)
