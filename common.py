import ipaddress
from typing import List
from typing import Optional
import host


def ip_in_subnet(addr: str, subnet: str) -> bool:
    return ipaddress.ip_address(addr) in ipaddress.ip_network(subnet)


def extract_ip(ipa: dict, port_name: str) -> str:
    interface = next(x for x in ipa if x["ifname"] == port_name)
    inet = next(x for x in interface["addr_info"] if x["family"] == "inet")
    return inet["local"]


def extract_port(ipr: dict, route: str) -> str:
    rt = next(x for x in ipr if x["dst"] == route)
    return rt["dev"]


def extract_interfaces(ipa: dict) -> List[str]:
    return [x["ifname"] for x in ipa]


def find_port(host, port_name: str) -> Optional[dict]:
    for e in host.all_ports():
        if e["ifname"] == port_name:
            return e
    return None


def route_to_port(host: host.Host, route: str) -> str:
    return extract_port(host.ipr(), route)


def port_to_ip(host: host.Host, port_name: str) -> str:
    return extract_ip(host.ipa(), port_name)
