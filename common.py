import ipaddress
from typing import List
from typing import Optional


def ip_in_subnet(addr, subnet) -> bool:
    return ipaddress.ip_address(addr) in ipaddress.ip_network(subnet)


def first(ll, x):
    return next(filter(ll, x))


def extract_ip(ipa: dict, port_name: str) -> str:
    interface = first(lambda x: x["ifname"] == port_name, ipa)
    inet = first(lambda x: x["family"] == "inet", interface["addr_info"])
    return inet["local"]


def extract_port(ipr: dict, route: str) -> str:
    rt = first(lambda x: x["dst"] == route, ipr)
    return rt["dev"]


def extract_interfaces(ipa: dict) -> List[str]:
    return [x["ifname"] for x in ipa]


def find_port(host, port_name: str) -> Optional[dict]:
    for e in host.all_ports():
        if e["ifname"] == port_name:
            return e
    return None
