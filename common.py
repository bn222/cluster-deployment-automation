from dataclasses import dataclass
import ipaddress
from threading import local
from typing import List
from typing import Optional
import host
import json


@dataclass
class IPRouteAddressInfoEntry:
    family: str
    local: str


@dataclass
class IPRouteAdressEntry:
    ifindex: int
    ifname: str
    flags: List[str]
    master: Optional[str]
    addr_info: List[IPRouteAddressInfoEntry]


def ipa(host: host.Host) -> str:
    return host.run("ip a -json").out


def ipa_to_entries(input: str) -> List[IPRouteAdressEntry]:
    j = json.loads(input)
    ret: List[IPRouteAdressEntry] = []
    for e in j:
        addr_infos = []
        for addr in e["addr_info"]:
            addr_infos.append(IPRouteAddressInfoEntry(addr["family"], addr["local"]))

        master = e["master"] if "master" in e else None

        ret.append(IPRouteAdressEntry(e["ifindex"], e["ifname"], e["flags"], master, addr_infos))
    return ret


def ipr(host: host.Host) -> str:
    return host.run("ip r -json").out


@dataclass
class IPRouteRouteEntry:
    dst: str
    dev: str


def ipr_to_entries(input: str) -> List[IPRouteRouteEntry]:
    j = json.loads(input)
    ret: List[IPRouteRouteEntry] = []
    for e in j:
        ret.append(IPRouteRouteEntry(e["dst"], e["dev"]))
    return ret


def ip_in_subnet(addr: str, subnet: str) -> bool:
    return ipaddress.ip_address(addr) in ipaddress.ip_network(subnet)


def extract_interfaces(input: str) -> List[str]:
    entries = ipa_to_entries(input)
    return [x.ifname for x in entries]


def find_port(host: host.Host, port_name: str) -> Optional[IPRouteAdressEntry]:
    entries = ipa_to_entries(ipa(host))
    for entry in entries:
        if entry.ifname == port_name:
            return entry
    return None


def route_to_port(host: host.Host, route: str) -> Optional[str]:
    entries = ipr_to_entries(ipr(host))
    for e in entries:
        if e.dst == route:
            return e.dev
    return None


def port_to_ip(host: host.Host, port_name: str) -> Optional[str]:
    entries = ipa_to_entries(ipa(host))
    for entry in entries:
        if entry.ifname == port_name:
            for addr in entry.addr_info:
                if addr.family == "inet":
                    return addr.local
    return None


def carrier_no_addr(host: host.Host) -> List[IPRouteAdressEntry]:
    def carrier_no_addr(intf: IPRouteAdressEntry) -> bool:
        return len(intf.addr_info) == 0 and "NO-CARRIER" not in intf.flags

    entries = ipa_to_entries(ipa(host))

    return [x for x in entries if carrier_no_addr(x)]
