from dataclasses import dataclass
import ipaddress
from typing import Optional, TypeVar, Iterator
import contextlib
import host
import json
import os
import glob
import socket
import tempfile
import typing


T = TypeVar("T")


def str_to_list(input_str: str) -> list[int]:
    result: set[int] = set()
    parts = input_str.split(',')

    for part in parts:
        if '-' in part:
            start, end = map(int, part.split('-'))
            result.update(range(start, end + 1))
        else:
            result.add(int(part))

    return sorted(result)


class RangeList:
    _range: list[tuple[bool, list[int]]] = []
    initial_values: Optional[list[int]] = None

    def __init__(self, initial_values: Optional[list[int]] = None):
        self.initial_values = initial_values

    def _append(self, lst: list[int], expand: bool) -> None:
        self._range.append((expand, lst))

    def include(self, lst: list[int]) -> None:
        self._append(lst, True)

    def exclude(self, lst: list[int]) -> None:
        self._append(lst, False)

    def filter_list(self, initial: list[T]) -> list[T]:
        applied = set(range(len(initial)))
        if self.initial_values is not None:
            applied &= set(self.initial_values)

        for expand, lst in self._range:
            if expand:
                applied = applied | set(lst)
            else:
                applied = applied - set(lst)
        return [initial[x] for x in sorted(applied) if x < len(initial)]


@dataclass
class IPRouteAddressInfoEntry:
    family: str
    local: str


@dataclass
class IPRouteAddressEntry:
    ifindex: int
    ifname: str
    flags: list[str]
    master: Optional[str]
    address: str  # Ethernet address.
    addr_info: list[IPRouteAddressInfoEntry]


def ipa(host: host.Host) -> str:
    return host.run("ip -json a").out


def ipa_to_entries(input: str) -> list[IPRouteAddressEntry]:
    j = json.loads(input)
    ret: list[IPRouteAddressEntry] = []
    for e in j:
        addr_infos = []
        for addr in e["addr_info"]:
            addr_infos.append(IPRouteAddressInfoEntry(addr["family"], addr["local"]))

        master = e["master"] if "master" in e else None

        ret.append(IPRouteAddressEntry(e["ifindex"], e["ifname"], e["flags"], master, e["address"], addr_infos))
    return ret


def ipr(host: host.Host) -> str:
    return host.run("ip -json r").out


@dataclass
class IPRouteRouteEntry:
    dst: str
    dev: str


def ipr_to_entries(input: str) -> list[IPRouteRouteEntry]:
    j = json.loads(input)
    ret: list[IPRouteRouteEntry] = []
    for e in j:
        ret.append(IPRouteRouteEntry(e["dst"], e["dev"]))
    return ret


def ip_range(start_addr: str, n_addrs: int) -> tuple[str, str]:
    return start_addr, str(ipaddress.ip_address(start_addr) + n_addrs)


def ip_range_contains(range: tuple[str, str], ip: str) -> bool:
    ip_val = ipaddress.IPv4Address(ip)
    return ipaddress.IPv4Address(range[0]) <= ip_val and ipaddress.IPv4Address(range[1]) > ip_val


def ip_range_size(range: tuple[str, str]) -> int:
    return int(ipaddress.IPv4Address(range[1])) - int(ipaddress.IPv4Address(range[0]))


def ip_in_subnet(addr: str, subnet: str) -> bool:
    return ipaddress.ip_address(addr) in ipaddress.ip_network(subnet)


def ipaddr_norm(addr: str | bytes) -> Optional[str]:
    # Normalize a string that contains an IP address (IPv4 or IPv6). On error,
    # return None.

    if isinstance(addr, bytes):
        # For convenience, also accept bytes (we might have read them
        # from file).
        try:
            addr = addr.decode('utf-8', errors='strict')
        except ValueError:
            return None
    elif not isinstance(addr, str):
        raise TypeError(f"ip address must be str | bytes but is {type(addr)}")

    # For convenience, accept leading/trailing whitespace
    addr = addr.strip()

    if ':' in addr:
        family = socket.AF_INET6
    else:
        family = socket.AF_INET

    try:
        a = socket.inet_pton(family, addr)
    except OSError:
        return None

    return socket.inet_ntop(family, a)


def extract_interfaces(input: str) -> list[str]:
    entries = ipa_to_entries(input)
    return [x.ifname for x in entries]


def find_port(host: host.Host, port_name: str) -> Optional[IPRouteAddressEntry]:
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
    if port_name == "auto":
        port_name = get_auto_port(host)

    entries = ipa_to_entries(ipa(host))
    for entry in entries:
        if entry.ifname == port_name:
            for addr in entry.addr_info:
                if addr.family == "inet":
                    return addr.local
    return None


def carrier_no_addr(host: host.Host) -> list[IPRouteAddressEntry]:
    def carrier_no_addr(intf: IPRouteAddressEntry) -> bool:
        return len(intf.addr_info) == 0 and "NO-CARRIER" not in intf.flags

    entries = ipa_to_entries(ipa(host))

    return [x for x in entries if carrier_no_addr(x)]


def get_auto_port(host: host.Host) -> str:
    interfaces = carrier_no_addr(host)
    if len(interfaces) == 0:
        raise ValueError("No interfaces found for auto port")
    else:
        return interfaces[0].ifname


def iterate_ssh_keys() -> Iterator[tuple[str, str, str]]:
    for pub_file in glob.glob("/root/.ssh/*.pub"):
        with open(pub_file, 'r') as f:
            pub_key_content = f.read().strip()
            priv_key_file = os.path.splitext(pub_file)[0]
            yield pub_file, pub_key_content, priv_key_file


def kubeconfig_get_paths(cluster_name: str, kubeconfig_path: Optional[str]) -> tuple[str, str, str, str]:
    # AssistedClient.download_kubeconfig() downloads the kubeconfig at a
    # particular place, determined by the @cluster_name and @kubeconfig_path.
    #
    # This function calculates the resulting file names where we can find these
    # files.
    if kubeconfig_path:
        kubeconfig_path = os.path.abspath(kubeconfig_path)
        path = os.path.dirname(kubeconfig_path)
    else:
        path = os.path.abspath(os.getcwd())

    downloaded_kubeadminpassword_path = f"{path}/kubeadmin-password.{cluster_name}"
    downloaded_kubeconfig_path = f"{path}/kubeconfig.{cluster_name}"

    if not kubeconfig_path:
        kubeconfig_path = downloaded_kubeconfig_path

    return path, kubeconfig_path, downloaded_kubeconfig_path, downloaded_kubeadminpassword_path


def kubeconfig_read_kubeadminpassword(cluster_name: str, kubeconfig_path: Optional[str]) -> str:
    path, kubeconfig_path, downloaded_kubeconfig_path, downloaded_kubeadminpassword_path = kubeconfig_get_paths(cluster_name, kubeconfig_path)

    try:
        with open(downloaded_kubeadminpassword_path) as f:
            kubeadminpassword = f.read()
    except Exception:
        raise RuntimeError(f"Cannot read kubeadmin password from {downloaded_kubeadminpassword_path}")

    return kubeadminpassword


# See:
#  - https://discuss.python.org/t/adding-atomicwrite-in-stdlib/11899
#  - https://stackoverflow.com/questions/2333872/how-to-make-file-creation-an-atomic-operation
#  - https://code.activestate.com/recipes/579097-safely-and-atomically-write-to-a-file/
@contextlib.contextmanager
def atomic_write(
    filename: str,
    *,
    text: bool = True,
    keep: bool = False,
    owner: Optional[int] = None,
    group: Optional[int] = None,
    mode: int = 0o644,
) -> Iterator[typing.IO[typing.Any]]:
    if owner is None:
        owner = -1
    if group is None:
        group = -1

    path = os.path.dirname(filename)
    basename = os.path.basename(filename)
    prefix = basename + "."

    tmp: Optional[str]

    fd_close = True
    fd, tmp = tempfile.mkstemp(prefix=prefix, dir=path, text=text)

    try:
        with os.fdopen(fd, 'w' if text else 'wb', closefd=False) as f:
            yield f

        # We update the owner, group and permission before renaming
        # the file. Unfortunately, this could result in no longer having
        # the suitable permissions to rename. Don't set permissions
        # that cut yourself off.
        if owner >= 0 or group >= 0:
            os.fchown(fd, owner, group)
        os.fchmod(fd, mode)

        fd_close = False
        try:
            os.close(fd)
        except IOError:
            pass

        os.replace(tmp, filename)
        tmp = None
    finally:
        if fd_close:
            try:
                os.close(fd)
            except IOError:
                pass
        if (tmp is not None) and (not keep):
            try:
                os.unlink(tmp)
            except IOError:
                pass
