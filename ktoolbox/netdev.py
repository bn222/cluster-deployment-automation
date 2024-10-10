import json
import os
import re
import socket

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from typing import Optional
from typing import Union

from . import host
from . import common

from .common import strict_dataclass
from .common import dict_add_optional


def _parse_line(line: str, caption: str) -> Optional[str]:
    if line.startswith(caption):
        return line[len(caption) :]
    return None


_isspace_kernel_set = {c[0] for c in (b" ", b"\n", b"\t", b"\r", b"\f", b"\v", b"\240")}


def isspace_kernel(c: Union[int, bytes]) -> bool:
    # mirrors kernel's isspace() from "include/linux/ctype.h", which treats as
    # space the common ASCII spaces, including '\v' (vertical tab), but also
    # '\240' (non-breaking space, NBSP in Latin-1). */
    if isinstance(c, int):
        if c < 0 or c > 255:
            raise ValueError("Integer is not a valid byte")
    elif isinstance(c, bytes):
        if len(c) != 1:
            raise ValueError("Requires a single byte as argument")
        c = c[0]
    else:
        raise TypeError("Expects either an integer or a single byte")

    return c in _isspace_kernel_set


def validate_addr_family(
    addr_family: Optional[Union[str, int]],
    *,
    with_unspec: bool = False,
) -> int:
    if addr_family is None:
        if with_unspec:
            return socket.AF_UNSPEC
    elif isinstance(addr_family, int):
        if addr_family in (socket.AF_INET, socket.AF_INET6):
            return addr_family
        if with_unspec:
            if addr_family == socket.AF_UNSPEC:
                return addr_family
    elif isinstance(addr_family, str):
        af2 = addr_family.lower().strip()
        if af2 in ("4", "inet", "inet4", "ipv4", "ip4", "addr4"):
            return socket.AF_INET
        if af2 in ("6", "inet6", "ipv6", "ip6", "addr6"):
            return socket.AF_INET6
        if with_unspec:
            if af2 in ("", "any", "unspec"):
                return socket.AF_UNSPEC
    raise ValueError(f"invalid address family {repr(addr_family)}")


def addr_family_to_str(addr_family: Optional[Union[str, int]]) -> str:
    addr_family = validate_addr_family(addr_family, with_unspec=True)
    if addr_family == socket.AF_INET:
        return "IPv4"
    if addr_family == socket.AF_INET6:
        return "IPv6"
    return "IP"


def validate_ipaddr(
    addr: str,
    *,
    addr_family: Optional[Union[str, int]] = None,
) -> tuple[str, int]:
    addr_orig = addr
    addr_family = validate_addr_family(addr_family, with_unspec=True)

    addrbin = None

    if isinstance(addr, str):
        # We accept whitespace. Strip it.
        addr = addr.strip()

    if addr_family in (socket.AF_INET, socket.AF_UNSPEC):
        try:
            addrbin = socket.inet_pton(socket.AF_INET, addr)
        except socket.error:
            pass
        else:
            addr_family = socket.AF_INET

    if addrbin is None and addr_family in (socket.AF_INET6, socket.AF_UNSPEC):
        try:
            addrbin = socket.inet_pton(socket.AF_INET6, addr)
        except socket.error:
            pass
        else:
            addr_family = socket.AF_INET6
        if (
            addrbin is None
            and isinstance(addr, str)
            and len(addr) > 2
            and addr[0] == "["
            and addr[-1] == "]"
        ):
            # Maybe the IPv6 address is wrapped in []. Retry.
            try:
                addrbin = socket.inet_pton(socket.AF_INET6, addr[1:][0:-1])
            except socket.error:
                pass
            else:
                addr_family = socket.AF_INET6
    if addrbin is None:
        raise ValueError(
            f"{repr(addr_orig)} is not a valid {addr_family_to_str(addr_family)} address"
        )

    addr2 = socket.inet_ntop(addr_family, addrbin)
    return addr2, addr_family


def normalize_ifname(
    ifname: Union[str, bytes],
    *,
    validate: bool = False,
    allow_reserved: bool = True,
) -> bytes:
    if isinstance(ifname, str):
        ifname = ifname.encode("utf-8", errors="surrogateescape")
    elif not isinstance(ifname, bytes):
        raise TypeError(f"Unexpected ifname of type {type(ifname)}")

    if validate:
        if not ifname:
            raise ValueError("Ifname cannot be empty")
        if b"/" in ifname:
            raise ValueError("Ifname cannot contain slash")
        if ifname in (b".", b".."):
            raise ValueError(f'Ifname cannot be "{ifname.decode()}"')
        if len(ifname) > 15:
            raise ValueError("Ifname cannot be longer than 15 characters")
        if b":" in ifname:
            raise ValueError("Ifname cannot contain colon")
        for c in ifname:
            if c == 0:
                raise ValueError("Invalid zero bytes")
            if isspace_kernel(c):
                raise ValueError("Invalid white space")
        if not allow_reserved:
            # Certain modules create sysctl files that later prevent creating
            # interfaces with those names. However, you can create those interfaces
            # if the module is not loaded.
            #
            # You are advised to not use those interface names, but you can
            # create such interfaces in kernel (if the conflicting module is
            # not loaded).
            #
            # The "all" and "default" names are reserved
            # due to their directories in "/proc/sys/net/ipv4/conf/" and "/proc/sys/net/ipv6/conf/".
            # Also, there is "/sys/class/net/bonding_masters" file.
            if ifname in (
                b"all",
                b"default",
                b"bonding_masters",
            ):
                raise ValueError(f"Interface name {repr(ifname)} is reserved")

    return ifname


def validate_ifname(
    ifname: Union[str, bytes],
    *,
    allow_reserved: bool = True,
) -> str:
    # The main point of this validation is whether this can be used
    # safely in a path name.
    #
    # See also, dev_valid_name() in kernel.
    ifname = normalize_ifname(ifname, validate=True, allow_reserved=allow_reserved)
    return ifname.decode(errors="surrogateescape")


def validate_ifname_or_none(ifname: Union[str, bytes]) -> Optional[str]:
    try:
        return validate_ifname(ifname)
    except ValueError:
        return None


_pciaddr_re = re.compile("^[0-9a-f]{4}:[0-9a-f]{2}:[01][0-9a-f].[0-7]$")


def validate_pciaddr(pciaddr: Union[str, bytes]) -> str:
    # The main point of this validation is whether this can be used
    # safely in a path name.
    if isinstance(pciaddr, bytes):
        try:
            pciaddr = pciaddr.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError(
                f"PCI address cannot contain non UTF-8 characters ({repr(pciaddr)})"
            )
    elif not isinstance(pciaddr, str):
        raise TypeError(f"PCI address of unexpected type {type(pciaddr)}")
    if not pciaddr:
        raise ValueError("PCI address cannot be empty")
    if not _pciaddr_re.search(pciaddr):
        raise ValueError(f"PCI address contains invalid characters ({repr(pciaddr)})")
    if pciaddr in (".", ".."):
        raise ValueError(f'PCI address cannot be "{pciaddr}"')
    return pciaddr


_ethaddr_re = re.compile(
    "^([0-9a-fA-F][0-9a-fA-F]?):([0-9a-fA-F][0-9a-fA-F]?):([0-9a-fA-F][0-9a-fA-F]?):([0-9a-fA-F][0-9a-fA-F]?):([0-9a-fA-F][0-9a-fA-F]?):([0-9a-fA-F][0-9a-fA-F]?)$"
)


def validate_ethaddr(ethaddr: Union[str, bytes]) -> str:
    # The main point of this validation is whether this can be used
    # safely in a path name.
    if isinstance(ethaddr, bytes):
        try:
            ethaddr = ethaddr.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError(
                f"Ethernet address cannot contain non UTF-8 characters ({repr(ethaddr)})"
            )
    elif not isinstance(ethaddr, str):
        raise TypeError(f"Ethernet address of unexpected type {type(ethaddr)}")
    m = _ethaddr_re.search(ethaddr)
    if not m:
        raise ValueError(
            f"Ethernet address contains invalid characters ({repr(ethaddr)})"
        )

    def _normalize_hex(s: str) -> str:
        s = s.lower()
        if len(s) == 1:
            return "0" + s
        return s

    ethaddr2 = ":".join(_normalize_hex(m.group(i)) for i in range(1, 7))
    if ethaddr2 == ethaddr:
        return ethaddr
    return ethaddr2


def validate_ethaddr_or_none(ethaddr: Union[str, bytes]) -> Optional[str]:
    try:
        return validate_ethaddr(ethaddr)
    except ValueError:
        return None


def pciaddr_get_func_address(pciaddr: Optional[Union[str, bytes]]) -> Optional[int]:
    # https://github.com/k8snetworkplumbingwg/sriovnet/blob/master/sriovnet_switchdev.go#L172
    if pciaddr is None:
        return None

    pciaddr = validate_pciaddr(pciaddr)

    last_char = pciaddr[-1]
    return int(last_char)


@strict_dataclass
@dataclass(frozen=True, **common.KW_ONLY_DATACLASS)
class IPRouteAddressInfoEntry:
    family: str
    local: str

    def _post_check(self) -> None:
        if not isinstance(self.family, str) or self.family not in ("inet", "inet6"):
            raise ValueError("Invalid address family")


@strict_dataclass
@dataclass(frozen=True, **common.KW_ONLY_DATACLASS)
class IPRouteAddressEntry:
    ifindex: int
    ifname: str
    flags: tuple[str, ...]
    master: Optional[str]
    address: str  # Ethernet address.
    addr_info: tuple[IPRouteAddressInfoEntry, ...]

    def has_carrier(self) -> bool:
        return "NO-CARRIER" not in self.flags


def ip_addrs_parse(
    jstr: str,
    *,
    strict_parsing: bool = False,
    ifname: Optional[str] = None,
) -> list[IPRouteAddressEntry]:
    ret: list[IPRouteAddressEntry] = []
    for e in common.json_parse_list(jstr, strict_parsing=strict_parsing):
        try:
            entry = IPRouteAddressEntry(
                ifindex=e["ifindex"],
                ifname=validate_ifname(e["ifname"]),
                flags=tuple(e["flags"]),
                master=e["master"] if "master" in e else None,
                address=e["address"],
                addr_info=tuple(
                    IPRouteAddressInfoEntry(
                        family=addr["family"],
                        local=addr["local"],
                    )
                    for addr in e["addr_info"]
                ),
            )
        except (KeyError, ValueError, TypeError):
            if strict_parsing:
                raise
            continue

        if ifname is not None and normalize_ifname(ifname) != normalize_ifname(
            entry.ifname
        ):
            continue
        ret.append(entry)
    return ret


def ip_addrs(
    rsh: Optional[host.Host] = None,
    *,
    strict_parsing: bool = False,
    ifname: Optional[str] = None,
    ip_log_level: int = -1,
) -> list[IPRouteAddressEntry]:
    rsh = host.host_or_local(rsh)
    ret = rsh.run(
        "ip -json addr",
        decode_errors="surrogateescape",
        log_level=ip_log_level,
    )
    if not ret.success:
        if strict_parsing:
            raise RuntimeError(f"calling ip-route on {rsh.pretty_str()} failed ({ret})")
        return []

    return ip_addrs_parse(ret.out, strict_parsing=strict_parsing, ifname=ifname)


@strict_dataclass
@dataclass(frozen=True, **common.KW_ONLY_DATACLASS)
class IPRouteLinkEntry:
    ifindex: int
    ifname: str
    address: Optional[str]
    permaddr: Optional[str]
    flags: tuple[str, ...]
    mtu: int
    operstate: str
    link_info_kind: Optional[str]

    def match_ifname(self, ifname: Optional[Union[str, bytes]]) -> bool:
        if ifname is None:
            return False
        return normalize_ifname(self.ifname) == normalize_ifname(ifname)


def ip_links_parse(
    jstr: str, *, strict_parsing: bool = False, ifname: Optional[str] = None
) -> list[IPRouteLinkEntry]:
    ret: list[IPRouteLinkEntry] = []
    for e in common.json_parse_list(jstr, strict_parsing=strict_parsing):
        try:

            link_info_kind: Optional[str] = None
            link_info = e.get("linkinfo")
            if link_info is not None:
                link_info_kind = link_info.get("info_kind")

            address = e.get("address")
            if address is not None:
                address = validate_ethaddr_or_none(address)

            permaddr = e.get("permaddr")
            if permaddr is not None:
                permaddr = validate_ethaddr_or_none(permaddr)

            entry = IPRouteLinkEntry(
                ifindex=e["ifindex"],
                ifname=validate_ifname(e["ifname"]),
                mtu=int(e["mtu"]),
                flags=tuple(e["flags"]),
                operstate=(e["operstate"]),
                link_info_kind=link_info_kind,
                address=address,
                permaddr=permaddr,
            )
        except (KeyError, ValueError, TypeError):
            if strict_parsing:
                raise
            continue

        if ifname is not None and normalize_ifname(ifname) != normalize_ifname(
            entry.ifname
        ):
            continue
        ret.append(entry)
    return ret


def ip_links(
    rsh: Optional[host.Host] = None,
    *,
    strict_parsing: bool = False,
    ifname: Optional[str] = None,
    ip_log_level: int = -1,
) -> list[IPRouteLinkEntry]:
    # If @ifname is requested, we could issue a `ip -json link show $IFNAME`. However,
    # that means we do different things for requesting one link vs. all links. That
    # seems undesirable. Instead, in all cases fetch all links. Any filtering then happens
    # in code that we control. Performance should not make a difference, since the JSON data
    # is probably small anyway (compared to the overhead of invoking a shell command).
    rsh = host.host_or_local(rsh)
    ret = rsh.run(
        "ip -json -d link",
        decode_errors="surrogateescape",
        log_level=ip_log_level,
    )
    if not ret.success:
        if strict_parsing:
            raise RuntimeError(f"calling ip-link on {rsh.pretty_str()} failed ({ret})")
        return []

    return ip_links_parse(ret.out, strict_parsing=strict_parsing, ifname=ifname)


@strict_dataclass
@dataclass(frozen=True, **common.KW_ONLY_DATACLASS)
class IPRouteRouteEntry:
    dst: str
    dev: str


def ip_routes_parse(
    jstr: str,
    *,
    strict_parsing: bool = False,
) -> list[IPRouteRouteEntry]:
    ret: list[IPRouteRouteEntry] = []
    for e in common.json_parse_list(jstr, strict_parsing=strict_parsing):
        try:
            entry = IPRouteRouteEntry(
                dst=e["dst"],
                dev=validate_ifname(e["dev"]),
            )
        except (KeyError, ValueError, TypeError):
            if strict_parsing:
                raise
            continue

        ret.append(entry)
    return ret


def ip_routes(
    rsh: Optional[host.Host] = None,
    *,
    strict_parsing: bool = False,
    ip_log_level: int = -1,
) -> list[IPRouteRouteEntry]:
    rsh = host.host_or_local(rsh)
    ret = rsh.run(
        "ip -json route",
        decode_errors="surrogateescape",
        log_level=ip_log_level,
    )
    if not ret.success:
        if strict_parsing:
            raise RuntimeError(f"calling ip-route on {rsh.pretty_str()} failed ({ret})")
        return []

    return ip_routes_parse(ret.out, strict_parsing=strict_parsing)


def ethtool_permaddr(
    rsh: Optional[host.Host] = None,
    *,
    ifname: Union[str, bytes],
    strict_parsing: bool = False,
    ip_log_level: int = -1,
) -> Optional[str]:
    ifname = validate_ifname(ifname)
    rsh = host.host_or_local(rsh)
    ret = rsh.run(
        ["ethtool", "-P", ifname],
        decode_errors="surrogateescape",
        log_level=ip_log_level,
        env={"LANG": "C"},
    )
    if not ret.success:
        if strict_parsing:
            raise RuntimeError(f"calling ethtool -P {repr(ifname)} failed ({ret})")
        return None

    permaddr: Optional[str] = None

    for line in ret.out.splitlines():
        if (x := _parse_line(line, "Permanent address: ")) is not None:
            permaddr = x

    if permaddr is None:
        return None

    return validate_ethaddr_or_none(permaddr)


@strict_dataclass
@dataclass(frozen=True, **common.KW_ONLY_DATACLASS)
class EthtoolDriverInfo:
    ifname: str
    driver: Optional[str]
    version: Optional[str]
    firmware_version: Optional[str]


def ethtool_driver(
    rsh: Optional[host.Host] = None,
    *,
    ifname: Union[str, bytes],
    strict_parsing: bool = False,
    ip_log_level: int = -1,
) -> Optional[EthtoolDriverInfo]:
    ifname = validate_ifname(ifname)
    rsh = host.host_or_local(rsh)
    ret = rsh.run(
        ["ethtool", "-i", ifname],
        decode_errors="surrogateescape",
        log_level=ip_log_level,
        env={"LANG": "C"},
    )
    if not ret.success:
        if strict_parsing:
            raise RuntimeError(f"calling ethtool -i {repr(ifname)} failed ({ret})")
        return None

    driver: Optional[str] = None
    version: Optional[str] = None
    firmware_version: Optional[str] = None

    for line in ret.out.splitlines():
        if (x := _parse_line(line, "driver: ")) is not None:
            driver = x
        elif (x := _parse_line(line, "version: ")) is not None:
            version = x
        elif (x := _parse_line(line, "firmware-version: ")) is not None:
            firmware_version = x

    return EthtoolDriverInfo(
        ifname=ifname,
        driver=driver,
        version=version,
        firmware_version=firmware_version,
    )


def _sysctl_parse_str(s: Optional[Union[str, bytes]]) -> Optional[str]:
    if s is None:
        return None

    if isinstance(s, bytes):
        try:
            s = s.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return None

    if not isinstance(s, str):
        return None

    return s.strip()


def sysctl_read(
    path: Union[str, bytes],
    *,
    strip: bool = True,
    fail_on_error: bool = False,
) -> Optional[str]:

    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        if fail_on_error:
            raise
        return None

    # We always return a `str`, but invalid characters are escaped
    # via "surrogateescape". Depending on what you need to do, you
    # may need to consider that.
    s = data.decode("utf-8", errors="surrogateescape")
    if strip:
        s = s.strip()
    return s


def sysctl_phys_port_name_parse(
    s: Optional[Union[str, bytes]]
) -> Optional[tuple[int, int]]:
    # Parses the output of /sys/class/net/$IFNAME/phys_port_name
    #
    # https://github.com/k8snetworkplumbingwg/sriovnet/blob/3ca5e43034e6425fb5e4b0b4d3c8c3a2b3f5a5e8/sriovnet_switchdev.go#L84C6-L84C19

    s = _sysctl_parse_str(s)
    if s is None:
        return None

    m = re.search("^(c[0-9]+)?pf([0-9]+)vf([0-9]+)$", s)
    if m:
        try:
            return (int(m.group(2)), int(m.group(3)))
        except Exception:
            pass

    # old kernel syntax of phys_port_name is vf index
    m = re.search("^[0-9]+$", s)
    if m:
        try:
            return (0, int(m.group()))
        except Exception:
            pass

    return None


def get_phys_port_name(ifname: Union[str, bytes]) -> Optional[str]:
    return sysctl_read(f"/sys/class/net/{validate_ifname(ifname)}/phys_port_name")


def get_phys_switch_id(ifname: Union[str, bytes]) -> Optional[str]:
    return sysctl_read(f"/sys/class/net/{validate_ifname(ifname)}/phys_switch_id")


def get_ifnames() -> list[str]:
    try:
        ifs1 = os.listdir(b"/sys/class/net/")
    except Exception:
        return []

    def _validate(ifname: bytes) -> Optional[str]:
        if not os.path.islink(b"/sys/class/net/" + ifname):
            return None
        return validate_ifname_or_none(ifname)

    return sorted(common.iter_filter_none(_validate(i) for i in ifs1))


def get_pciaddrs() -> list[str]:
    path = "/sys/bus/pci/devices/"
    pcis = os.listdir(path)
    pcis = [validate_pciaddr(p) for p in pcis if os.path.exists(path + p + "/net/")]
    pcis2 = dict.fromkeys(pcis)
    return list(pcis2)


def _get_pciaddr_from_path(path: str) -> Optional[str]:
    i = path.rfind("/")
    if i >= 0:
        pciaddr = path[i + 1 :]
    else:
        pciaddr = path
    try:
        return validate_pciaddr(pciaddr)
    except Exception:
        return None


def _get_usbaddr_from_path(path: str) -> Optional[str]:
    i = path.rfind("/")
    if i >= 0:
        usbaddr = path[i + 1 :]
    else:
        usbaddr = path
    if not re.search("^[-0-9a-f.:]+$", usbaddr):
        return None
    return usbaddr


def get_busaddr_from_ifname(ifname: Union[str, bytes]) -> Optional[tuple[str, str]]:
    ifname = validate_ifname(ifname)
    try:
        path = os.readlink(f"/sys/class/net/{ifname}/device")
    except Exception:
        return None

    pciaddr = _get_pciaddr_from_path(path)
    if pciaddr is not None and os.path.exists(f"/sys/bus/pci/devices/{pciaddr}"):
        return ("pci", pciaddr)

    usbaddr = _get_usbaddr_from_path(path)
    if usbaddr is not None and os.path.exists(f"/sys/bus/usb/devices/{usbaddr}"):
        return ("usb", usbaddr)

    return None


def get_pciaddr_from_ifname(ifname: Union[str, bytes]) -> Optional[str]:
    busaddr = get_busaddr_from_ifname(ifname)
    if busaddr is None:
        return None
    bustype, busaddress = busaddr
    if bustype != "pci":
        return None
    return busaddress


def _get_ifnames_from_dir(dirname: str) -> Optional[list[str]]:
    try:
        devices = os.listdir(dirname)
    except Exception:
        return None
    return sorted(common.iter_filter_none(validate_ifname_or_none(d) for d in devices))


def get_ifnames_from_pciaddr(pciaddr: str) -> Optional[list[str]]:
    return _get_ifnames_from_dir(
        f"/sys/bus/pci/devices/{validate_pciaddr(pciaddr)}/net/"
    )


def get_ifindex_from_ifname(ifname: Union[str, bytes]) -> Optional[int]:
    ifname = validate_ifname(ifname)
    try:
        v = sysctl_read(f"/sys/class/net/{ifname}/ifindex")
    except Exception:
        pass
    else:
        if v:
            try:
                return int(v)
            except Exception:
                pass
    return None


def get_address_from_ifname(ifname: Union[str, bytes]) -> Optional[str]:
    ifname = validate_ifname(ifname)
    try:
        data = sysctl_read(f"/sys/class/net/{ifname}/address")
        if data:
            return validate_ethaddr(data)
    except Exception:
        pass
    return None


def is_switchdev(ifname: Union[str, bytes]) -> bool:
    # https://github.com/k8snetworkplumbingwg/sriovnet/blob/3ca5e43034e6425fb5e4b0b4d3c8c3a2b3f5a5e8/sriovnet_switchdev.go#L102
    return bool(get_phys_switch_id(ifname))


def get_uplink_representor(pciaddr: str) -> Optional[str]:
    # https://github.com/k8snetworkplumbingwg/sriovnet/blob/3ca5e43034e6425fb5e4b0b4d3c8c3a2b3f5a5e8/sriovnet_switchdev.go#L116
    pciaddr = validate_pciaddr(pciaddr)

    devicePath = f"/sys/bus/pci/devices/{pciaddr}/physfn/net"
    if not os.path.exists(devicePath):
        devicePath = f"/sys/bus/pci/devices/{pciaddr}/net"
        if not os.path.exists(devicePath):
            return None

    devices = _get_ifnames_from_dir(devicePath)
    for device in devices or ():
        if not is_switchdev(device):
            continue
        # Try to get the phys port name, if not exists then fallback to check without it
        # phys_port_name should be in formant p<port-num> e.g p0,p1,p2 ...etc.
        port_name = get_phys_port_name(device)
        if port_name is not None:
            if not re.search("^p[0-9]+$", port_name):
                continue
        return device

    return None


def get_vf_representor(
    uplink_ifname: Union[str, bytes], vf_index: int
) -> Optional[str]:
    # https://github.com/k8snetworkplumbingwg/sriovnet/blob/3ca5e43034e6425fb5e4b0b4d3c8c3a2b3f5a5e8/sriovnet_switchdev.go#L143
    uplink_ifname = validate_ifname(uplink_ifname)

    phys_switch_id = get_phys_switch_id(uplink_ifname)
    if phys_switch_id is None:
        return None

    uplink_pciaddr = get_pciaddr_from_ifname(uplink_ifname)
    uplink_pci_func_address = pciaddr_get_func_address(uplink_pciaddr)

    devices = _get_ifnames_from_dir(f"/sys/class/net/{uplink_ifname}/subsystem")
    for device in devices or ():
        device_switch_id = get_phys_switch_id(device)
        if device_switch_id != phys_switch_id:
            continue
        port_name = sysctl_phys_port_name_parse(get_phys_port_name(device))
        if port_name is None:
            continue
        if port_name[0] != uplink_pci_func_address:
            continue
        if port_name[1] != vf_index:
            continue

        return device

    return None


def get_vfs_for_representor(uplink_pciaddr: str) -> list[tuple[str, int]]:
    uplink_pciaddr = validate_pciaddr(uplink_pciaddr)

    path = f"/sys/bus/pci/devices/{uplink_pciaddr}"

    try:
        files = os.listdir(path)
    except Exception:
        return []

    result: list[tuple[str, int]] = []

    regex = re.compile("^virtfn(\\d+)$")

    for file in files:
        m = regex.search(file)
        if not m:
            continue

        try:
            vf_index = int(m.group(1))
        except Exception:
            continue

        try:
            data = os.readlink(f"{path}/{file}")
        except Exception:
            continue
        pciaddr = _get_pciaddr_from_path(data)

        if pciaddr is None:
            continue

        result.append((pciaddr, vf_index))

    return result


@common.repeat_for_same_result
def get_device_infos(with_ethtool: bool = True) -> list[dict[str, Any]]:

    result = []

    devices: set[tuple[Optional[str], Optional[str]]] = set()

    link_infos: dict[str, Optional[IPRouteLinkEntry]]
    link_infos = dict.fromkeys(get_ifnames())
    link_infos.update((lnk.ifname, lnk) for lnk in ip_links())

    ifnames_tmp = set(link_infos)
    for pciaddr1 in get_pciaddrs():
        ifnames1 = get_ifnames_from_pciaddr(pciaddr1)
        if ifnames1:
            for ifname1 in ifnames1:
                devices.add((pciaddr1, ifname1))
                ifnames_tmp.discard(ifname1)
        else:
            devices.add((pciaddr1, None))
    for ifname1 in ifnames_tmp:
        devices.add((None, ifname1))

    for device in devices:
        res: dict[str, Any] = {}

        pciaddr, ifname = device

        if ifname is not None:
            link_info = link_infos.get(ifname)
            if link_info is not None:
                res["ifindex"] = link_info.ifindex
            else:
                dict_add_optional(res, "ifindex", get_ifindex_from_ifname(ifname))
        else:
            link_info = None

        if ifname is not None:
            res["ifname"] = ifname

        if pciaddr is not None:
            res["pciaddr"] = pciaddr
        elif ifname is not None:
            busaddr = get_busaddr_from_ifname(ifname)
            if busaddr is not None:
                bustype, busaddress = busaddr
                if bustype == "usb":
                    res["usbaddr"] = busaddress

        if ifname is not None:
            link_dict: dict[str, Any] = {}

            if link_info is not None:
                li_dict = common.dataclass_to_dict(link_info)
                del li_dict["ifindex"]
                del li_dict["ifname"]
            else:
                li_dict = {}

            li_address = li_dict.get("address")
            if li_address is None:
                li_address = get_address_from_ifname(ifname)

            li_permaddr = li_dict.get("permaddr")
            if li_permaddr is None:
                li_permaddr = ethtool_permaddr(ifname=ifname)

            dict_add_optional(link_dict, "address", li_address)
            dict_add_optional(link_dict, "permaddr", li_permaddr)

            if link_info is not None:
                del li_dict["address"]
                del li_dict["permaddr"]
                if li_dict.get("link_info_kind", 1) is None:
                    del li_dict["link_info_kind"]
                link_dict.update(li_dict)

            res["link"] = link_dict

        if ifname is not None:
            dict_add_optional(res, "phys_port_name", get_phys_port_name(ifname))
            dict_add_optional(res, "phys_switch_id", get_phys_switch_id(ifname))

        if pciaddr is not None:
            dict_add_optional(res, "uplink_rep_ifname", get_uplink_representor(pciaddr))

        if with_ethtool:
            if ifname is not None:
                ethdata = ethtool_driver(ifname=ifname)
                if ethdata is not None:
                    d3 = common.dataclass_to_dict(ethdata)
                    del d3["ifname"]
                    res["ethtool"] = d3

        result.append(res)

    uplink_reps: list[str] = sorted(
        set(common.iter_filter_none(x1.get("uplink_rep_ifname") for x1 in result))
    )

    for uplink_rep_ifname in uplink_reps:
        uplink_rep_pciaddr = get_pciaddr_from_ifname(uplink_rep_ifname)
        if uplink_rep_pciaddr is None:
            continue
        vf_infos = get_vfs_for_representor(uplink_rep_pciaddr)
        for vf_info in vf_infos:
            vf_pciaddr, vf_index = vf_info

            inf_vf = common.iter_get_first(
                r for r in result if r.get("pciaddr") == vf_pciaddr
            )

            vf_rep = get_vf_representor(uplink_rep_ifname, vf_index)
            if vf_rep is not None:
                inf_vf_rep = common.iter_get_first(
                    r for r in result if r.get("ifname") == vf_rep
                )
            else:
                inf_vf_rep = None

            d2: dict[str, Any] = {
                "uplink_rep_ifname": uplink_rep_ifname,
                "uplink_rep_pciaddr": uplink_rep_pciaddr,
                "vfindex": vf_index,
            }
            if inf_vf is not None:
                d3 = d2.copy()
                if inf_vf_rep is not None:
                    dict_add_optional(d3, "vf_rep_ifname", inf_vf_rep.get("ifname"))
                    dict_add_optional(d3, "vf_rep_ifindex", inf_vf_rep.get("ifindex"))
                    dict_add_optional(d3, "vf_rep_pciaddr", inf_vf_rep.get("pciaddr"))
                inf_vf["is_vf"] = d3
            if inf_vf_rep is not None:
                d3 = d2.copy()
                if inf_vf is not None:
                    dict_add_optional(d3, "vf_ifname", inf_vf.get("ifname"))
                    dict_add_optional(d3, "vf_ifindex", inf_vf.get("ifindex"))
                    dict_add_optional(d3, "vf_pciaddr", inf_vf.get("pciaddr"))
                inf_vf_rep["is_vf_rep"] = d3

    result.sort(
        key=lambda x: (
            x.get("ifindex") or 2**33,
            x.get("ifname") or "",
            x.get("pciaddr") or "",
        )
    )

    return result


def device_infos_parse_lst(
    device_infos_str: str,
    *,
    ifname: Optional[str] = None,
    pciaddr: Optional[str] = None,
    vf_rep_for_pciaddr: Optional[str] = None,
) -> list[dict[str, Any]]:
    lst = common.json_parse_list(device_infos_str)
    return device_infos_find(
        lst,
        ifname=ifname,
        pciaddr=pciaddr,
        vf_rep_for_pciaddr=vf_rep_for_pciaddr,
    )


def device_infos_find(
    device_info_list: Iterable[Any],
    *,
    ifname: Optional[str] = None,
    pciaddr: Optional[str] = None,
    vf_rep_for_pciaddr: Optional[str] = None,
) -> list[dict[str, Any]]:

    # First, filter out all non-strdicts
    lst = [
        di
        for di in device_info_list
        if (isinstance(di, dict) and all(isinstance(k, str) for k in di))
    ]

    if ifname is not None:
        ifname = validate_ifname(ifname)
        lst = [di for di in lst if di.get("ifname") == ifname]

    if pciaddr is not None:
        pciaddr = validate_ifname(pciaddr)
        lst = [di for di in lst if di.get("pciaddr") == pciaddr]

    if vf_rep_for_pciaddr is not None:

        vf_rep_for_pciaddr = validate_pciaddr(vf_rep_for_pciaddr)

        def _match(di: dict[str, Any]) -> bool:
            x = di.get("is_vf_rep")
            if not isinstance(x, dict):
                return False
            return x.get("vf_pciaddr") == vf_rep_for_pciaddr

        lst = [di for di in lst if _match(di)]

    return lst


if __name__ == "__main__":

    def main() -> None:
        import argparse

        commands = {f.__name__: f for f in (get_device_infos,)}

        argparser = argparse.ArgumentParser(description="Helper network functions.")
        argparser.add_argument(
            "command",
            choices=commands,
            default="get_device_infos",
            nargs="?",
        )
        args = argparser.parse_args()

        result = commands[args.command]()
        print(json.dumps(result))

    main()
