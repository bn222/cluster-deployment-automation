from dataclasses import dataclass
import dataclasses
import ipaddress
from typing import Any, Callable, Optional, TypeVar, Iterator, Type
from concurrent.futures import Future
import contextlib
from types import TracebackType
import http.server
from multiprocessing import Process
from git.repo import Repo
import shutil
import host
from logger import logger
import json
import functools
import os
import re
import glob
import socket
import tempfile
import typing
from collections.abc import Iterable
from typing import Union
import time
import itertools
import signal
import types


def with_timeout(timeout: int, func: Callable[[], None]) -> None:
    def handler(signum: int, frame: Optional[types.FrameType]) -> None:
        signum = signum
        frame = frame
        raise TimeoutError(f"Timed out after {timeout} seconds")

    signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeout)
    try:
        return func()
    except TimeoutError as e:
        logger.error_and_exit(f"{e}")
    finally:
        signal.alarm(0)


T = TypeVar("T")


def check_type(value: typing.Any, type_hint: typing.Any) -> bool:

    # Some naive type checking. This is used for ensuring that data classes
    # contain the expected types (via @strict_dataclass.
    #
    # That is most interesting, when we initialize the data class with
    # data from an untrusted source (like elements from a JSON parser).

    actual_type = typing.get_origin(type_hint)
    if actual_type is None:
        return isinstance(value, type_hint)

    if actual_type is typing.Union:
        args = typing.get_args(type_hint)
        return any(check_type(value, a) for a in args)

    if actual_type is list:
        args = typing.get_args(type_hint)
        (arg,) = args
        return isinstance(value, list) and all(check_type(v, arg) for v in value)

    if actual_type is dict:
        args = typing.get_args(type_hint)
        (arg_key, arg_val) = args
        return isinstance(value, dict) and all(check_type(k, arg_key) and check_type(v, arg_val) for k, v in value.items())

    if actual_type is tuple:
        # tuple[int, ...] is not supported (yet).
        args = typing.get_args(type_hint)
        return isinstance(value, tuple) and len(value) == len(args) and all(check_type(value[i], args[i]) for i in range(len(value)))

    return False


TCallable = typing.TypeVar("TCallable", bound=typing.Callable[..., typing.Any])


def strict_dataclass(cls: TCallable) -> TCallable:

    init = getattr(cls, '__init__')

    def wrapped_init(self, *args, **argv):  # type: ignore
        init(self, *args, **argv)
        for field in dataclasses.fields(self):
            name = field.name
            value = getattr(self, name)
            type_hint = field.type
            if not check_type(value, type_hint):
                raise TypeError(f"Expected type '{type_hint}' for attribute '{name}' but received type '{type(value)}')")

        # Normally, data classes support __post_init__(), which is called by __init__()
        # already. Add a way for a @strict_dataclass to add additional validation *after*
        # the original check.
        _post_check = getattr(type(self), "_post_check", None)
        if _post_check is not None:
            _post_check(self)

    setattr(cls, '__init__', wrapped_init)
    return cls


def str_to_list(input_str: str) -> list[int]:
    result: set[int] = set()
    parts = input_str.split(',')

    for part in parts:
        if '-' in part:
            start, end = part.split('-')
            result.update(range(int(start), int(end) + 1))
        else:
            result.add(int(part))

    return sorted(result)


@dataclass(frozen=True, init=False)
class RangeList:
    _include: Optional[set[int]]
    _exclude: Optional[set[int]]

    UNLIMITED: typing.ClassVar['RangeList']

    def __init__(
        self,
        include: Optional[Iterable[int]] = None,
        exclude: Optional[Iterable[int]] = None,
    ):
        def prepare(arg: Optional[Iterable[int]]) -> Optional[set[int]]:
            return set(arg) if arg is not None else None

        object.__setattr__(self, "_include", prepare(include))
        object.__setattr__(self, "_exclude", prepare(exclude))

    def match(self, idx: int) -> bool:
        if self._include is not None and idx not in self._include:
            return False
        if self._exclude is not None and idx in self._exclude:
            return False
        return True

    def filter(self, lst: Iterable[T]) -> list[T]:
        lst = list(lst)
        return [lst[idx] for idx in range(len(lst)) if self.match(idx)]

    def _accumulate(
        self,
        is_include: bool,
        value: typing.Any,
    ) -> None:

        if not isinstance(value, str):
            raise ValueError(f"Unexpected argument type {type(value)} for value")

        lst = RangeList.parse_list(value)
        assert lst is not None

        # RangeList is mostly immutable, except this _accumulate() method.
        # It's used while parsing the command line arguments, to incrementally
        # built the RangeList.
        if is_include:
            add_attr, del_attr = "_include", "_exclude"
        else:
            add_attr, del_attr = "_exclude", "_include"

        s: Optional[set[int]]

        s = getattr(self, add_attr)
        if s is None:
            s = set()
            object.__setattr__(self, add_attr, s)
        s.update(lst)

        s = getattr(self, del_attr)
        if s is not None:
            s.difference_update(lst)

    @staticmethod
    def parse_list(lst: Optional[Union[str, Iterable[Union[int, str, Iterable[int]]]]]) -> Optional[set[int]]:
        if lst is None:
            return None
        result: set[int] = set()
        if isinstance(lst, str):
            result.update(str_to_list(lst))
        else:
            for entry in list(lst):
                if isinstance(entry, str):
                    result.update(str_to_list(entry))
                elif isinstance(entry, int):
                    result.add(entry)
                else:
                    for entry2 in list(entry):
                        if not isinstance(entry2, int):
                            raise ValueError("Unsupported argument for range")
                        result.add(entry2)
        return result


RangeList.UNLIMITED = RangeList()


@strict_dataclass
@dataclass
class IPRouteAddressInfoEntry:
    family: str
    local: str

    def _post_check(self) -> None:
        if not isinstance(self.family, str) or self.family not in ("inet", "inet6"):
            raise ValueError("Invalid address family")


@strict_dataclass
@dataclass
class IPRouteAddressEntry:
    ifindex: int
    ifname: str
    flags: list[str]
    master: Optional[str]
    address: str  # Ethernet address.
    addr_info: list[IPRouteAddressInfoEntry]

    def has_carrier(self) -> bool:
        return "NO-CARRIER" not in self.flags


class HttpServerManager:
    def __init__(self, path: str, port: int = 8000):
        self.path = path
        self.port = port
        self.process: Optional[Process] = None

    def __enter__(self) -> 'HttpServerManager':
        self.start_server()
        return self

    def __exit__(self, exc_type: Optional[Type[BaseException]], exc_value: Optional[BaseException], traceback: Optional[TracebackType]) -> None:
        self.stop_server()

    def start_server(self) -> None:
        def target() -> None:
            os.chdir(self.path)
            server_address = ('', self.port)
            httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
            httpd.serve_forever()

        self.port = self.find_open_port()
        self.process = Process(target=target)
        self.process.start()
        logger.info(f"Http Server started on port {self.port}")

    def stop_server(self) -> None:
        if self.process:
            self.process.terminate()
            self.process.join()
            logger.info("Http Server stopped")

    def port_is_in_use(self, port: int) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            return s.connect_ex(('localhost', port)) == 0

    def find_open_port(self) -> int:
        port = self.port
        while self.port_is_in_use(port):
            logger.debug(f"port {self.port} in use, trying port + 1")
            port += 1
        return port


def _parse_json_list(jstr: str, *, strict_parsing: bool = False) -> list[typing.Any]:
    try:
        lst = json.loads(jstr)
    except ValueError:
        if strict_parsing:
            raise
        return []

    if not isinstance(lst, list):
        try:
            lst = list(lst)
        except Exception:
            if strict_parsing:
                raise
            return []

    return typing.cast(list[typing.Any], lst)


def ip_addrs_parse(jstr: str, *, strict_parsing: bool = False, ifname: Optional[str] = None) -> list[IPRouteAddressEntry]:
    ret: list[IPRouteAddressEntry] = []
    for e in _parse_json_list(jstr, strict_parsing=strict_parsing):
        try:
            entry = IPRouteAddressEntry(
                e["ifindex"],
                e["ifname"],
                e["flags"],
                e["master"] if "master" in e else None,
                e["address"],
                [IPRouteAddressInfoEntry(addr["family"], addr["local"]) for addr in e["addr_info"]],
            )
        except (KeyError, ValueError, TypeError):
            if strict_parsing:
                raise
            continue

        if ifname is not None and entry.ifname != ifname:
            continue
        ret.append(entry)
    return ret


def ip_addrs(rsh: host.Host, *, strict_parsing: bool = False, ifname: Optional[str] = None) -> list[IPRouteAddressEntry]:
    ret = rsh.run("ip -json addr")
    if ret.returncode != 0:
        if strict_parsing:
            raise RuntimeError(f"calling ip-route on {rsh.hostname()} failed ({ret})")
        return []

    return ip_addrs_parse(ret.out, strict_parsing=strict_parsing, ifname=ifname)


@strict_dataclass
@dataclass
class IPRouteLinkEntry:
    ifindex: int
    ifname: str


def ip_links_parse(jstr: str, *, strict_parsing: bool = False, ifname: Optional[str] = None) -> list[IPRouteLinkEntry]:
    ret: list[IPRouteLinkEntry] = []
    for e in _parse_json_list(jstr, strict_parsing=strict_parsing):
        try:
            entry = IPRouteLinkEntry(
                e["ifindex"],
                e["ifname"],
            )
        except (KeyError, ValueError, TypeError):
            if strict_parsing:
                raise
            continue

        if ifname is not None and ifname != entry.ifname:
            continue
        ret.append(entry)
    return ret


def ip_links(rsh: host.Host, *, strict_parsing: bool = False, ifname: Optional[str] = None) -> list[IPRouteLinkEntry]:
    # If @ifname is requested, we could issue a `ip -json link show $IFNAME`. However,
    # that means we do different things for requesting one link vs. all links. That
    # seems undesirable. Instead, in all cases fetch all links. Any filtering then happens
    # in code that we control. Performance should not make a difference, since the JSON data
    # is probably small anyway (compared to the overhead of invoking a shell command).
    ret = rsh.run("ip -json link")
    if ret.returncode != 0:
        if strict_parsing:
            raise RuntimeError(f"calling ip-link on {rsh.hostname()} failed ({ret})")
        return []

    return ip_links_parse(ret.out, strict_parsing=strict_parsing, ifname=ifname)


@strict_dataclass
@dataclass
class IPRouteRouteEntry:
    dst: str
    dev: str


def ip_routes_parse(jstr: str, *, strict_parsing: bool = False) -> list[IPRouteRouteEntry]:
    ret: list[IPRouteRouteEntry] = []
    for e in _parse_json_list(jstr, strict_parsing=strict_parsing):
        try:
            entry = IPRouteRouteEntry(
                e["dst"],
                e["dev"],
            )
        except (KeyError, ValueError, TypeError):
            if strict_parsing:
                raise
            continue

        ret.append(entry)
    return ret


def ip_routes(rsh: host.Host, *, strict_parsing: bool = False) -> list[IPRouteRouteEntry]:
    ret = rsh.run("ip -json route")
    if ret.returncode != 0:
        if strict_parsing:
            raise RuntimeError(f"calling ip-route on {rsh.hostname()} failed ({ret})")
        return []

    return ip_routes_parse(ret.out, strict_parsing=strict_parsing)


def ip_range(start_addr: str, n_addrs: int) -> tuple[str, str]:
    return start_addr, str(ipaddress.ip_address(start_addr) + n_addrs)


def ip_to_gateway(ipv4_address: str, subnet_mask: str) -> str:
    network = ipaddress.ip_network(f"{ipv4_address}/{subnet_mask}", strict=False)
    range_start = network.network_address + 1
    return str(range_start)


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


def find_port(host: host.Host, port_name: str) -> Optional[IPRouteAddressEntry]:
    entries = ip_addrs(host)
    for entry in entries:
        if entry.ifname == port_name:
            return entry
    return None


def route_to_port(host: host.Host, route: str) -> Optional[str]:
    for e in ip_routes(host):
        if e.dst == route:
            return e.dev
    return None


def port_to_ip(host: host.Host, port_name: str) -> Optional[str]:
    if port_name == "auto":
        port_name = get_auto_port(host)

    entries = ip_addrs(host)
    for entry in entries:
        if entry.ifname == port_name:
            for addr in entry.addr_info:
                if addr.family == "inet":
                    return addr.local
    return None


def get_auto_port(host: host.Host) -> str:
    def ipa_is_candidate(ipa: IPRouteAddressEntry) -> bool:
        if not ipa.has_carrier():
            # No carrier, this interface is not a candidate.
            return False
        if any(ai.family == 'inet' or (ai.family == 'inet6' and not ai.local.startswith("fe80:")) for ai in ipa.addr_info):
            # We expect that there is no IP address. However, Ipv6 link local
            # addresses may be configured (for example, if NetworkManager in
            # the background tries to autoactivate a ipv6.method=auto profile).
            return False
        return True

    interfaces = {ipa.ifname for ipa in ip_addrs(host) if ipa_is_candidate(ipa)}
    if len(interfaces) == 0:
        raise ValueError("No interfaces found for auto port")

    if len(interfaces) > 1:
        # We hardcore a preference of commonly used interfaces by their
        # name.
        for ifname in ("ens12399", "ens12409"):
            if ifname in interfaces:
                return ifname

    return next(iter(sorted(interfaces)))


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


def build_sriov_network_operator_check_permissions() -> bool:
    # To build sriov_network_operator, we must be able to pull build images
    # from registry.ci.ipenshift.org. See [1].
    #
    # For that, you must get a token from [2] and issue `podman login
    # registry.ci.openshift.org`.
    #
    # This function tries to fetch such an image, to determine whether we have
    # permissions.
    #
    # [1] https://github.com/openshift/sriov-network-operator/blob/34f3e5f934ca72eae57667d7a9185f5af47aea3a/Dockerfile.rhel7#L1
    # [2] https://oauth-openshift.apps.ci.l2s4.p1.openshiftapps.com/oauth/token/request
    rsh = host.LocalHost()
    ret = rsh.run("podman pull registry.ci.openshift.org/ocp/builder:rhel-9-golang-1.21-openshift-4.16")
    return ret.success()


def git_repo_setup(repo_dir: str, *, repo_wipe: bool = True, url: str, branch: Optional[str] = None) -> None:
    exists = os.path.exists(repo_dir)
    if exists and not repo_wipe:
        return
    if exists:
        shutil.rmtree(repo_dir)

    logger.info(f"Cloning repo {url} to {repo_dir}")
    Repo.clone_from(url, repo_dir, branch=branch)


def extract_version_or_panic(version: str) -> str:
    v, number_of_subs_made = re.subn("^([0-9]+[.][0-9]+\\b).*$", "\\1", version)
    if number_of_subs_made == 1:
        return v
    logger.error_and_exit(f"unsupported version \"{version}\"")


def calculate_elapsed_time(start: float, end: float) -> tuple[int, int]:
    minutes, seconds = divmod(int(end - start), 60)
    return minutes, seconds


@functools.cache
def current_host() -> str:
    chost = os.environ.get("CDA_CURRENT_HOST")
    if chost:
        return chost
    lh = host.LocalHost()
    res = lh.run("hostname -f")
    if res.returncode == 0 and (c := res.out.strip()):
        return c
    raise RuntimeError(f"Failure detecting current hostname: {res}")


def empty_future(result_type: type[T]) -> Future[Optional[T]]:
    f: Future[Optional[T]] = Future()
    f.set_result(None)
    return f


def wait_true(name: str, n_tries: int, func: Callable[..., bool], **func_kwargs: Any) -> bool:
    # Wait until the "func" is successful, or we will reach "n_tries".
    # When "n_tries" is zero it will run until "func" succeeds.
    logger.info(f"Waiting for {name}")
    for try_count in itertools.count(0):
        if func(**func_kwargs):
            logger.info(f"Took {try_count} tries for {name}")
            return True

        if n_tries and try_count >= n_tries:
            logger.info(f"The limit of {n_tries} tries was reached for {name}")
            return False

        time.sleep(5)

    return True


def wait_futures(msg: str, futures: list[tuple[str, Future[bool]]], cb: Callable[[], None] = lambda: None) -> None:
    def get_future_state(future: Future[bool]) -> str:
        if not future.done():
            return "Running"
        elif future.result():
            return "Ok"
        else:
            return "Fail"

    state = {name: get_future_state(future) for (name, future) in futures}
    logger.info(f"Waiting for {msg}: {state}")
    max_tries = 200

    for tries in itertools.count(0):
        new_state = {name: get_future_state(future) for (name, future) in futures}

        if set(state.items()) - set(new_state.items()):
            logger.info(f"State change of {msg}: {new_state}")

        state = new_state

        if all(future.done() for (_, future) in futures):
            break

        time.sleep(30)
        cb()
        if tries == max_tries:
            logger.error_and_exit(f"Failed to wait for futures after {tries} tries")

    if any(not future.result() for (_, future) in futures):
        logger.error_and_exit(f"Failed to {msg}: {state}")
