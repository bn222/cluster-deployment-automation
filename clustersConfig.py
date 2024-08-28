from os import path, getcwd
import os
import io
import sys
import re
import ipaddress
from typing import Optional, Union
import xml.etree.ElementTree as et
import jinja2
from yaml import safe_load
import host
from logger import logger
import secrets
import common
import collections.abc
from clusterInfo import ClusterInfo
from clusterInfo import load_all_cluster_info
from dataclasses import dataclass, field
from typing import Any
import ktoolbox.common as kcommon
import ktoolbox.netdev as knetdev


def _show_secret(secret: Optional[str], *, show: bool) -> Optional[str]:
    if secret is None:
        return None
    if not show:
        return "***"
    return secret


def _normalize_ifname(ifname: str) -> tuple[bool, str]:
    ifname2 = knetdev.validate_ifname_or_none(ifname)
    if ifname2 is None:
        return False, ifname
    return True, ifname2


def _normalize_network_api_port(network_api_port: Optional[str]) -> Optional[str]:
    # in YAML, the auto port is represented with the string "auto" or "".
    # In HostConfig.network_api_port we map that to None.
    if network_api_port is None or network_api_port in ("auto", ""):
        return None
    return network_api_port


def random_mac() -> str:
    return "52:54:" + ":".join(re.findall("..", secrets.token_hex()[:8]))


@dataclass
class ExtraConfigArgs:
    base_path: str
    name: str

    # OVN-K extra configs:
    # New ovn-k image to use.
    image: Optional[str] = None
    # Time to wait for new ovn-k to roll out.
    ovnk_rollout_timeout: str = "20m"

    kubeconfig: Optional[str] = None
    mapping: Optional[list[dict[str, str]]] = None

    # With "sriov_network_operator", if true build the container images locally
    # and push them to the internal container registry of openshift.
    #
    # You will need authentication for fetching build containers.
    # Get the login token from [1]. Then `podman login registry.ci.openshift.org`
    # or create "$XDG_RUNTIME_DIR/containers/auth.json".
    # [1] https://oauth-openshift.apps.ci.l2s4.p1.openshiftapps.com/oauth/token/request
    #
    # If enabled, an existing "/root/sriov-network-operator" directory is not
    # wiped and you can prepare there the version you want to build and
    # install.
    sriov_network_operator_local: bool = False

    # Custom config to the scheduler whether the masters are allowed to run workloads.
    schedulable: bool = True
    # https://console.redhat.com/insights/connector/activation-keys
    organization_id: Optional[str] = None

    activation_key: Optional[str] = None

    dpu_operator_path: str = "/root/dpu-operator"

    # Specify the commit to checkout when building https://github.com/intel/ipu-opi-plugins
    ipu_plugin_sha: str = "main"

    rebuild_dpu_operators_images: bool = True

    dpu_net_interface: Optional[str] = "ens2f0"

    def pre_check(self) -> None:
        if self.sriov_network_operator_local:
            if self.name != "sriov_network_operator":
                raise ValueError("\"sriov_network_operator_local\" can only be set to TRUE for name=\"sriov_network_operator\"")
            if not common.build_sriov_network_operator_check_permissions():
                raise ValueError("Building sriov_network_operator requires permissions to fetch. Get a token from https://oauth-openshift.apps.ci.l2s4.p1.openshiftapps.com/oauth/token/request and issue `podman login registry.ci.openshift.org`")

    def resolve_dpu_operator_path(self) -> str:
        if self.dpu_operator_path[0] == "/":
            return self.dpu_operator_path
        else:
            return os.path.normpath(os.path.join(self.base_path, self.dpu_operator_path))


@dataclass
class NodeConfig:
    cluster_name: str
    name: str
    node: str
    image_path: str = field(init=False)
    mac: str = field(default_factory=random_mac)
    bmc: str = ""
    bmc_user: str = "root"
    bmc_password: str = "calvin"
    ip: Optional[str] = None
    kind: Optional[str] = None  # optional to allow 'type'
    type: Optional[str] = None
    preallocated: str = "true"
    os_variant: str = "rhel8.6"
    disk_size: str = "48"
    ram: str = "32768"
    cpu: str = "8"
    disk_kind: str = "qcow2"

    def __post_init__(self) -> None:
        if self.type:
            logger.warning("Deprecated 'type' in node config. Use 'kind' instead")
            self.kind = self.type

        delattr(self, 'type')

        if self.kind is None:
            raise ValueError("NodeConfig: kind not provided")

        # bmc ip is mandatory for physical, not for vm
        if self.kind == "physical" or self.kind == "bf" or self.kind == "ipu":
            if self.bmc == "":
                raise ValueError("NodeConfig: bmc not provided")
        else:
            delattr(self, "bmc")
            delattr(self, "bmc_user")
            delattr(self, "bmc_password")

        base_path = f'/home/{self.cluster_name}_guests_images'
        qemu_img_name = f'{self.name}.qcow2'
        self.image_path = os.path.join(base_path, qemu_img_name)

    def is_preallocated(self) -> bool:
        return self.preallocated == "true"


@kcommon.strict_dataclass
@dataclass(frozen=True, kw_only=True)
class HostConfig(kcommon.StructParseBaseNamed):
    # In YAML, if the value is set explicitly to "auto" or "", it
    # gets mapped to None here. It means to autodetect it.
    # See also _normalize_network_api_port().
    network_api_port: Optional[str]

    # If True, it means that the host entry did not have a network_api_port
    # key. Instead, network_api_port value is inherited from the default.
    network_api_port_is_default: bool

    username: str
    password: Optional[str]
    pre_installed: bool

    def serialize(self, *, show_secrets: bool = False) -> dict[str, Any]:
        extra_1 = {}
        extra_2: dict[str, Any] = {}
        if not self.network_api_port_is_default:
            extra_1["network_api_port"] = self.network_api_port or "auto"
        kcommon.dict_add_optional(extra_2, "password", _show_secret(self.password, show=show_secrets))
        return {
            **super().serialize(),
            **extra_1,
            "username": self.username,
            **extra_2,
            "pre_installed": self.pre_installed,
        }

    @staticmethod
    def parse(
        yamlidx: int,
        yamlpath: str,
        arg: Any,
        *,
        default_network_api_port: Optional[str] = None,
    ) -> "HostConfig":
        with kcommon.structparse_with_strdict(arg, yamlpath) as varg:

            name = kcommon.structparse_pop_str_name(*varg.for_name())

            network_api_port_is_default = False
            network_api_port = kcommon.structparse_pop_str(
                *varg.for_key("network_api_port"),
                default=None,
            )
            if network_api_port is None:
                network_api_port_is_default = True
                network_api_port = default_network_api_port
            network_api_port = _normalize_network_api_port(network_api_port)
            if network_api_port is not None:
                val_valid, network_api_port = _normalize_ifname(network_api_port)
                if not val_valid:
                    if network_api_port_is_default:
                        raise ValueError(f'"{yamlpath}.network_api_port": default {repr(network_api_port)} is not a valid interface name')
                    raise ValueError(f'"{yamlpath}.network_api_port": {repr(network_api_port)} is not a valid interface name')

            username = kcommon.structparse_pop_str(
                *varg.for_key("username"),
                default="core",
            )

            password = kcommon.structparse_pop_str(
                *varg.for_key("password"),
                default=None,
            )

            pre_installed = kcommon.structparse_pop_bool(
                *varg.for_key("pre_installed"),
                default=True,
            )

        return HostConfig(
            yamlidx=yamlidx,
            yamlpath=yamlpath,
            name=name,
            network_api_port=network_api_port,
            network_api_port_is_default=network_api_port_is_default,
            username=username,
            password=password,
            pre_installed=pre_installed,
        )


@kcommon.strict_dataclass
@dataclass(frozen=True, kw_only=True)
class BridgeConfig:
    ip: str
    mask: str
    dynamic_ip_range: Optional[tuple[str, str]] = None


# Run the full hostname command
def current_host() -> str:
    lh = host.LocalHost()
    return lh.run("hostname -f").out.strip()


class ClustersConfig:
    name: str
    kubeconfig: str
    api_vip: dict[str, str]
    ingress_vip: dict[str, str]
    external_port: str
    kind: str
    version: str
    network_api_port: str
    masters: list[NodeConfig]
    workers: list[NodeConfig]
    configured_workers: list[NodeConfig]
    local_bridge_config: BridgeConfig
    remote_bridge_config: BridgeConfig
    full_ip_range: tuple[str, str]
    ip_range: tuple[str, str]
    hosts: tuple[HostConfig, ...]
    proxy: Optional[str]
    noproxy: Optional[str]
    preconfig: list[ExtraConfigArgs]
    postconfig: list[ExtraConfigArgs]
    ntp_source: str
    base_dns_domain: str
    install_iso: str
    secrets_path: str

    # All configurations that used to be supported but are not anymore.
    # Used to warn the user to change their config.
    deprecated_configs: dict[str, Optional[str]] = {"api_ip": "api_vip", "ingress_ip": "ingress_vip"}

    def __init__(
        self,
        yaml_path: str,
        *,
        secrets_path: str = "",
        worker_range: common.RangeList = common.RangeList.UNLIMITED,
        test_only: bool = False,
    ):
        self.external_port = "auto"
        self.kind = "openshift"
        self.version = "4.14.0-nightly"
        self.network_api_port = "auto"
        self.masters: list[NodeConfig] = []
        self.workers: list[NodeConfig] = []
        self.configured_workers: list[NodeConfig] = []
        self.proxy: Optional[str] = None
        self.noproxy: Optional[str] = None
        self.preconfig: list[ExtraConfigArgs] = []
        self.postconfig: list[ExtraConfigArgs] = []
        self.ntp_source = "clock.redhat.com"
        self.base_dns_domain = "redhat.com"
        self.install_iso = ""

        self._cluster_info: Optional[ClusterInfo] = None
        self._load_full_config(yaml_path)
        self._check_deprecated_config()

        yamlpath = ".clusters[0]"

        cc = self.fullConfig
        self.secrets_path = secrets_path
        self.set_cc_defaults(cc)
        if "proxy" in cc:
            self.proxy = cc["proxy"]
        if "noproxy" in cc:
            self.noproxy = cc["noproxy"]
        if "external_port" in cc:
            self.external_port = cc["external_port"]
        if "version" in cc:
            self.version = cc["version"]
        if "kind" in cc:
            self.kind = cc["kind"]
            if self.kind == "iso":
                self.install_iso = cc["install_iso"]
        if "network_api_port" in cc:
            self.network_api_port = cc["network_api_port"]
        self.name = cc["name"]
        if "ntp_source" in cc:
            self.ntp_source = cc["ntp_source"]
        if "base_dns_domain" in cc:
            self.base_dns_domain = cc["base_dns_domain"]

        self.kubeconfig = path.join(getcwd(), f'kubeconfig.{cc["name"]}')
        if "kubeconfig" in cc:
            self.kubeconfig = cc["kubeconfig"]

        for n in cc["masters"]:
            self.masters.append(NodeConfig(self.name, **n))

        self.configured_workers = [NodeConfig(self.name, **w) for w in cc["workers"]]
        self.workers = [NodeConfig(self.name, **w) for w in worker_range.filter(cc["workers"])]

        self.hosts = self.parse_hosts(
            yamlpath,
            cc,
            node_names=(n.node for n in self.all_nodes()),
            default_network_api_port=self.network_api_port,
        )

        if not self.is_sno():
            self.api_vip = {'ip': cc["api_vip"]}
            self.ingress_vip = {'ip': cc["ingress_vip"]}

        base_path = os.path.dirname(yaml_path)
        for c in cc["preconfig"]:
            self.preconfig.append(ExtraConfigArgs(base_path, **c))
        for c in cc["postconfig"]:
            self.postconfig.append(ExtraConfigArgs(base_path, **c))

        if test_only:
            # Skip the remaining steps. They access the system, which makes them
            # unsuitable for unit tests.
            #
            # TODO: this flag will go away, and instead the test can inject the pieces
            # that are needed.
            return

        if self.kind == "openshift":
            self.configure_ip_range()

        for c in self.preconfig:
            c.pre_check()
        for c in self.postconfig:
            c.pre_check()

    def configure_ip_range(self) -> None:
        cc = self.fullConfig
        # Reserve IPs for AI, masters and workers.
        ip_mask = cc["ip_mask"]
        ip_range = cc["ip_range"].split("-")
        if len(ip_range) != 2:
            logger.error_and_exit(f"Invalid ip_range config {cc['ip_range']};  it must be of the form '<startIP>-<endIP>.")

        self.full_ip_range = (ip_range[0], ip_range[1])
        n_nodes = len(cc["masters"]) + len(cc["workers"]) + 1

        # Get the last IP used in the running cluster.
        last_ip = self.get_last_ip()

        # Update the last IP based on the config.
        for node in self.all_nodes():
            if node.ip and last_ip and ipaddress.IPv4Address(node.ip) > ipaddress.IPv4Address(last_ip):
                last_ip = node.ip

        if last_ip and ipaddress.IPv4Address(last_ip) > ipaddress.IPv4Address(ip_range[0]) + n_nodes:
            self.ip_range = ip_range[0], str(ipaddress.ip_address(last_ip) + 1)
        else:
            self.ip_range = common.ip_range(ip_range[0], n_nodes)
        logger.info(f"range = {self.ip_range}")
        if common.ip_range_size(ip_range) < common.ip_range_size(self.ip_range):
            logger.error_and_exit("The supplied ip_range config is too small for the number of nodes")

        dynamic_ip_range = common.ip_range(self.ip_range[1], common.ip_range_size(ip_range) - common.ip_range_size(self.ip_range))
        self.local_bridge_config = BridgeConfig(ip=self.ip_range[0], mask=ip_mask, dynamic_ip_range=dynamic_ip_range)
        self.remote_bridge_config = BridgeConfig(ip=ip_range[1], mask=ip_mask)

    def get_last_ip(self) -> str | None:
        hostconn = host.LocalHost()
        last_ip = "0.0.0.0"
        xml_str = hostconn.run("virsh net-dumpxml default").out
        if xml_str.strip():
            tree = et.fromstring(xml_str)
            ip_tree = next((it for it in tree.iter("ip")), et.Element(''))
            dhcp = next((it for it in ip_tree.iter("dhcp")), et.Element(''))
            for e in dhcp:
                if ipaddress.IPv4Address(e.get('ip', "0.0.0.0")) > ipaddress.IPv4Address(last_ip):
                    last_ip = e.get('ip', "0.0.0.0")
            return last_ip
        return None

    def set_cc_defaults(self, cc: dict[str, Union[None, str, list[dict[str, str]]]]) -> None:
        # Some config may be left out from the yaml. Try to provide defaults.
        if "masters" not in cc:
            cc["masters"] = []
        if "workers" not in cc:
            cc["workers"] = []
        if "kubeconfig" not in cc:
            cc["kubeconfig"] = path.join(getcwd(), f'kubeconfig.{cc["name"]}')
        if "preconfig" not in cc:
            cc["preconfig"] = []
        if "postconfig" not in cc:
            cc["postconfig"] = []
        if "proxy" not in cc:
            cc["proxy"] = None
        if "ip_range" not in cc:
            cc["ip_range"] = "192.168.122.1-192.168.122.254"
        if "ip_mask" not in cc:
            cc["ip_mask"] = "255.255.0.0"

    @staticmethod
    def parse_hosts(
        yamlpath: str,
        cc: dict[str, Any],
        *,
        node_names: collections.abc.Iterable[str],
        default_network_api_port: Optional[str],
    ) -> tuple[HostConfig, ...]:
        hosts_lst: list[HostConfig] = []
        lst1 = cc.get("hosts", None)
        if lst1 is None:
            pass
        elif not isinstance(lst1, list):
            raise ValueError(f"\"{yamlpath}.hosts\": this must be a list but is {type(lst1)}")
        else:
            for yamlidx2, e in enumerate(lst1):
                host = HostConfig.parse(
                    yamlidx2,
                    f"{yamlpath}.hosts[{yamlidx2}]",
                    e,
                    default_network_api_port=default_network_api_port,
                )
                for h in hosts_lst:
                    if h.name == host.name:
                        raise ValueError(f"\"{host.yamlpath}.name\": dupliate name {repr(host.name)} with {h.yamlpath}.name.")
                hosts_lst.append(host)
        node_names2 = set(node_names)
        node_names2.discard("localhost")
        for node_name in ["localhost"] + sorted(node_names2):
            if not any(h.name == node_name for h in hosts_lst):
                # artificially create an entry for this host.
                yamlidx2 = len(hosts_lst)
                hosts_lst.append(
                    HostConfig.parse(
                        yamlidx2,
                        f"{yamlpath}.hosts[{yamlidx2}]",
                        {"name": node_name},
                        default_network_api_port=default_network_api_port,
                    )
                )
        return tuple(hosts_lst)

    def _load_full_config(self, yaml_path: str) -> None:
        if not path.exists(yaml_path):
            logger.error(f"could not find config in path: '{yaml_path}'")
            sys.exit(1)

        with open(yaml_path, 'r') as f:
            contents = f.read()
            # load it twice, to get the name of the cluster so
            # that that can be used as a var
            loaded = safe_load(io.StringIO(contents))["clusters"][0]
            contents = self._apply_jinja(contents, loaded["name"])
            self.fullConfig = safe_load(io.StringIO(contents))["clusters"][0]

    def _check_deprecated_config(self) -> None:
        deprecated = self.deprecated_configs.keys() & self.fullConfig.keys()

        for key in deprecated:
            value = self.deprecated_configs[key]
            err = f"Deprecated config \"{key}\" found"
            if value is not None:
                err += f", please use \"{value}\" instead"
            logger.error(err)

        if len(deprecated):
            sys.exit(-1)

    def autodetect_external_port(self) -> None:
        candidate = common.route_to_port(host.LocalHost(), "default")
        if candidate is None:
            logger.error("Failed to found port from default route")
            sys.exit(-1)

        self.external_port = candidate

    def prepare_external_port(self) -> None:
        if self.external_port == "auto":
            self.autodetect_external_port()

    def validate_node_ips(self) -> None:
        def validate_node_ip(n: NodeConfig) -> bool:
            if n.ip is not None and not common.ip_range_contains(self.ip_range, n.ip):
                logger.error(f"Node ({n.name} IP ({n.ip}) not in cluster subnet range: {self.ip_range[0]} - {self.ip_range[1]}.")
                return False
            return True

        if not all(validate_node_ip(n) for n in self.masters + self.configured_workers):
            logger.error(f"Not all master/worker IPs are in the reserved cluster IP range ({self.ip_range}).  Other hosts in the network might be offered those IPs via DHCP.")

    def validate_external_port(self) -> bool:
        return bool(common.ip_links(host.LocalHost(), ifname=self.external_port))

    def _apply_jinja(self, contents: str, cluster_name: str) -> str:
        def worker_number(a: int) -> str:
            self._ensure_clusters_loaded()
            assert self._cluster_info is not None
            name = self._cluster_info.workers[a]
            lab_match = re.search(r"lab(\d+)", name)
            if lab_match:
                return lab_match.group(1)
            else:
                return re.sub("[^0-9]", "", name)

        def worker_name(a: int) -> str:
            self._ensure_clusters_loaded()
            assert self._cluster_info is not None
            return self._cluster_info.workers[a]

        def bmc(a: int) -> str:
            self._ensure_clusters_loaded()
            assert self._cluster_info is not None
            return self._cluster_info.bmcs[a]

        def api_network() -> str:
            self._ensure_clusters_loaded()
            assert self._cluster_info is not None
            return self._cluster_info.network_api_port

        def iso_server() -> str:
            self._ensure_clusters_loaded()
            assert self._cluster_info is not None
            return self._cluster_info.iso_server

        def activation_key() -> str:
            self._ensure_clusters_loaded()
            assert self._cluster_info is not None
            return self._cluster_info.activation_key

        def organization_id() -> str:
            self._ensure_clusters_loaded()
            assert self._cluster_info is not None
            return self._cluster_info.organization_id

        def imc_hostname(a: int) -> str:
            self._ensure_clusters_loaded()
            assert self._cluster_info is not None
            return self._cluster_info.bmc_imc_hostnames[a]

        def ipu_mac_address(a: int) -> str:
            self._ensure_clusters_loaded()
            assert self._cluster_info is not None
            return self._cluster_info.ipu_mac_addresses[a]

        format_string = contents

        template = jinja2.Template(format_string)
        template.globals['worker_number'] = worker_number
        template.globals['worker_name'] = worker_name
        template.globals['api_network'] = api_network
        template.globals['iso_server'] = iso_server
        template.globals['bmc'] = bmc
        template.globals['activation_key'] = activation_key
        template.globals['organization_id'] = organization_id
        template.globals['IMC_hostname'] = imc_hostname
        template.globals['IPU_mac_address'] = ipu_mac_address

        kwargs = {}
        kwargs["cluster_name"] = cluster_name

        t: str = template.render(**kwargs)
        return t

    def _ensure_clusters_loaded(self) -> None:
        if self._cluster_info is not None:
            return
        all_cluster_info = load_all_cluster_info()
        ch = current_host()
        if ch in all_cluster_info:
            self._cluster_info = all_cluster_info[ch]
        elif ch.split(".")[0] in all_cluster_info:
            self._cluster_info = all_cluster_info[ch.split(".")[0]]
        else:
            logger.error(f"Hostname {ch} not found in {all_cluster_info}")
            sys.exit(-1)

    # def __getitem__(self, key):
    #     return self.fullConfig[key]

    # def __setitem__(self, key, value) -> None:
    #     self.fullConfig[key] = value

    def all_nodes(self) -> list[NodeConfig]:
        return self.masters + self.workers

    def all_vms(self) -> list[NodeConfig]:
        return [x for x in self.all_nodes() if x.kind == "vm"]

    def worker_vms(self) -> list[NodeConfig]:
        return [x for x in self.workers if x.kind == "vm"]

    def master_vms(self) -> list[NodeConfig]:
        return [x for x in self.masters if x.kind == "vm"]

    def local_vms(self) -> list[NodeConfig]:
        return [x for x in self.all_vms() if x.node == "localhost"]

    def local_worker_vms(self) -> list[NodeConfig]:
        return [x for x in self.worker_vms() if x.node == "localhost"]

    def is_sno(self) -> bool:
        return len(self.masters) == 1 and self.kind == "openshift"


def main() -> None:
    pass


if __name__ == "__main__":
    main()
