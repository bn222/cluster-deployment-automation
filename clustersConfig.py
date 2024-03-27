from os import path, getcwd
import os
import io
import sys
import re
import ipaddress
from typing import Optional
import xml.etree.ElementTree as et
import jinja2
from yaml import safe_load
import host
from logger import logger
import secrets
import common
from clusterInfo import ClusterInfo
from clusterInfo import load_all_cluster_info
from dataclasses import dataclass, field


def random_mac() -> str:
    return "52:54:" + ":".join(re.findall("..", secrets.token_hex()[:8]))


@dataclass
class ExtraConfigArgs:
    name: str

    # OVN-K extra configs:
    # New ovn-k image to use.
    image: Optional[str] = None
    # Time to wait for new ovn-k to roll out.
    ovnk_rollout_timeout: str = "20m"

    kubeconfig: Optional[str] = None
    mapping: Optional[list[dict[str, str]]] = None

    # Custom OVN build extra configs:
    # Time to wait for the builders to roll out.
    custom_ovn_build_timeout: str = "20m"


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
        if self.kind == "physical" or self.kind == "bf":
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


@dataclass
class HostConfig:
    name: str
    network_api_port: str
    username: str = "core"
    password: Optional[str] = None
    pre_installed: str = "true"

    def __init__(self, network_api_port: str, **kwargs: str):
        if "network_api_port" not in kwargs:
            kwargs["network_api_port"] = network_api_port
        for k, v in kwargs.items():
            setattr(self, k, v)

    def is_preinstalled(self) -> bool:
        return self.pre_installed == "true"


@dataclass
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
    external_port: str = "auto"
    kind: str = "openshift"
    version: str = "4.14.0-nightly"
    network_api_port: str = "auto"
    masters: list[NodeConfig] = []
    workers: list[NodeConfig] = []
    configured_workers: list[NodeConfig] = []
    local_bridge_config: BridgeConfig
    remote_bridge_config: BridgeConfig
    full_ip_range: tuple[str, str]
    ip_range: tuple[str, str]
    hosts: list[HostConfig] = []
    proxy: Optional[str] = None
    noproxy: Optional[str] = None
    preconfig: list[ExtraConfigArgs] = []
    postconfig: list[ExtraConfigArgs] = []
    ntp_source: str = "clock.redhat.com"
    base_dns_domain: str = "redhat.com"

    # All configurations that used to be supported but are not anymore.
    # Used to warn the user to change their config.
    deprecated_configs: dict[str, Optional[str]] = {"api_ip": "api_vip", "ingress_ip": "ingress_vip"}

    def __init__(self, yaml_path: str, worker_range: common.RangeList):
        self._cluster_info: Optional[ClusterInfo] = None
        self._load_full_config(yaml_path)
        self._check_deprecated_config()

        cc = self.fullConfig
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
        if "hosts" not in cc:
            cc["hosts"] = [{"name": "localhost"}]
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
        if "network_api_port" in cc:
            self.network_api_port = cc["network_api_port"]
        self.name = cc["name"]
        if "ntp_source" in cc:
            self.ntp_source = cc["ntp_source"]
        if "base_dns_domain" in cc:
            self.base_dns_domain = cc["base_dns_domain"]
        if "ip_range" not in cc:
            cc["ip_range"] = "192.168.122.1-192.168.122.254"
        if "ip_mask" not in cc:
            cc["ip_mask"] = "255.255.0.0"

        self.kubeconfig = path.join(getcwd(), f'kubeconfig.{cc["name"]}')
        if "kubeconfig" in cc:
            self.kubeconfig = cc["kubeconfig"]

        for n in cc["masters"]:
            self.masters.append(NodeConfig(self.name, **n))

        self.configured_workers = [NodeConfig(self.name, **w) for w in cc["workers"]]
        self.workers = [NodeConfig(self.name, **w) for w in worker_range.filter_list(cc["workers"])]

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
            if node.ip and ipaddress.IPv4Address(node.ip) > ipaddress.IPv4Address(last_ip):
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

        # creates hosts entries for each referenced node name
        node_names = {x["name"] for x in cc["hosts"]}
        for node in self.all_nodes():
            if node.node not in node_names:
                cc["hosts"].append({"name": node.node})
                node_names.add(node.node)

        if not self.is_sno():
            self.api_vip = {'ip': cc["api_vip"]}
            self.ingress_vip = {'ip': cc["ingress_vip"]}

        for e in cc["hosts"]:
            self.hosts.append(HostConfig(self.network_api_port, **e))

        for c in cc["preconfig"]:
            self.preconfig.append(ExtraConfigArgs(**c))
        for c in cc["postconfig"]:
            self.postconfig.append(ExtraConfigArgs(**c))

    def get_last_ip(self) -> str:
        hostconn = host.LocalHost()
        last_ip = "0.0.0.0"
        xml_str = hostconn.run("virsh net-dumpxml default").out
        tree = et.fromstring(xml_str)
        ip_tree = next((it for it in tree.iter("ip")), et.Element(''))
        dhcp = next((it for it in ip_tree.iter("dhcp")), et.Element(''))
        for e in dhcp:
            if ipaddress.IPv4Address(e.get('ip', "0.0.0.0")) > ipaddress.IPv4Address(last_ip):
                last_ip = e.get('ip', "0.0.0.0")
        return last_ip

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
        return host.LocalHost().port_exists(self.external_port)

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

        format_string = contents

        template = jinja2.Template(format_string)
        template.globals['worker_number'] = worker_number
        template.globals['worker_name'] = worker_name
        template.globals['api_network'] = api_network
        template.globals['bmc'] = bmc

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
        return len(self.masters) == 1


def main() -> None:
    pass


if __name__ == "__main__":
    main()
