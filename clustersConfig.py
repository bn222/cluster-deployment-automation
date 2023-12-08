from os import path, getcwd
import os
import io
import sys
import re
from typing import Optional
from typing import List
from typing import Dict
import jinja2
from yaml import safe_load
import host
from logger import logger
import secrets
import common
from clusterInfo import ClusterInfo
from clusterInfo import load_all_cluster_info
from dataclasses import dataclass


def random_mac() -> str:
    return "52:54:" + ":".join(re.findall("..", secrets.token_hex()[:8]))


@dataclass
class ExtraConfigArgs:
    name: str
    image: Optional[str] = None
    kubeconfig: Optional[str] = None
    mapping: Optional[List[Dict[str, str]]] = None


@dataclass
class NodeConfig:
    name: str
    kind: str
    node: str
    image_path: str
    mac: str
    disk_size: str
    ram: str
    cpu: str
    preallocated: str
    os_variant: str
    ip: Optional[str] = None
    bmc_ip: Optional[str] = None
    bmc_user: str = "root"
    bmc_password: str = "calvin"

    def __init__(self, cluster_name: str, **kwargs: str):
        if 'image_path' not in kwargs:
            base_path = f'/home/{cluster_name}_guests_images'
            qemu_img_name = f'{kwargs["name"]}.qcow2'
            kwargs['image_path'] = os.path.join(base_path, qemu_img_name)
        if "type" in kwargs:
            logger.warn("Deprecated 'type' in node config. Use 'kind' instead")
            kwargs["kind"] = kwargs["type"]
            del kwargs["type"]
        if "mac" not in kwargs:
            kwargs["mac"] = random_mac()
        if "disk_size" not in kwargs:
            kwargs["disk_size"] = "48"
        if "preallocated" not in kwargs:
            kwargs["preallocated"] = "true"
        if "os_variant" not in kwargs:
            kwargs["os_variant"] = "rhel8.6"
        if "ram" not in kwargs:
            kwargs["ram"] = "32768"
        if "cpu" not in kwargs:
            kwargs["cpu"] = "8"
        for k, v in kwargs.items():
            setattr(self, k, v)

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


# Run the hostname command and only take the first part. For example
# "my-host.test.redhat.com" would return "my-host" here.
# This is only required if we are using the Google sheets integration
# to match the node name syntax in the spreadsheet.
def current_host() -> str:
    lh = host.LocalHost()
    return lh.run("hostname").out.strip().split(".")[0]


class ClustersConfig:
    name: str
    kubeconfig: str
    api_ip: str
    ingress_ip: str
    external_port: str = "auto"
    version: str = "4.13.0-ec.3"
    network_api_port: str = "auto"
    masters: List[NodeConfig] = []
    workers: List[NodeConfig] = []
    hosts: List[HostConfig] = []
    proxy: Optional[str] = None
    noproxy: Optional[str] = None
    preconfig: List[ExtraConfigArgs] = []
    postconfig: List[ExtraConfigArgs] = []

    def __init__(self, yaml_path: str):
        self._cluster_info: Optional[ClusterInfo] = None
        self._load_full_config(yaml_path)

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
            cc["hosts"] = []
        if "proxy" in cc:
            self.proxy = cc["proxy"]
        if "noproxy" in cc:
            self.noproxy = cc["noproxy"]
        if "external_port" in cc:
            self.external_port = cc["external_port"]
        if "version" in cc:
            self.version = cc["version"]
        if "network_api_port" in cc:
            self.network_api_port = cc["network_api_port"]
        self.name = cc["name"]

        self.kubeconfig = path.join(getcwd(), f'kubeconfig.{cc["name"]}')
        if "kubeconfig" in cc:
            self.kubeconfig = cc["kubeconfig"]

        for n in cc["masters"]:
            self.masters.append(NodeConfig(self.name, **n))
        for n in cc["workers"]:
            self.workers.append(NodeConfig(self.name, **n))
        # creates hosts entries for each referenced node name
        node_names = set(x["name"] for x in cc["hosts"])
        for node in self.all_nodes():
            if node.kind != "physical" and node.node not in node_names:
                cc["hosts"].append({"name": node.node})
                node_names.add(node.node)

        if not self.is_sno():
            self.api_ip = cc["api_ip"]
            self.ingress_ip = cc["ingress_ip"]

        for e in cc["hosts"]:
            self.hosts.append(HostConfig(self.network_api_port, **e))

        for c in cc["preconfig"]:
            self.preconfig.append(ExtraConfigArgs(**c))
        for c in cc["postconfig"]:
            self.postconfig.append(ExtraConfigArgs(**c))

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

    def autodetect_external_port(self) -> None:
        candidate = common.route_to_port(host.LocalHost(), "default")
        if candidate is None:
            logger.error("Failed to found port from default route")
            sys.exit(-1)

        self.external_port = candidate

    def prepare_external_port(self) -> None:
        if self.external_port == "auto":
            self.autodetect_external_port()

    def validate_external_port(self) -> bool:
        return host.LocalHost().port_exists(self.external_port)

    def _apply_jinja(self, contents: str, cluster_name: str) -> str:
        def worker_number(a: int) -> str:
            self._ensure_clusters_loaded()
            assert self._cluster_info is not None
            name = self._cluster_info.workers[a]
            return re.sub("[^0-9]", "", name)

        def worker_name(a: int) -> str:
            self._ensure_clusters_loaded()
            assert self._cluster_info is not None
            return self._cluster_info.workers[a]

        def api_network() -> str:
            self._ensure_clusters_loaded()
            assert self._cluster_info is not None
            return self._cluster_info.network_api_port

        format_string = contents

        template = jinja2.Template(format_string)
        template.globals['worker_number'] = worker_number
        template.globals['worker_name'] = worker_name
        template.globals['api_network'] = api_network

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
        else:
            sys.exit(-1)

    # def __getitem__(self, key):
    #     return self.fullConfig[key]

    # def __setitem__(self, key, value) -> None:
    #     self.fullConfig[key] = value

    def all_nodes(self) -> List[NodeConfig]:
        return self.masters + self.workers

    def all_vms(self) -> List[NodeConfig]:
        return [x for x in self.all_nodes() if x.kind == "vm"]

    def worker_vms(self) -> List[NodeConfig]:
        return [x for x in self.workers if x.kind == "vm"]

    def master_vms(self) -> List[NodeConfig]:
        return [x for x in self.masters if x.kind == "vm"]

    def local_vms(self) -> List[NodeConfig]:
        return [x for x in self.all_vms() if x.node == "localhost"]

    def local_worker_vms(self) -> List[NodeConfig]:
        return [x for x in self.worker_vms() if x.node == "localhost"]

    def is_sno(self) -> bool:
        return len(self.masters) == 1 and len(self.workers) == 0


def main() -> None:
    pass


if __name__ == "__main__":
    main()
