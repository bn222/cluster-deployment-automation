import itertools
import os
import time
from concurrent.futures import Future, ThreadPoolExecutor
from logger import logger
from typing import List, Optional, Tuple

import common
import coreosBuilder
import host
from clustersConfig import BridgeConfig, ClustersConfig, HostConfig, NodeConfig
from clusterNode import ClusterNode, X86ClusterNode, VmClusterNode, BFClusterNode
from virtualBridge import VirBridge


class ClusterHost:
    """
    Physical host representation.  Contains fields and methods that allow to:
    - connect to the host
    - provision and tear down master/worker k8s nodes on the host
    - configure host networking
    """

    hostconn: host.Host
    bridge: VirBridge
    config: HostConfig
    needs_api_network: bool
    api_port: Optional[str] = None
    k8s_master_nodes: List[ClusterNode]
    k8s_worker_nodes: List[ClusterNode]
    hosts_vms: bool

    def __init__(self, h: host.Host, c: HostConfig, cc: ClustersConfig, bc: BridgeConfig, serves_dhcp: bool):
        self.bridge = VirBridge(h, bc)
        self.hostconn = h
        self.config = c

        def _create_k8s_nodes(configs: List[NodeConfig]) -> List[ClusterNode]:
            nodes: List[ClusterNode] = []
            for node_config in configs:
                if node_config.node != self.config.name:
                    continue
                if node_config.kind == "vm":
                    nodes.append(VmClusterNode(self.hostconn, node_config))
                elif node_config.kind == "physical":
                    nodes.append(X86ClusterNode(node_config, cc.external_port))
                elif node_config.kind == "bf":
                    nodes.append(BFClusterNode(node_config, cc.external_port))
                else:
                    raise ValueError()
            return nodes

        self.k8s_master_nodes = _create_k8s_nodes(cc.masters)
        self.k8s_worker_nodes = _create_k8s_nodes(cc.workers)
        self.hosts_vms = any(k8s_node.config.kind == "vm" for k8s_node in self._k8s_nodes())

        if not self.config.pre_installed:
            self.hostconn.need_sudo()

        if self.hosts_vms:
            if not self.hostconn.is_localhost():
                self.hostconn.ssh_connect(self.config.username, self.config.password)

        self.needs_api_network = self.hosts_vms or serves_dhcp
        if self.needs_api_network:
            if self.config.network_api_port == "auto":
                self.api_port = common.get_auto_port(self.hostconn)
            else:
                self.api_port = self.config.network_api_port
            if self.api_port is None:
                logger.error_and_exit(f"Can't find a valid network API port, config is {self.config.network_api_port}")
            logger.info(f"Using {self.api_port} as network API port")

    def _k8s_nodes(self) -> List[ClusterNode]:
        return self.k8s_master_nodes + self.k8s_worker_nodes

    def _ensure_images(self, local_iso_path: str, infra_env: str, nodes: List[ClusterNode]) -> None:
        if not self.hosts_vms:
            return

        image_paths = {node.config.image_path for node in nodes}
        for vm_image_path in image_paths:
            image_path = os.path.dirname(vm_image_path)
            self.hostconn.run(f"mkdir -p {image_path}")
            self.hostconn.run(f"chmod a+rw {image_path}")
            iso_path = os.path.join(image_path, f"{infra_env}.iso")
            logger.info(f"Copying {local_iso_path} to {self.hostconn.hostname()}:/{iso_path}")
            self.hostconn.copy_to(local_iso_path, iso_path)
            logger.debug(f"iso_path is now {iso_path} for {self.hostconn.hostname()}")

    def configure_bridge(self) -> None:
        if not self.needs_api_network:
            return
        assert self.api_port is not None

        self.bridge.configure(self.api_port)

    def ensure_linked_to_network(self, dhcp_bridge: VirBridge) -> None:
        if not self.needs_api_network:
            return
        assert self.api_port is not None

        interface = common.find_port(self.hostconn, self.api_port)
        if not interface:
            logger.error_and_exit(f"Host {self.config.name} misses API network interface {self.api_port}")

        logger.info(f"Block all DHCP replies on {self.api_port} except the ones coming from the DHCP bridge")
        self.hostconn.run(f"ebtables -t filter -A FORWARD -p IPv4 --in-interface {self.api_port} --src {dhcp_bridge.eth_address()} --ip-proto udp --ip-sport 67 --ip-dport 68 -j ACCEPT")
        self.hostconn.run(f"ebtables -t filter -A FORWARD -p IPv4 --in-interface {self.api_port} --ip-proto udp --ip-sport 67 --ip-dport 68 -j DROP")

        logger.info(f"Link {self.api_port} to virbr0")
        br_name = "virbr0"

        if interface.master is None:
            logger.info(f"No master set for interface {self.api_port}, setting it to {br_name}")
            self.hostconn.run(f"ip link set {self.api_port} master {br_name}")
        elif interface.master != br_name:
            logger.error_and_exit(f"Incorrect master set for interface {self.api_port}")

        logger.info(f"Setting interface {self.api_port} as unmanaged in NetworkManager")
        self.hostconn.run(f"nmcli device set {self.api_port} managed no")

    def ensure_not_linked_to_network(self) -> None:
        if not self.needs_api_network:
            return
        assert self.api_port is not None

        logger.info(f'Validating API network port {self.api_port}')
        if not self.hostconn.port_exists(self.api_port):
            logger.error(f"Can't find API network port {self.api_port}")
            return
        if not self.hostconn.port_has_carrier(self.api_port):
            logger.error(f"API network port {self.api_port} doesn't have a carrier")
            return

        logger.info(self.hostconn.run(f"ip link set {self.api_port} nomaster"))
        logger.info(f"Setting interface {self.api_port} as managed in NetworkManager")
        self.hostconn.run(f"nmcli device set {self.api_port} managed yes")

        logger.info(f"Removing DHCP reply drop rules on {self.api_port}")
        self.hostconn.run("ebtables -t filter -F FORWARD")

    def _configure_dhcp_entries(self, dhcp_bridge: VirBridge, nodes: List[ClusterNode]) -> None:
        if not self.hosts_vms:
            return

        for node in nodes:
            dhcp_bridge.setup_dhcp_entry(node.config)

    def configure_master_dhcp_entries(self, dhcp_bridge: VirBridge) -> None:
        return self._configure_dhcp_entries(dhcp_bridge, self.k8s_master_nodes)

    def configure_worker_dhcp_entries(self, dhcp_bridge: VirBridge) -> None:
        return self._configure_dhcp_entries(dhcp_bridge, self.k8s_worker_nodes)

    def preinstall(self, external_port: str, executor: ThreadPoolExecutor) -> Future[None]:
        def _preinstall() -> None:
            if self.config.is_preinstalled():
                return

            iso = "fedora-coreos.iso"
            coreosBuilder.ensure_fcos_exists(os.path.join(os.getcwd(), iso))
            logger.debug(f"Provisioning Host {self.config.name}")

            # Use the X86 node provisioning infrastructure to provision the host
            # too.
            x86_node = X86ClusterNode(self.k8s_worker_nodes[0].config, external_port)
            x86_node._boot_iso_x86(iso)

        return executor.submit(_preinstall)

    def _start_nodes(self, iso_path: str, infra_env: str, executor: ThreadPoolExecutor, nodes: List[ClusterNode]) -> List[Future[Optional[host.Result]]]:
        self._ensure_images(iso_path, infra_env, nodes)
        futures = []
        for node in nodes:
            remote_iso_path = os.path.join(os.path.dirname(node.config.image_path), f"{infra_env}.iso")
            node.start(remote_iso_path, executor)
            futures.append(node.future)
        return futures

    def start_masters(self, iso_path: str, infra_env: str, executor: ThreadPoolExecutor) -> List[Future[Optional[host.Result]]]:
        return self._start_nodes(iso_path, infra_env, executor, self.k8s_master_nodes)

    def start_workers(self, iso_path: str, infra_env: str, executor: ThreadPoolExecutor) -> List[Future[Optional[host.Result]]]:
        return self._start_nodes(iso_path, infra_env, executor, self.k8s_worker_nodes)

    def _wait_for_boot(self, nodes: List[ClusterNode], desired_ip_range: Tuple[str, str]) -> None:
        if not nodes:
            return

        for try_count in itertools.count(0):
            states = {node.config.name: node.has_booted() for node in nodes}
            node_names = ', '.join(states.keys())
            logger.info(f"Waiting for nodes ({node_names}) to have booted (try #{try_count})..")
            logger.info(f"Current boot state: {states}")
            if all(has_booted for has_booted in states.values()):
                break
            time.sleep(10)
        logger.info(f"It took {try_count} tries to wait for nodes ({node_names}) to have booted.")

        for try_count in itertools.count(0):
            states = {node.config.name: node.post_boot(desired_ip_range) for node in nodes}
            node_names = ', '.join(states.keys())
            logger.info(f"Waiting for nodes ({node_names}) to have run post_boot (try #{try_count})..")
            logger.info(f"Current post_boot state: {states}")
            if all(has_post_booted for has_post_booted in states.values()):
                break
            time.sleep(10)
        logger.info(f"It took {try_count} tries to wait for nodes ({node_names}) to have run post_boot.")

        for node in nodes:
            node.health_check()

    def wait_for_masters_boot(self, desired_ip_range: Tuple[str, str]) -> None:
        return self._wait_for_boot(self.k8s_master_nodes, desired_ip_range)

    def wait_for_workers_boot(self, desired_ip_range: Tuple[str, str]) -> None:
        return self._wait_for_boot(self.k8s_worker_nodes, desired_ip_range)

    def teardown(self) -> None:
        for node in self._k8s_nodes():
            node.teardown()
