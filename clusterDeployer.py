import os
import sys
import time
import json
import xml.etree.ElementTree as et
import shutil
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import Future
from typing import Optional
from typing import Generator
from typing import Dict
from typing import Union
from typing import List
from typing import Callable
from typing import Set
import re
import logging
import paramiko
from assistedInstaller import AssistedClientAutomation
import host
from clustersConfig import ClustersConfig, NodeConfig, HostConfig, ExtraConfigArgs
from k8sClient import K8sClient
from nfs import NFS
import coreosBuilder
from typing import Tuple
import common
from python_hosts import Hosts, HostsEntry
from logger import logger
import microshift
from extraConfigRunner import ExtraConfigRunner
from host import BMC
import abc


class VirBridge:
    """
    Wrapper on top of the libvirt virtual bridge.

    It can be running locally or remote.
    """

    hostconn: host.Host

    def __init__(self, h: host.Host):
        self.hostconn = h

    def setup_dhcp_entry(self, cfg: NodeConfig) -> None:
        if cfg.ip is None:
            logger.error_and_exit(f"Missing IP for node {cfg.name}")
        ip = cfg.ip
        mac = cfg.mac
        name = cfg.name
        # If adding a worker node fails, one might want to retry w/o tearing down
        # the whole cluster. In that case, the DHCP entry might already be present,
        # with wrong mac -> remove it

        cmd = "virsh net-dumpxml default"
        ret = self.hostconn.run_or_die(cmd)
        if f"'{name}'" in ret.out:
            logger.info(f"{name} already configured as static DHCP entry - removing before adding back with proper configuration")
            host_xml = f"<host name='{name}'/>"
            cmd = f"virsh net-update default delete ip-dhcp-host \"{host_xml}\" --live --config"
            self.hostconn.run_or_die(cmd)

        cmd = "virsh net-dhcp-leases default"
        ret = self.hostconn.run(cmd)
        # Look for "{name} " in the output. The space is intended to differentiate between "bm-worker-2 " and e.g. "bm-worker-20"
        if f"{name} " in ret.out:
            logger.error(f"Error: {name} found in dhcp leases")
            logger.error("To fix this, run")
            logger.error("\tvirsh net-destroy default")
            logger.error("\tRemove wrong entries from /var/lib/libvirt/dnsmasq/virbr0.status")
            logger.error("\tvirsh net-start default")
            logger.error("\tsystemctl restart libvirt")
            sys.exit(-1)

        host_xml = f"<host mac='{mac}' name='{name}' ip='{ip}'/>"
        logger.info(f"Creating static DHCP entry for VM {name}, ip {ip} mac {mac}")
        cmd = f"virsh net-update default add ip-dhcp-host \"{host_xml}\" --live --config"
        self.hostconn.run_or_die(cmd)

    def _ensure_started(self, api_network: str, bridge_xml: str) -> None:
        cmd = "virsh net-destroy default"
        self.hostconn.run(cmd)  # ignore return code - it might fail if net was not started

        cmd = "virsh net-undefine default"
        ret = self.hostconn.run(cmd)
        if ret.returncode != 0 and "Network not found" not in ret.err:
            logger.error_and_exit(str(ret))

        # Fix cases where virsh net-start fails with error "... interface virbr0: File exists"
        cmd = "ip link delete virbr0"
        self.hostconn.run(cmd)  # ignore return code - it might fail if virbr did not exist

        cmd = f"virsh net-define {bridge_xml}"
        self.hostconn.run_or_die(cmd)

        # set interface down before starting bridge as otherwise bridge start might fail if interface
        # already got an IP address in same network as bridge
        self.hostconn.run(f"ip link set {api_network} down")

        cmd = "virsh net-start default"
        self.hostconn.run_or_die(cmd)

        self.hostconn.run(f"ip link set {api_network} up")

    def limit_dhcp_range(self, old_range: str, new_range: str) -> None:
        # restrict dynamic dhcp range: we use static dhcp ip addresses; however, those addresses might have been used
        # through the dynamic dhcp by any systems such as systems ready to be installed.
        cmd = "virsh net-dumpxml default"
        ret = self.hostconn.run(cmd)
        if f"range start='{old_range}'" in ret.out:
            host_xml = f"<range start='{old_range}' end='192.168.122.254'/>"
            cmd = f"virsh net-update default delete ip-dhcp-range \"{host_xml}\" --live --config"
            r = self.hostconn.run(cmd)
            logger.debug(r.err if r.err else r.out)

            host_xml = f"<range start='{new_range}' end='192.168.122.254'/>"
            cmd = f"virsh net-update default add ip-dhcp-range \"{host_xml}\" --live --config"
            r = self.hostconn.run(cmd)
            logger.debug(r.err if r.err else r.out)

    def _network_xml(self, ip: str, dhcp_range: Optional[Tuple[str, str]] = None) -> str:
        if dhcp_range is None:
            dhcp_part = ""
        else:
            dhcp_part = f"""<dhcp>
                <range start='{dhcp_range[0]}' end='{dhcp_range[1]}'/>
                </dhcp>"""

        return f"""
                <network>
                <name>default</name>
                <forward mode='nat'/>
                <bridge name='virbr0' stp='off' delay='0'/>
                <ip address='{ip}' netmask='255.255.0.0'>
                    {dhcp_part}
                </ip>
                </network>"""

    def _restart(self) -> None:
        self.hostconn.run_or_die("systemctl restart libvirtd")

    def _ensure_run_as_root(self) -> None:
        qemu_conf = self.hostconn.read_file("/etc/libvirt/qemu.conf")
        if re.search('\nuser = "root"', qemu_conf) and re.search('\nuser = "root"', qemu_conf):
            return
        self.hostconn.run("sed -e 's/#\\(user\\|group\\) = \".*\"$/\\1 = \"root\"/' -i /etc/libvirt/qemu.conf")
        self._restart()

    def configure(self, api_network: str) -> None:
        hostname = self.hostconn.hostname()
        cmd = "systemctl enable libvirtd --now"
        self.hostconn.run_or_die(cmd)

        self._ensure_run_as_root()

        # stp must be disabled or it might conflict with default configuration of some physical switches
        # 'bridge' section of network 'default' can't be updated => destroy and recreate
        # check that default exists and contains stp=off
        cmd = "virsh net-dumpxml default"
        ret = self.hostconn.run(cmd)

        if "stp='off'" not in ret.out or "range start='192.168.122.2'" in ret.out:
            logger.info("Destoying and recreating bridge")
            logger.info(f"creating default-net.xml on {hostname}")
            if hostname == "localhost":
                contents = self._network_xml('192.168.122.1', ('192.168.122.129', '192.168.122.254'))
            else:
                contents = self._network_xml('192.168.123.250')

            bridge_xml = os.path.join("/tmp", 'vir_bridge.xml')
            self.hostconn.write(bridge_xml, contents)
            # Not sure why/whether this is needed. But we saw failures w/o it.
            # Without this, net-undefine within ensure_bridge_is_started fails as libvirtd fails to restart
            # We need to investigate how to remove the sleep to speed up
            time.sleep(5)
            self._ensure_started(api_network, bridge_xml)

            self.limit_dhcp_range("192.168.122.2", "192.168.122.129")

            self._restart()

            # Not sure why/whether this is needed. But we saw failures w/o it.
            # We need to investigate how to remove the sleep to speed up
            time.sleep(5)


class ClusterNode:
    """
    Base class for all k8s-like nodes to inherit from.

    At a minimum, a correct implementation should provide:
    - a start() method: to provision the node.
    - a has_booted() method: to determine if the node has booted
    - a post_boot() method: to execute actions after the node has been
      provisioned and booted for the first time
    """

    config: NodeConfig
    future: Future[Optional[host.Result]]
    dynamic_ip: Optional[str] = None

    def __init__(self, config: NodeConfig):
        def empty() -> Future[Optional[host.Result]]:
            f: Future[Optional[host.Result]] = Future()
            f.set_result(None)
            return f

        self.config = config
        self.future = empty()

    def ip(self) -> str:
        if self.config.ip is not None:
            return self.config.ip
        if self.dynamic_ip is None:
            logger.error_and_exit(f"Node {self.config.name} has no IP address")
        return self.dynamic_ip

    @abc.abstractmethod
    def start(self, iso_or_image_path: str, executor: ThreadPoolExecutor) -> None:
        pass

    @abc.abstractmethod
    def has_booted(self) -> bool:
        pass

    @abc.abstractmethod
    def post_boot(self, desired_ip_range: Tuple[str, str]) -> bool:
        pass

    def teardown(self) -> None:
        pass

    def set_password(self, user: str = "root", password: str = "redhat") -> None:
        rh = host.RemoteHost(self.ip())
        rh.ssh_connect("core")
        rh.run_or_die(f"echo {user}:{password} | sudo chpasswd")

    def print_logs(self) -> None:
        rh = host.RemoteHost(self.ip())
        logger.info(f"Gathering logs from {self.config.name}")
        logger.info(rh.run("sudo journalctl TAG=agent --no-pager").out)

    def _verify_package_is_installed(self, package: str) -> bool:
        rh = host.RemoteHost(self.ip())
        rh.ssh_connect("core")
        ret = rh.run(f"rpm -qa | grep {package}")
        return not ret.returncode

    def health_check(self) -> None:
        required_packages = ["kernel-modules-extra"]
        missing_packages = [p for p in required_packages if not self._verify_package_is_installed(p)]
        for p in missing_packages:
            logger.error(f"Required rpm '{p}' is not installed")
        if any(missing_packages):
            sys.exit(-1)


class VmClusterNode(ClusterNode):
    hostconn: host.Host
    install_wait: bool = True

    def __init__(self, h: host.Host, config: NodeConfig):
        super().__init__(config)
        self.hostconn = h

    def ip(self) -> str:
        assert self.config.ip is not None
        return self.config.ip

    def setup_vm(self, iso_or_image_path: str) -> host.Result:
        disk_size_gb = self.config.disk_size
        if iso_or_image_path.endswith(".iso"):
            options = "-o preallocation="
            if self.config.is_preallocated():
                options += "full"
            else:
                options += "off"

            os.makedirs(os.path.dirname(self.config.image_path), exist_ok=True)
            logger.info(f"creating {disk_size_gb}GB storage for VM {self.config.name} at {self.config.image_path}")
            self.hostconn.run_or_die(f'qemu-img create -f qcow2 {options} {self.config.image_path} {disk_size_gb}G')

            cdrom_line = f"--cdrom {iso_or_image_path}"
            append = "--wait=-1"
            self.install_wait = True
        else:
            cdrom_line = ""
            append = "--noautoconsole"
            self.install_wait = False

        if self.hostconn.is_localhost():
            network = "network=default"
        else:
            network = "bridge=virbr0"
        cmd = f"""
        virt-install
            --connect qemu:///system
            -n {self.config.name}
            -r {self.config.ram}
            --cpu host
            --vcpus {self.config.cpu}
            --os-variant={self.config.os_variant}
            --import
            --network {network},mac={self.config.mac}
            --events on_reboot=restart
            {cdrom_line}
            --disk path={self.config.image_path}
            {append}
        """

        logger.info(f"Starting VM {self.config.name}")
        ret = self.hostconn.run(cmd)
        if ret.returncode != 0:
            logger.info(f"Finished starting VM {self.config.name}, cmd = {cmd}, ret = {ret}")
        else:
            logger.info(f"Finished starting VM {self.config.name} without any errors")
        return ret

    def start(self, iso_or_image_path: str, executor: ThreadPoolExecutor) -> None:
        self.future = executor.submit(self.setup_vm, iso_or_image_path)

    def has_booted(self) -> bool:
        return self.hostconn.vm_is_running(self.config.name)

    def post_boot(self, desired_ip_range: Tuple[str, str]) -> bool:
        if not self.install_wait:
            self.future.result()
        return True

    def teardown(self) -> None:
        # remove the image only if it really exists
        image_path = self.config.image_path
        self.hostconn.remove(image_path.replace(".qcow2", ".img"))
        self.hostconn.remove(image_path)

        # destroy the VM only if it really exists
        if self.hostconn.run(f"virsh desc {self.config.name}").returncode == 0:
            r = self.hostconn.run(f"virsh destroy {self.config.name}")
            logger.info(r.err if r.err else r.out.strip())
            r = self.hostconn.run(f"virsh undefine {self.config.name}")
            logger.info(r.err if r.err else r.out.strip())


class X86ClusterNode(ClusterNode):
    external_port: str

    def __init__(self, config: NodeConfig, external_port: str):
        super().__init__(config)
        self.external_port = external_port

    def _boot_iso_x86(self, iso: str) -> host.Result:
        logger.info(f"trying to boot {self.config.node} using {iso}")

        lh = host.LocalHost()
        nfs = NFS(lh, self.external_port)

        bmc = BMC.from_bmc(self.config.bmc, self.config.bmc_user, self.config.bmc_password)
        h = host.HostWithBF2(self.config.node, bmc)

        iso = nfs.host_file(os.path.join(os.getcwd(), iso))
        h.boot_iso_redfish(iso)
        h.ssh_connect("core")
        logger.info("connected")
        return h.run("hostname")

    def start(self, iso_or_image_path: str, executor: ThreadPoolExecutor) -> None:
        self.future = executor.submit(self._boot_iso_x86, iso_or_image_path)

    def has_booted(self) -> bool:
        return self.future.done()

    def post_boot(self, desired_ip_range: Tuple[str, str]) -> bool:
        rh = host.RemoteHost(self.config.node)
        rh.ssh_connect("core")
        ipr_entries = common.ipa_to_entries(rh.run("ip -json a").out)
        ips = []
        for ipr in ipr_entries:
            for addr_info in ipr.addr_info:
                if addr_info.family != "inet":
                    continue
                if common.ip_range_contains(desired_ip_range, addr_info.local):
                    ips.append(addr_info.local)

        if len(ips) != 1:
            logger.debug(f"Node {self.config.name} has unexpected IP addresses in range {desired_ip_range}.  Got: {ips}")
            return False
        self.dynamic_ip = ips[0]
        return True


class BFClusterNode(ClusterNode):
    external_port: str

    def __init__(self, config: NodeConfig, external_port: str):
        super().__init__(config)
        self.external_port = external_port

    def _boot_iso_bf(self, iso: str) -> host.Result:
        lh = host.LocalHost()
        nfs = NFS(lh, self.external_port)

        logger.info(f"Preparing BF on host {self.config.node}")
        bmc = BMC.from_bmc(self.config.bmc, self.config.bmc_user, self.config.bmc_password)
        h = host.HostWithBF2(self.config.node, bmc)
        skip_boot = False
        if h.ping():
            try:
                h.ssh_connect("core")
                skip_boot = h.running_fcos()
            except paramiko.ssh_exception.AuthenticationException:
                logger.info("Authentication failed, will not be able to skip boot")

        if skip_boot:
            logger.info(f"Skipping booting {self.config.node}, already booted with FCOS")
        else:
            nfs_file = nfs.host_file("/root/iso/fedora-coreos.iso")
            h.boot_iso_redfish(nfs_file)
            time.sleep(10)
            h.ssh_connect("core")

        if not h.running_fcos():
            logger.error_and_exit("Expected FCOS after booting host {self.config.node} but booted something else")

        nfs_iso = nfs.host_file(f"/root/iso/{iso}")
        nfs_key = nfs.host_file("/root/iso/ssh_priv_key")
        output = h.bf_pxeboot(nfs_iso, nfs_key)
        logger.debug(output)
        if output.returncode:
            logger.error_and_exit(f"Failed to run pxeboot on bf {self.config.node}")
        else:
            logger.info(f"succesfully ran pxeboot on bf {self.config.node}")

        # ip is printed as the last thing when bf is pxeboot'ed
        bf_ip = output.out.strip().split("\n")[-1].strip()
        h.connect_to_bf(bf_ip)
        max_tries = 3
        bf_interfaces = ["enp3s0f0", "enp3s0f0np0"]
        logger.info(f'Will try {max_tries} times to get an IP on {" or ".join(bf_interfaces)}')
        ip = None
        tries = 0
        while True:
            ipa = h.run_on_bf("ip -json a").out
            detected = common.ipa_to_entries(ipa)
            found = [e for e in detected if e.ifname in bf_interfaces]
            if len(found) != 1:
                logger.error(f"Failed to find expected number of interfaces on bf {self.config.node}")
                logger.error(f"Output was: {ipa}")
                sys.exit(-1)

            ip = None
            for e in found[0].addr_info:
                if e.family == "inet":
                    ip = e.local
            if ip is not None:
                break
            logger.info(f"IP missing on {found[0]}, output was {ipa}")
            tries += 1
            if tries >= max_tries:
                logger.error(f"IP missing on {found[0]}")
                break
            time.sleep(10)

        if ip is None:
            return host.Result(out="", err="Could not detect IP", returncode=1)
        logger.info(f"Detected ip {ip}")
        return host.Result(out=f"{ip}", err="", returncode=0)

    def start(self, iso_or_image_path: str, executor: ThreadPoolExecutor) -> None:
        self.future = executor.submit(self._boot_iso_bf, iso_or_image_path)

    def has_booted(self) -> bool:
        return self.future.done()

    def post_boot(self, desired_ip_range: Tuple[str, str]) -> bool:
        result: Optional[host.Result] = self.future.result()
        if result is not None:
            self.dynamic_ip = result.out
        else:
            logger.error_and_exit(f"Couldn't find ip of worker {self.config.name}")
        return True


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
    k8s_master_nodes: List[ClusterNode]
    k8s_worker_nodes: List[ClusterNode]
    hosts_vms: bool

    def __init__(self, h: host.Host, c: HostConfig, cc: ClustersConfig):
        self.bridge = VirBridge(h)
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

        if self.hosts_vms and not self.hostconn.is_localhost():
            self.hostconn.ssh_connect(self.config.username, self.config.password)

    def _k8s_nodes(self) -> List[ClusterNode]:
        return self.k8s_master_nodes + self.k8s_worker_nodes

    def _ensure_images(self, local_iso_path: str, infra_env: str, nodes: List[ClusterNode]) -> None:
        if not self.hosts_vms:
            return

        image_paths = (node.config.image_path for node in nodes)
        for vm_image_path in image_paths:
            image_path = os.path.dirname(vm_image_path)
            self.hostconn.run(f"mkdir -p {image_path}")
            self.hostconn.run(f"chmod a+rw {image_path}")
            iso_path = os.path.join(image_path, f"{infra_env}.iso")
            logger.info(f"Copying {local_iso_path} to {self.hostconn.hostname()}:/{iso_path}")
            self.hostconn.copy_to(local_iso_path, iso_path)
            logger.debug(f"iso_path is now {iso_path} for {self.hostconn.hostname()}")

    def configure_bridge(self) -> None:
        if not self.hosts_vms:
            return

        self.bridge.configure(self.config.network_api_port)

    def ensure_linked_to_network(self) -> None:
        if not self.hosts_vms:
            return

        api_network = self.config.network_api_port
        logger.info(f"link {api_network} to virbr0")
        interface = common.find_port(self.hostconn, api_network)
        if not interface:
            logger.error_and_exit(f"Host {self.config.name} misses API network interface {api_network}")

        br_name = "virbr0"

        if interface.master is None:
            logger.info(f"No master set for interface {api_network}, setting it to {br_name}")
            self.hostconn.run(f"ip link set {api_network} master {br_name}")
        elif interface.master != br_name:
            logger.error_and_exit(f"Incorrect master set for interface {api_network}")

        logger.info(f"Setting interface {api_network} as unmanaged in NetworkManager")
        self.hostconn.run(f"nmcli device set {api_network} managed no")

    def ensure_not_linked_to_network(self) -> None:
        if not self.hosts_vms:
            return

        intif = self.validate_api_port()
        if not intif:
            logger.info("can't find network API port")
        else:
            logger.info(self.hostconn.run(f"ip link set {intif} nomaster"))
            logger.info(f"Setting interface {intif} as managed in NetworkManager")
            self.hostconn.run(f"nmcli device set {intif} managed yes")

    def validate_api_port(self) -> Optional[str]:
        if self.config.network_api_port == "auto":
            self.config.network_api_port = common.get_auto_port(self.hostconn)

        port = self.config.network_api_port
        logger.info(f'Validating API network port {port}')
        if not self.hostconn.port_exists(port):
            logger.error(f"Can't find API network port {port}")
            return None
        if not self.hostconn.port_has_carrier(port):
            logger.error(f"API network port {port} doesn't have a carrier")
            return None
        return port

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

        try_count = 0
        while True:
            try_count += 1
            states = {node.config.name: node.has_booted() for node in nodes}
            node_names = ', '.join(states.keys())
            logger.info(f"Waiting for nodes ({node_names}) to have booted (try #{try_count})..")
            logger.info(f"Current boot state: {states}")
            if all(has_booted for has_booted in states.values()):
                break
            time.sleep(10)
        logger.info(f"It took {try_count} tries to wait for nodes ({node_names}) to have booted.")

        try_count = 0
        while True:
            try_count += 1
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


def match_to_proper_version_format(version_cluster_config: str) -> str:
    regex_pattern = r'^\d+\.\d+'
    match = re.match(regex_pattern, version_cluster_config)
    logger.info(f"getting version to match with format XX.X using regex {regex_pattern}")
    if not match:
        logger.error_and_exit(f"Invalid match {match}")
    return match.group(0)


class ClusterDeployer:
    def __init__(self, cc: ClustersConfig, ai: AssistedClientAutomation, steps: List[str], secrets_path: str):
        self._client: Optional[K8sClient] = None
        self.steps = steps
        self._cc = cc
        self._ai = ai
        self._secrets_path = secrets_path
        self._bf_iso_path = "/root/iso"
        self._extra_config = ExtraConfigRunner(cc)

        if self.need_external_network():
            self._cc.prepare_external_port()

        lh = host.LocalHost()
        self._local_host = ClusterHost(lh, self.local_host_config(lh.hostname()), cc)
        self._remote_hosts = {bm.name: ClusterHost(host.RemoteHost(bm.name), bm, cc) for bm in self._cc.hosts if bm.name != lh.hostname()}
        self._all_hosts = [self._local_host] + list(self._remote_hosts.values())
        self._futures = {k8s_node.config.name: k8s_node.future for h in self._all_hosts for k8s_node in h._k8s_nodes()}
        self._all_nodes = {k8s_node.config.name: k8s_node for h in self._all_hosts for k8s_node in h._k8s_nodes()}

        self.masters_arch = "x86_64"
        self.is_bf = (x.kind == "bf" for x in self._cc.workers)
        if any(self.is_bf):
            if not all(self.is_bf):
                logger.error_and_exit("Not yet supported to have mixed BF and non-bf workers")
            self.workers_arch = "arm64"
        else:
            self.workers_arch = "x86_64"
        self._validate()

    def local_host_config(self, hostname: str = "localhost") -> HostConfig:
        return next(e for e in self._cc.hosts if e.name == hostname)

    def _all_hosts_with_masters(self) -> Set[ClusterHost]:
        return {ch for ch in self._all_hosts if len(ch.k8s_master_nodes) > 0}

    def _all_hosts_with_workers(self) -> Set[ClusterHost]:
        return {ch for ch in self._all_hosts if len(ch.k8s_worker_nodes) > 0}

    """
    Using Aicli, we will find all the clusters installed on our host included in our configuration file.
      E.g: aicli -U 0.0.0.0:8090 list cluster
    Then delete the cluster, such that we are on a clean slate:
      E.g. aicli -U 0.0.0.0:8090 delete cluster <cluster name>

    Next we want to tear down any VMs we have created. By default the qcow
    images are here: "/home/infracluster_guests_images/"
    We delete these images. virsh will be pointing to this qcow file. You can
    inspect this via: virsh dumpxml --domain <name of VM> | grep "source file"
      E.g. <source file='/home/infracluster_guests_images/infracluster-master-1.qcow2' index='2'/>

    We then delete the VMs using virsh using "virsh destroy" and "virsh undefine" commands.

    By default virsh ships with the "default" network using the virtual bridge "virbr0". DHCP
    entries for the VMs (by mac address) are added to the "default" network. We need to make sure
    to remove them for cleanup.

    Likewise we need to clean up the dnsmasq for the "virbr0" entries in this file:
    "/var/lib/libvirt/dnsmasq/virbr0.status". This will ensure that the virtual bridge interface
    does not have any lingering entries in its database. The "default" virsh network is then
    destroyed and started.

    Then we destroy the libvirt pool created to house our guest images.

    Lastly we unlink the "eno1" interface from the virtual bridge "virtbr0". Currently "eno1" on hosts
    is hardcoded to be the network hosting the API network.
    """

    def teardown(self) -> None:
        cluster_name = self._cc.name
        logger.info(f"Tearing down {cluster_name}")
        self._ai.ensure_cluster_deleted(self._cc.name)

        for h in self._all_hosts:
            h.teardown()

        self._ai.ensure_infraenv_deleted(f"{cluster_name}-x86_64")
        self._ai.ensure_infraenv_deleted(f"{cluster_name}-arm64")

        xml_str = self._local_host.hostconn.run("virsh net-dumpxml default").out
        q = et.fromstring(xml_str)
        removed_macs = []
        names = [x.name for x in self._cc.all_vms()]
        ips = [x.ip for x in self._cc.all_vms()]
        for e in q[-1][0][1:]:
            if e.attrib["name"] in names or e.attrib["ip"] in ips:
                mac = e.attrib["mac"]
                name = e.attrib["name"]
                ip = e.attrib["ip"]
                pre = "virsh net-update default delete ip-dhcp-host"
                cmd = f"{pre} \"<host mac='{mac}' name='{name}' ip='{ip}'/>\" --live --config"
                logger.info(self._local_host.hostconn.run(cmd))
                removed_macs.append(mac)

        # bring back initial dynamic dhcp range.
        self._local_host.bridge.limit_dhcp_range("192.168.122.129", "192.168.122.2")

        fn = "/var/lib/libvirt/dnsmasq/virbr0.status"
        with open(fn) as f:
            contents = f.read()

        if contents:
            j = json.loads(contents)
            names = [x.name for x in self._cc.all_vms()]
            logger.info(f'Cleaning up {fn}')
            logger.info(f'removing hosts with mac in {removed_macs} or name in {names}')
            filtered = []
            for entry in j:
                if entry["mac-address"] in removed_macs:
                    logger.info(f'Removed host with mac {entry["mac-address"]}')
                    continue
                if "hostname" in entry and entry["hostname"] in names:
                    logger.info(f'Removed host with name {entry["hostname"]}')
                    continue
                logger.info(f'Kept entry {entry}')
                filtered.append(entry)

            logger.info(self._local_host.hostconn.run("virsh net-destroy default"))
            with open(fn, "w") as f:
                f.write(json.dumps(filtered, indent=4))
            logger.info(self._local_host.hostconn.run("virsh net-start default"))
            logger.info(self._local_host.hostconn.run("systemctl restart libvirtd"))

        if self.need_api_network():
            for h in self._all_hosts:
                h.ensure_not_linked_to_network()

        if os.path.exists(self._cc.kubeconfig):
            os.remove(self._cc.kubeconfig)

    def _preconfig(self) -> None:
        for e in self._cc.preconfig:
            self._prepost_config(e)

    def _postconfig(self) -> None:
        for e in self._cc.postconfig:
            self._prepost_config(e)

    def _prepost_config(self, to_run: ExtraConfigArgs) -> None:
        if not to_run:
            return
        self._extra_config.run(to_run, self._futures)

    def need_api_network(self) -> bool:
        return len(self._cc.local_vms()) != len(self._cc.all_nodes())

    def need_external_network(self) -> bool:
        vm_bm = [x for x in self._cc.workers if x.kind == "vm" and x.node != "localhost"]
        remote_workers = len(self._cc.workers) - len(self._cc.worker_vms())
        remote_masters = len(self._cc.masters) - len(self._cc.master_vms())
        if "workers" not in self.steps:
            remote_workers = 0
        if "masters" not in self.steps:
            remote_masters = 0
        return remote_masters != 0 or remote_workers != 0 or len(vm_bm) != 0

    def deploy(self) -> None:
        if self._cc.masters:
            if "pre" in self.steps:
                self._preconfig()
            else:
                logger.info("Skipping pre configuration.")

            if self._cc.kind != "microshift":
                if "masters" in self.steps:
                    self.teardown()
                    self.create_cluster()
                    self.create_masters()
                else:
                    logger.info("Skipping master creation.")

                if "workers" in self.steps:
                    if len(self._cc.workers) != 0:
                        self.create_workers()
                    else:
                        logger.info("Skipping worker creation.")
        if self._cc.kind == "microshift":
            version = match_to_proper_version_format(self._cc.version)

            if len(self._cc.masters) == 1:
                microshift.deploy(self._cc.fullConfig["name"], self._cc.masters[0], self._cc.external_port, version)
            else:
                logger.error_and_exit("Masters must be of length one for deploying microshift")

        if "post" in self.steps:
            self._postconfig()
        else:
            logger.info("Skipping post configuration.")

    def _validate(self) -> None:
        if self._cc.is_sno():
            logger.info("Setting up a Single Node OpenShift (SNO) environment")
            if self._cc.masters[0].ip is None:
                logger.error_and_exit("Missing ip on master")

        min_cores = 28
        cc = int(self._local_host.hostconn.run("nproc").out)
        if cc < min_cores:
            logger.error_and_exit(f"Detected {cc} cores on localhost, but need at least {min_cores} cores")
        if self.need_external_network():
            if not self._cc.validate_external_port():
                logger.error_and_exit(f"Invalid external port, config is {self._cc.external_port}")
        else:
            logger.info("Don't need external network so will not set it up")
        if self._cc.kind != "microshift":
            if self.need_api_network() and not self._local_host.validate_api_port():
                logger.error_and_exit(f"Can't find a valid network API port, config is {self._local_host.config.network_api_port}")
            else:
                logger.info(f"Using {self._local_host.config.network_api_port} as network API port")

    def _get_status(self, name: str) -> Optional[str]:
        h = self._ai.get_ai_host(name)
        return h.status if h is not None else None

    def _wait_known_state(self, names_gen: Generator[str, None, None], cb: Callable[[], None] = lambda: None) -> None:
        names = list(names_gen)
        logger.info(f"Waiting for {names} to be in \'known\' state")
        status: Dict[str, Optional[str]] = {n: "" for n in names}
        while not all(v == "known" for v in status.values()):
            new_status: Dict[str, Optional[str]] = {n: self._get_status(n) for n in names}
            if new_status != status:
                logger.info(f"latest status: {new_status}")
                status = new_status
            if any(v == "error" for v in status.values()):
                for e in names:
                    k8s_node = self._all_nodes.get(e)
                    if k8s_node is not None:
                        k8s_node.print_logs()
                logger.error_and_exit("Error encountered in one of the nodes, quitting...")
            cb()
            time.sleep(5)

    def client(self) -> K8sClient:
        if self._client is None:
            self._client = K8sClient(self._cc.kubeconfig)
        return self._client

    def create_cluster(self) -> None:
        cluster_name = self._cc.name
        cfg: Dict[str, Union[str, bool, List[str], List[Dict[str, str]]]] = {}
        cfg["openshift_version"] = self._cc.version
        cfg["cpu_architecture"] = "multi"
        cfg["pull_secret"] = self._secrets_path
        cfg["infraenv"] = "false"

        if not self._cc.is_sno():
            cfg["api_vips"] = [self._cc.api_vip]
            cfg["ingress_vips"] = [self._cc.ingress_vip]

        cfg["vip_dhcp_allocation"] = False
        cfg["additional_ntp_source"] = self._cc.ntp_source
        cfg["base_dns_domain"] = self._cc.base_dns_domain
        cfg["sno"] = self._cc.is_sno()
        if self._cc.proxy:
            cfg["proxy"] = self._cc.proxy
        if self._cc.noproxy:
            cfg["noproxy"] = self._cc.noproxy

        logger.info("Creating cluster")
        logger.info(cfg)
        self._ai.create_cluster(cluster_name, cfg)

    def create_masters(self) -> None:
        cluster_name = self._cc.name
        infra_env = f"{cluster_name}-{self.masters_arch}"
        logger.info(f"Ensuring infraenv {infra_env} exists.")

        cfg = {}
        cfg["cluster"] = cluster_name
        cfg["pull_secret"] = self._secrets_path
        cfg["cpu_architecture"] = self.masters_arch
        cfg["openshift_version"] = self._cc.version
        if self._cc.proxy:
            cfg["proxy"] = self._cc.proxy
        if self._cc.noproxy:
            cfg["noproxy"] = self._cc.noproxy
        self._ai.ensure_infraenv_created(infra_env, cfg)

        hosts_with_masters = self._all_hosts_with_masters()

        # Ensure the virtual bridge is properly configured and
        # configure DHCP entries for all masters on the local virbr.
        for h in hosts_with_masters:
            h.configure_bridge()
            h.configure_master_dhcp_entries(self._local_host.bridge)

        # Start all masters on all hosts.
        executor = ThreadPoolExecutor(max_workers=len(self._cc.masters))
        iso_path = os.getcwd()
        iso_file = os.path.join(iso_path, f"{infra_env}.iso")
        self._ai.download_iso_with_retry(infra_env, iso_path)

        futures = []
        for h in hosts_with_masters:
            futures.extend(h.start_masters(iso_file, infra_env, executor))

        # Wait for masters to have booted.
        for h in hosts_with_masters:
            h.wait_for_masters_boot(("192.168.122.1", "192.168.255.254"))

        def cb() -> None:
            finished = [p for p in futures if p.done()]
            for f in finished:
                result = f.result()
                if result is not None and result.returncode != 0:
                    raise Exception(f"Can't install masters {result}")

        names = (e.name for e in self._cc.masters)
        self._wait_known_state(names, cb)
        self._ai.start_until_success(cluster_name)

        logger.info(f'downloading kubeconfig to {self._cc.kubeconfig}')
        self._ai.download_kubeconfig(self._cc.name, self._cc.kubeconfig)

        self._ai.wait_cluster(cluster_name)

        logger.info('updating /etc/hosts')
        self.update_etc_hosts()

        # Make sure any submitted tasks have completed.
        for p in futures:
            p.result()

        # Connect the masters to the physical network.
        # NOTE: this must happen after the masters are installed by AI
        # to ensure AI doesn't detect other nodes on the network.
        for h in hosts_with_masters:
            h.ensure_linked_to_network()

        logger.info("Setting password to for root to redhat")
        for h in hosts_with_masters:
            for master in h.k8s_master_nodes:
                master.set_password()

    def create_workers(self) -> None:
        logger.info("Setting up workers")
        cluster_name = self._cc.name
        infra_env = f"{cluster_name}-{self.workers_arch}"

        self._ai.allow_add_workers(cluster_name)

        cfg = {}
        cfg["cluster"] = cluster_name
        cfg["pull_secret"] = self._secrets_path
        cfg["cpu_architecture"] = self.workers_arch
        cfg["openshift_version"] = self._cc.version
        if self._cc.proxy:
            cfg["proxy"] = self._cc.proxy
        if self._cc.noproxy:
            cfg["noproxy"] = self._cc.noproxy

        self._ai.ensure_infraenv_created(infra_env, cfg)
        hosts_with_workers = self._all_hosts_with_workers()

        # Ensure the virtual bridge is properly configured and
        # configure DHCP entries for all workers on the local virbr and
        # connect the workers to the physical network.
        #
        # NOTE: linking the network must happen before starting workers because
        # they need to be able to access the DHCP server running on the
        # provisioning node.
        for h in hosts_with_workers:
            h.configure_bridge()
            h.configure_worker_dhcp_entries(self._local_host.bridge)
            h.ensure_linked_to_network()

        executor = ThreadPoolExecutor(max_workers=len(self._cc.workers))

        # Install all hosts that need to run (or be) workers.
        preinstall_futures = [h.preinstall(self._cc.external_port, executor) for h in hosts_with_workers]
        for pf in preinstall_futures:
            logger.info(pf.result())

        # Start all workers on all hosts.
        if not self.is_bf:
            iso_path = os.getcwd()
        else:
            # BF images are NFS mounted from self._bf_iso_path.
            iso_path = self._bf_iso_path

        os.makedirs(self._bf_iso_path, exist_ok=True)
        self._ai.download_iso_with_retry(infra_env, iso_path)
        iso_file = os.path.join(iso_path, f"{infra_env}.iso")
        ssh_priv_key_path = self._get_discovery_ign_ssh_priv_key(infra_env)
        shutil.copyfile(ssh_priv_key_path, os.path.join(self._bf_iso_path, "ssh_priv_key"))

        futures = []
        for h in hosts_with_workers:
            futures.extend(h.start_workers(iso_file, infra_env, executor))

        # Wait for workers to have booted.
        for h in hosts_with_workers:
            h.wait_for_workers_boot(("192.168.122.1", "192.168.255.254"))

        # Rename workers in AI.
        logger.info("renaming workers")
        self._rename_workers(infra_env)

        def cb() -> None:
            finished = [p for p in futures if p.done()]
            for f in finished:
                result = f.result()
                if result is not None and result.returncode != 0:
                    raise Exception(f"Can't install workers {result}")

        self._wait_known_state((e.name for e in self._cc.workers), cb)

        logger.info("starting infra env")
        self._ai.start_infraenv(infra_env)
        logger.info("waiting for workers to be ready")
        self.wait_for_workers()

        logger.info("Setting password to for root to redhat")
        for h in hosts_with_workers:
            for worker in h.k8s_worker_nodes:
                worker.set_password()

        # Make sure any submitted tasks have completed.
        for p in futures:
            p.result()

    def _rename_workers(self, infra_env_name: str) -> None:
        logger.info("Waiting for connectivity to all workers")
        hosts = []
        workers = []
        for bm in self._all_hosts:
            for k8s_node in bm.k8s_worker_nodes:
                rh = host.RemoteHost(k8s_node.ip())
                rh.ssh_connect("core")
                hosts.append(rh)
                workers.append(k8s_node)
        subnet = "192.168.122.0/24"
        logger.info(f"Connectivity established to all workers; checking that they have an IP in {subnet}")

        def addresses(h: host.Host) -> List[str]:
            ret = []
            for e in h.ipa():
                if "addr_info" not in e:
                    continue
                for k in e["addr_info"]:
                    ret.append(k["local"])
            return ret

        def addr_ok(a: str) -> bool:
            return common.ip_in_subnet(a, subnet)

        any_worker_bad = False
        for w, h in zip(workers, hosts):
            if all(not addr_ok(a) for a in addresses(h)):
                logger.error(f"Worker {w.config.name} doesn't have an IP in {subnet}.")
                any_worker_bad = True

        if any_worker_bad:
            sys.exit(-1)

        logger.info("Connectivity established to all workers, renaming them in Assited installer")
        logger.info(f"looking for workers with ip {[w.ip() for w in workers]}")
        while True:
            renamed = self._try_rename_workers(infra_env_name)
            expected = len(workers)
            if renamed == expected:
                logger.info(f"Found and renamed {renamed} workers")
                break
            if renamed:
                logger.info(f"Found and renamed {renamed} workers, but waiting for {expected}, retrying")
                time.sleep(5)

    def _try_rename_workers(self, infra_env_name: str) -> int:
        infra_env_id = self._ai.get_infra_env_id(infra_env_name)
        renamed = 0

        for bm in self._all_hosts:
            for k8s_node in bm.k8s_worker_nodes:
                for h in filter(lambda x: x["infra_env_id"] == infra_env_id, self._ai.list_hosts()):
                    if "inventory" not in h:
                        continue
                    nics = json.loads(h["inventory"]).get("interfaces")
                    addresses: List[str] = sum((nic["ipv4_addresses"] for nic in nics), [])
                    stripped_addresses = [a.split("/")[0] for a in addresses]

                    if k8s_node.ip() in stripped_addresses:
                        self._ai.update_host(h["id"], {"name": k8s_node.config.name})
                        logger.info(f"renamed {k8s_node.config.name}")
                        renamed += 1
        return renamed

    def _get_discovery_ign_ssh_priv_key(self, infra_env_name: str) -> str:
        self._ai.download_discovery_ignition(infra_env_name, "/tmp")

        # In a provisioning system where there could be multiple keys, it is not guaranteed that
        # AI will use id_rsa. Thus we need to properly extract the key from the discovery ignition.
        ssh_priv_key = "/root/.ssh/id_rsa"
        with open(os.path.join("/tmp", f"discovery.ign.{infra_env_name}")) as f:
            j = json.load(f)
        ssh_pub_key = j["passwd"]["users"][0]["sshAuthorizedKeys"][0]
        # It seems that if you have both rsa and ed25519, AI will prefer to use ed25519.
        logger.info(f"The SSH key that the discovery ISO will use is: {ssh_pub_key}")
        for file, key, priv_key in common.iterate_ssh_keys():
            if key.split()[0] == ssh_pub_key.split()[0]:
                logger.info(f"Found matching public key at {file}")
                ssh_priv_key = priv_key
                logger.info(f"Found matching private key at {ssh_priv_key}")
                break

        return ssh_priv_key

    def update_etc_hosts(self) -> None:
        cluster_name = self._cc.name
        api_name = f"api.{cluster_name}.redhat.com"
        api_vip = self._ai.get_ai_cluster_info(cluster_name).api_vip

        hosts = Hosts()
        hosts.remove_all_matching(name=api_name)
        hosts.remove_all_matching(address=api_vip)
        hosts.add([HostsEntry(entry_type='ipv4', address=api_vip, names=[api_name])])
        hosts.write()

        # libvirtd also runs dnsmasq, and dnsmasq reads /etc/hosts.
        # For that reason, restart libvirtd to re-read the changes.
        lh = host.LocalHost()
        lh.run("systemctl restart libvirtd")

    def wait_for_workers(self) -> None:
        logger.info(f'waiting for {len(self._cc.workers)} workers')
        lh = host.LocalHost()
        bf_workers = [x for x in self._cc.workers if x.kind == "bf"]
        connections: Dict[str, host.Host] = {}
        while True:
            workers = [w.name for w in self._cc.workers]
            if all(self.client().is_ready(w) for w in workers):
                break

            self.client().approve_csr()

            if len(connections) != len(bf_workers):
                for e in filter(lambda x: x.name not in connections, bf_workers):
                    ai_ip = self._ai.get_ai_ip(e.name)
                    if ai_ip is None:
                        continue
                    h = host.Host(ai_ip)
                    h.ssh_connect("core")
                    logger.info(f'connected to {e.name}, setting user:pw')
                    h.run("echo root:redhat | sudo chpasswd")
                    connections[e.name] = h

            # Workaround: Time is not set and consequently HTTPS doesn't work
            for w in filter(lambda x: x.kind == "bf", self._cc.workers):
                if w.name not in connections:
                    continue
                h = connections[w.name]
                host.sync_time(lh, h)

                # Workaround: images might become corrupt for an unknown reason. In that case, remove it to allow retries
                out = h.run("sudo podman images", logging.DEBUG).out
                reg = re.search(r".*Top layer (\w+) of image (\w+) not found in layer tree. The storage may be corrupted, consider running", out)
                if reg:
                    logger.warning(f'Removing corrupt image from worker {w.name}')
                    logger.warning(h.run(f"sudo podman rmi {reg.group(2)}"))
                try:
                    out = h.run("sudo podman images --format json", logging.DEBUG).out
                    podman_images = json.loads(out)
                    for image in podman_images:
                        inspect_output = h.run(f"sudo podman image inspect {image['Id']}", logging.DEBUG).out
                        if "A storage corruption might have occurred" in inspect_output:
                            logger.warning("Corrupt image found")
                            h.run(f"sudo podman rmi {image['id']}")
                except Exception as e:
                    logger.info(e)

            time.sleep(30)
