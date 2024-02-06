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
import re
import socket
import glob
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
from dataclasses import dataclass
from extraConfigRunner import ExtraConfigRunner
import argparse


def setup_dhcp_entry(h: host.Host, cfg: NodeConfig) -> None:
    if cfg.ip is None:
        logger.error(f"Missing IP for node {cfg.name}")
        sys.exit(-1)
    ip = cfg.ip
    mac = cfg.mac
    name = cfg.name
    # If adding a worker node fails, one might want to retry w/o tearing down
    # the whole cluster. In that case, the DHCP entry might already be present,
    # with wrong mac -> remove it

    cmd = "virsh net-dumpxml default"
    ret = h.run_or_die(cmd)
    if f"'{name}'" in ret.out:
        logger.info(f"{name} already configured as static DHCP entry - removing before adding back with proper configuration")
        host_xml = f"<host name='{name}'/>"
        cmd = f"virsh net-update default delete ip-dhcp-host \"{host_xml}\" --live --config"
        h.run_or_die(cmd)

    cmd = "virsh net-dhcp-leases default"
    ret = h.run(cmd)
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
    h.run_or_die(cmd)


def setup_vm(h: host.Host, cfg: NodeConfig, iso_or_image_path: str) -> host.Result:
    name = cfg.name
    mac = cfg.mac
    disk_size_gb = cfg.disk_size
    if iso_or_image_path.endswith(".iso"):
        options = "-o preallocation="
        if cfg.is_preallocated():
            options += "full"
        else:
            options += "off"

        os.makedirs(os.path.dirname(cfg.image_path), exist_ok=True)
        logger.info(f"creating image for VM {name}")
        h.run_or_die(f'qemu-img create -f qcow2 {options} {cfg.image_path} {disk_size_gb}G')

        cdrom_line = f"--cdrom {iso_or_image_path}"
        append = "--wait=-1"
    else:
        cdrom_line = ""
        append = "--noautoconsole"

    if h.is_localhost():
        network = "network=default"
    else:
        network = "bridge=virbr0"
    cmd = f"""
    virt-install
        --connect qemu:///system
        -n {name}
        -r {cfg.ram}
        --cpu host
        --vcpus {cfg.cpu}
        --os-variant={cfg.os_variant}
        --import
        --network {network},mac={mac}
        --events on_reboot=restart
        {cdrom_line}
        --disk path={cfg.image_path}
        {append}
    """

    logger.info(f"Starting VM {name}")
    ret = h.run(cmd)
    if ret.returncode != 0:
        logger.info(f"Finished starting VM {name}, cmd = {cmd}, ret = {ret}")
    else:
        logger.info(f"Finished starting VM {name} without any errors")
    return ret


def setup_all_vms(h: host.Host, vms: List[NodeConfig], iso_path: str) -> List[Future[host.Result]]:
    if not vms:
        return []

    hostname = h.hostname()
    logger.debug(f"Setting up vms on {hostname}")

    executor = ThreadPoolExecutor(max_workers=len(vms))
    futures = []
    for e in vms:
        futures.append(executor.submit(setup_vm, h, e, iso_path))
        while not h.vm_is_running(e.name) and not futures[-1].done():
            time.sleep(1)

    return futures


def ensure_bridge_is_started(h: host.Host, api_network: str, bridge_xml: str) -> None:
    cmd = "virsh net-destroy default"
    h.run(cmd)  # ignore return code - it might fail if net was not started

    cmd = "virsh net-undefine default"
    ret = h.run(cmd)
    if ret.returncode != 0 and "Network not found" not in ret.err:
        logger.error(ret)
        sys.exit(-1)

    # Fix cases where virsh net-start fails with error "... interface virbr0: File exists"
    cmd = "ip link delete virbr0"
    h.run(cmd)  # ignore return code - it might fail if virbr did not exist

    cmd = f"virsh net-define {bridge_xml}"
    h.run_or_die(cmd)

    # set interface down before starting bridge as otherwise bridge start might fail if interface
    # already got an IP address in same network as bridge
    h.run(f"ip link set {api_network} down")

    cmd = "virsh net-start default"
    h.run_or_die(cmd)

    h.run(f"ip link set {api_network} up")


def limit_dhcp_range(h: host.Host, old_range: str, new_range: str) -> None:
    # restrict dynamic dhcp range: we use static dhcp ip addresses; however, those addresses might have been used
    # through the dynamic dhcp by any systems such as systems ready to be installed.
    cmd = "virsh net-dumpxml default"
    ret = h.run(cmd)
    if f"range start='{old_range}'" in ret.out:
        host_xml = f"<range start='{old_range}' end='192.168.122.254'/>"
        cmd = f"virsh net-update default delete ip-dhcp-range \"{host_xml}\" --live --config"
        r = h.run(cmd)
        logger.debug(r.err if r.err else r.out)

        host_xml = f"<range start='{new_range}' end='192.168.122.254'/>"
        cmd = f"virsh net-update default add ip-dhcp-range \"{host_xml}\" --live --config"
        r = h.run(cmd)
        logger.debug(r.err if r.err else r.out)


def network_xml(ip: str, dhcp_range: Optional[Tuple[str, str]] = None) -> str:
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
</network>
  """


def configure_bridge(h: host.Host, api_network: str) -> None:
    hostname = h.hostname()
    cmd = "systemctl enable libvirtd"
    h.run_or_die(cmd)
    cmd = "systemctl start libvirtd"
    h.run_or_die(cmd)

    # stp must be disabled or it might conflict with default configuration of some physical switches
    # 'bridge' section of network 'default' can't be updated => destroy and recreate
    # check that default exists and contains stp=off
    cmd = "virsh net-dumpxml default"
    ret = h.run(cmd)

    if "stp='off'" not in ret.out:
        logger.info("Destoying and recreating bridge")
        logger.info(f"creating default-net.xml on {hostname}")
        if hostname == "localhost":
            contents = network_xml('192.168.122.1', ('192.168.122.129', '192.168.122.254'))
        else:
            contents = network_xml('192.168.123.250')

        bridge_xml = os.path.join("/tmp", 'vir_bridge.xml')
        h.write(bridge_xml, contents)
        # Not sure why/whether this is needed. But we saw failures w/o it.
        # Without this, net-undefine within ensure_bridge_is_started fails as libvirtd fails to restart
        # We need to investigate how to remove the sleep to speed up
        time.sleep(5)
        ensure_bridge_is_started(h, api_network, bridge_xml)

        limit_dhcp_range(h, "192.168.122.2", "192.168.122.129")

        cmd = "systemctl restart libvirtd"
        h.run_or_die(cmd)

        # Not sure why/whether this is needed. But we saw failures w/o it.
        # We need to investigate how to remove the sleep to speed up
        time.sleep(5)


class ClusterDeployer:
    def __init__(self, cc: ClustersConfig, ai: AssistedClientAutomation, steps: List[str], secrets_path: str):
        self._client: Optional[K8sClient] = None
        self.steps = steps
        self._cc = cc
        self._ai = ai
        self._secrets_path = secrets_path
        self._iso_path = "/root/iso"
        os.makedirs(self._iso_path, exist_ok=True)
        self._extra_config = ExtraConfigRunner(cc)

        def empty() -> Future[None]:
            f: Future[None] = Future()
            f.set_result(None)
            return f

        self._futures = {e.name: empty() for e in self._cc.all_nodes()}

    def local_host_config(self, hostname: str = "localhost") -> HostConfig:
        return next(e for e in self._cc.hosts if e.name == hostname)

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
        lh = host.LocalHost()
        for m in self._cc.all_vms():
            h = host.Host(m.node)
            if m.node != "localhost":
                host_config = self.local_host_config(m.node)
                h.ssh_connect(host_config.username, host_config.password)
                if not host_config.pre_installed:
                    h.need_sudo()

            # remove the image only if it really exists
            image_path = m.image_path
            h.remove(image_path.replace(".qcow2", ".img"))
            h.remove(image_path)

            # destroy the VM only if it really exists
            if h.run(f"virsh desc {m.name}").returncode == 0:
                r = h.run(f"virsh destroy {m.name}")
                logger.info(r.err if r.err else r.out.strip())
                r = h.run(f"virsh undefine {m.name}")
                logger.info(r.err if r.err else r.out.strip())

        self._ai.ensure_infraenv_deleted(f"{cluster_name}-x86")
        self._ai.ensure_infraenv_deleted(f"{cluster_name}-arm")

        xml_str = lh.run("virsh net-dumpxml default").out
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
                logger.info(lh.run(cmd))
                removed_macs.append(mac)

        # bring back initial dynamic dhcp range.
        limit_dhcp_range(lh, "192.168.122.129", "192.168.122.2")

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

            logger.info(lh.run("virsh net-destroy default"))
            with open(fn, "w") as f:
                f.write(json.dumps(filtered, indent=4))
            logger.info(lh.run("virsh net-start default"))
            logger.info(lh.run("systemctl restart libvirtd"))

        if self.need_api_network():
            for hc in self._cc.hosts:
                h = host.Host(hc.name)
                if hc.name != "localhost":
                    host_config = self.local_host_config(hc.name)
                    h.ssh_connect(host_config.username, host_config.password)
                    if not host_config.is_preinstalled():
                        h.need_sudo()

                intif = self._validate_api_port(h)
                if not intif:
                    logger.info("can't find network API port")
                else:
                    logger.info(h.run(f"ip link set {intif} nomaster"))
                    logger.info(f"Setting interface {intif} as managed in NetworkManager")
                    lh.run(f"nmcli device set {intif} managed yes")

        if os.path.exists(self._cc.kubeconfig):
            os.remove(self._cc.kubeconfig)

    def _validate_api_port(self, lh: host.Host) -> Optional[str]:
        host_config = self.local_host_config(lh.hostname())
        if host_config.network_api_port == "auto":
            interfaces = common.carrier_no_addr(lh)
            if len(interfaces) == 0:
                return None
            else:
                host_config.network_api_port = interfaces[0].ifname

        port = host_config.network_api_port
        logger.info(f'Validating API network port {port}')
        if not lh.port_exists(port):
            logger.error(f"Can't find API network port {port}")
            return None
        if not lh.port_has_carrier(port):
            logger.error(f"API network port {port} doesn't have a carrier")
            return None
        return port

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

    def ensure_linked_to_bridge(self, lh: host.Host) -> None:
        if not self.need_api_network():
            logger.info("Only running local VMs (virbr0 not connected to externally)")
            return

        host_config = self.local_host_config(lh.hostname())
        api_network = host_config.network_api_port

        logger.info(f"link {api_network} to virbr0")

        interface = common.find_port(lh, api_network)
        if not interface:
            logger.info(f"Missing API network interface {api_network}")
            sys.exit(-1)

        bridge = "virbr0"

        # Need to restart libvirtd after modify the config file, which will be
        # done in configure_bridge().
        cmd = "sed -e 's/#\\(user\\|group\\) = \".*\"$/\\1 = \"root\"/' -i /etc/libvirt/qemu.conf"
        lh.run(cmd)
        configure_bridge(lh, api_network)

        if interface.master is None:
            logger.info(f"No master set for interface {api_network}, setting it to {bridge}")
            lh.run(f"ip link set {api_network} master {bridge}")
        elif interface.master != bridge:
            logger.info(f"Incorrect master set for interface {api_network}")
            sys.exit(-1)

        logger.info(f"Setting interface {api_network} as unmanaged in NetworkManager")
        lh.run(f"nmcli device set {api_network} managed no")

    def need_external_network(self) -> bool:
        vm_bm = list(x for x in self._cc.workers if x.kind == "vm" and x.node != "localhost")
        remote_workers = len(self._cc.workers) - len(self._cc.worker_vms())
        remote_masters = len(self._cc.masters) - len(self._cc.master_vms())
        if "workers" not in self.steps:
            remote_workers = 0
        if "masters" not in self.steps:
            remote_masters = 0
        return remote_masters != 0 or remote_workers != 0 or len(vm_bm) != 0

    def deploy(self) -> None:
        self._validate()

        if self._cc.masters:
            if "pre" in self.steps:
                self._preconfig()
            else:
                logger.info("Skipping pre configuration.")

            lh = host.LocalHost()
            self.ensure_linked_to_bridge(lh)

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

        if "post" in self.steps:
            self._postconfig()
        else:
            logger.info("Skipping post configuration.")

    def _validate(self) -> None:
        if self._cc.is_sno():
            logger.info("Setting up a Single Node OpenShift (SNO) environment")
            if self._cc.masters[0].ip is None:
                logger.error("Missing ip on master")
                sys.exit(-1)

        lh = host.LocalHost()
        min_cores = 28
        cc = int(lh.run("nproc").out)
        if cc < min_cores:
            logger.info(f"Detected {cc} cores on localhost, but need at least {min_cores} cores")
            sys.exit(-1)
        if self.need_external_network():
            self._cc.prepare_external_port()
            if not self._cc.validate_external_port():
                logger.error(f"Invalid external port, config is {self._cc.external_port}")
                sys.exit(-1)
        else:
            logger.info("Don't need external network so will not set it up")
        host_config = self.local_host_config(lh.hostname())
        if self.need_api_network() and not self._validate_api_port(lh):
            logger.info(f"Can't find a valid network API port, config is {host_config.network_api_port}")
            sys.exit(-1)
        else:
            logger.info(f"Using {host_config.network_api_port} as network API port")

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
        for e in self._cc.masters:
            self._futures[e.name].result()
        cluster_name = self._cc.name
        infra_env = f"{cluster_name}-x86"
        logger.info(f"Ensuring infraenv {infra_env} exists.")

        cfg = {}
        cfg["cluster"] = cluster_name
        cfg["pull_secret"] = self._secrets_path
        cfg["cpu_architecture"] = "x86_64"
        cfg["openshift_version"] = self._cc.version
        if self._cc.proxy:
            cfg["proxy"] = self._cc.proxy
        if self._cc.noproxy:
            cfg["noproxy"] = self._cc.noproxy
        self._ai.ensure_infraenv_created(infra_env, cfg)
        self._ai.download_iso_with_retry(infra_env)

        lh = host.LocalHost()
        # TODO: clean this up. Currently just skipping this

        # since self.local_host_config() is not present if no local vms
        if self._cc.local_vms():
            for e in self._cc.masters:
                setup_dhcp_entry(lh, e)
            futures = setup_all_vms(lh, self._cc.masters, os.path.join(os.getcwd(), f"{infra_env}.iso"))
        else:
            self._create_physical_x86_nodes(self._cc.masters)
            futures = []

        def cb() -> None:
            finished = [p for p in futures if p.done()]
            if finished:
                raise Exception(f"Can't install VMs {finished[0].result()}")

        names = (e.name for e in self._cc.masters)
        self._wait_known_state(names, cb)
        self._ai.start_until_success(cluster_name)

        logger.info(f'downloading kubeconfig to {self._cc.kubeconfig}')
        self._ai.download_kubeconfig(self._cc.name, self._cc.kubeconfig)

        self._ai.wait_cluster(cluster_name)

        logger.info('updating /etc/hosts')
        self.update_etc_hosts()

        for p in futures:
            p.result()
        self.ensure_linked_to_bridge(lh)
        for e in self._cc.masters:
            self._set_password(e.name)
        self.update_etc_hosts()

    def _print_logs(self, name: str) -> None:
        ip = self._ai.get_ai_ip(name)
        if ip is None:
            return
        rh = host.RemoteHost(ip)
        logger.info(f"Gathering logs from {name}")
        logger.info(rh.run("sudo journalctl TAG=agent --no-pager").out)

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
                    self._print_logs(e)
                logger.info("Error encountered in one of the nodes, quitting...")
                sys.exit(-1)
            cb()
            time.sleep(5)

    def _verify_package_is_installed(self, worker: NodeConfig, package: str) -> bool:
        ai_ip = self._ai.get_ai_ip(worker.name)
        if ai_ip is None:
            logger.error(f"Failed to get ip for worker with name {worker.name}")
            sys.exit(-1)
        rh = host.RemoteHost(ai_ip)
        rh.ssh_connect("core")
        ret = rh.run(f"rpm -qa | grep {package}")
        return not ret.returncode

    def _perform_worker_health_check(self, workers: List[NodeConfig]) -> None:
        for w in workers:
            err_str = "Required rpm 'kernel-modules-extra' is not installed"
            assert self._verify_package_is_installed(w, "kernel-modules-extra"), err_str

    def create_workers(self) -> None:
        for e in self._cc.workers:
            self._futures[e.name].result()
        is_bf = (x.kind == "bf" for x in self._cc.workers)

        if any(is_bf):
            if not all(is_bf):
                logger.info("Not yet supported to have mixed BF and non-bf workers")
            else:
                self._create_bf_workers()
        else:
            self._create_x86_workers()

        logger.info("Setting password to for root to redhat")
        for w in self._cc.workers:
            self._set_password(w.name)

        self._perform_worker_health_check(self._cc.workers)

    def _set_password(self, node_name: str) -> None:
        ai_ip = self._ai.get_ai_ip(node_name)
        assert ai_ip is not None
        rh = host.RemoteHost(ai_ip)
        rh.ssh_connect("core")
        rh.run("echo root:redhat | sudo chpasswd")

    def _create_physical_x86_nodes(self, nodes: List[NodeConfig]) -> None:
        def boot_helper(worker: NodeConfig, iso: str) -> None:
            return self.boot_iso_x86(worker, iso)

        executor = ThreadPoolExecutor(max_workers=len(nodes))
        futures = []

        nodes = list(x for x in nodes if x.kind == "physical")
        cluster_name = self._cc.name
        infra_env_name = f"{cluster_name}-x86"
        for h in nodes:
            futures.append(executor.submit(boot_helper, h, f"{infra_env_name}.iso"))

        for f in futures:
            logger.info(f.result())

        for w in nodes:
            w.ip = socket.gethostbyname(w.node)

    def _create_vm_x86_workers(self) -> None:
        cluster_name = self._cc.name
        infra_env = f"{cluster_name}-x86"
        vm = self._cc.local_worker_vms()
        logger.info(infra_env)
        lh = host.LocalHost()
        # TODO: clean this up. Currently just skipping this
        # since self.local_host_config() is not present if no local vms
        if self._cc.local_worker_vms():
            for e in vm:
                setup_dhcp_entry(lh, e)
            _ = setup_all_vms(lh, vm, os.path.join(os.getcwd(), f"{infra_env}.iso"))
        self._wait_known_state(e.name for e in vm)

    def _create_remote_vm_x86_workers(self) -> None:
        def boot_helper(worker: NodeConfig, iso: str) -> None:
            return self.boot_iso_x86(worker, iso)

        logger.debug("Setting up vm x86 workers on remote hosts")
        cluster_name = self._cc.name
        infra_env = f"{cluster_name}-x86"
        executor = ThreadPoolExecutor(max_workers=len(self._cc.workers))
        futures = []

        bm_hostnames = set()
        bms: List[NodeConfig] = []
        for x in self._cc.workers:
            if x.node not in bm_hostnames and x.kind == "vm" and x.node != 'localhost':
                bms.append(x)
                bm_hostnames.add(x.node)
        for bm in bms:
            rh = host.RemoteHost(bm.node)
            host_config = self.local_host_config(bm.node)
            if not host_config.is_preinstalled():
                coreosBuilder.ensure_fcos_exists(os.path.join(os.getcwd(), "fedora-coreos.iso"))
                break

        # If bm is not pre-installed, boot an iso with prepoer packages installed
        # Remember also that we'll need sudo access
        # If bm was pre-installed  (e.g. by beaker), install the necessary packages
        for bm in bms:
            rh = host.RemoteHost(bm.node)
            host_config = self.local_host_config(bm.node)
            if not host_config.is_preinstalled():
                logger.debug(f"Setting up Host {bm.node} to host vms")
                iso = "fedora-coreos.iso"
                futures.append(executor.submit(boot_helper, bm, iso))
                rh.need_sudo()
            else:
                rh.ssh_connect(host_config.username, host_config.password)
                cmd = "yum -y install libvirt qemu-img qemu-kvm virt-install"
                rh.run(cmd)

        for f in futures:
            logger.debug(f.result())

        lh = host.LocalHost()
        vms = []
        for bm in bms:
            rh = host.RemoteHost(bm.node)
            logger.debug(f"Setting up vms on {bm.node}")
            host_config = self.local_host_config(bm.node)
            rh.ssh_connect(host_config.username, host_config.password)

            # TODO validate api port on rh
            self.ensure_linked_to_bridge(rh)

            image_path = os.path.dirname(bm.image_path)
            rh.run(f"mkdir -p {image_path}")
            rh.run(f"chmod a+rw {image_path}")
            iso_src = os.path.join(os.getcwd(), f"{infra_env}.iso")
            iso_path = os.path.join(image_path, f"{infra_env}.iso")
            logger.info(f"Copying {iso_src} to {rh.hostname()}:/{iso_path}")
            rh.copy_to(iso_src, iso_path)
            logger.debug(f"iso_path is now {iso_path} for {rh.hostname()}")

            vm = list(x for x in self._cc.workers if x.kind == "vm" and x.node == bm.node)
            for e in vm:
                setup_dhcp_entry(lh, e)

            logger.debug(f"Starting {len(vm)} VMs on {bm.node}")
            setup_all_vms(rh, vm, iso_path)
            vms.extend(vm)
        self._wait_known_state(e.name for e in vms)

    def _create_x86_workers(self) -> None:
        logger.info("Setting up x86 workers")
        cluster_name = self._cc.name
        infra_env_name = f"{cluster_name}-x86"

        self._ai.allow_add_workers(cluster_name)

        cfg = {}
        cfg["cluster"] = cluster_name
        cfg["pull_secret"] = self._secrets_path
        cfg["cpu_architecture"] = "x86_64"
        cfg["openshift_version"] = self._cc.version
        if self._cc.proxy:
            cfg["proxy"] = self._cc.proxy
        if self._cc.noproxy:
            cfg["noproxy"] = self._cc.noproxy

        self._ai.ensure_infraenv_created(infra_env_name, cfg)

        os.makedirs(self._iso_path, exist_ok=True)

        file_path = os.path.join(os.getcwd(), f"{infra_env_name}.iso")
        if os.path.isfile(file_path):
            logger.info(f"\tiso for {infra_env_name} was already downloaded to {file_path}")
        else:
            self._ai.download_iso_with_retry(infra_env_name)

        self._create_physical_x86_nodes(self._cc.workers)
        self._create_vm_x86_workers()
        self._create_remote_vm_x86_workers()

        logger.info("renaming workers")
        self._rename_workers(infra_env_name)
        self._wait_known_state(e.name for e in self._cc.workers)
        logger.info("starting infra env")
        self._ai.start_infraenv(infra_env_name)
        logger.info("waiting for workers to be ready")
        self.wait_for_workers()

    def _rename_workers(self, infra_env_name: str) -> None:
        logger.info("Waiting for connectivity to all workers")
        hosts = []
        for w in self._cc.workers:
            if w.ip is None:
                logger.error(f"Missing ip for worker {w.name}")
                sys.exit(-1)
            rh = host.RemoteHost(w.ip)
            rh.ssh_connect("core")
            hosts.append(rh)
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
        for w, h in zip(self._cc.workers, hosts):
            if all(not addr_ok(a) for a in addresses(h)):
                logger.info(f"Worker {w.name} doesn't have an IP in {subnet}.")
                any_worker_bad = True

        if any_worker_bad:
            sys.exit(-1)

        logger.info("Connectivity established to all workers, renaming them in Assited installer")
        logger.info(f"looking for workers with ip {[w.ip for w in self._cc.workers]}")
        while True:
            renamed = self._try_rename_workers(infra_env_name)
            expected = len(self._cc.workers)
            if renamed == expected:
                logger.info(f"Found and renamed {renamed} workers")
                break
            if renamed:
                logger.info(f"Found and renamed {renamed} workers, but waiting for {expected}, retrying")
                time.sleep(5)

    def _try_rename_workers(self, infra_env_name: str) -> int:
        infra_env_id = self._ai.get_infra_env_id(infra_env_name)
        renamed = 0

        for w in self._cc.workers:
            for h in filter(lambda x: x["infra_env_id"] == infra_env_id, self._ai.list_hosts()):
                if "inventory" not in h:
                    continue
                nics = json.loads(h["inventory"]).get("interfaces")
                addresses: List[str] = sum((nic["ipv4_addresses"] for nic in nics), [])
                stripped_addresses = list(a.split("/")[0] for a in addresses)

                if w.ip in stripped_addresses:
                    self._ai.update_host(h["id"], {"name": w.name})
                    logger.info(f"renamed {w.name}")
                    renamed += 1
        return renamed

    def boot_iso_x86(self, worker: NodeConfig, iso: str) -> None:
        host_name = worker.node
        logger.info(f"trying to boot {host_name} using {iso}")

        lh = host.LocalHost()
        nfs = NFS(lh, self._cc.external_port)

        bmc = host.bmc_from_host_name_or_ip(worker.node, worker.bmc_ip, worker.bmc_user, worker.bmc_password)
        h = host.HostWithBF2(host_name, bmc)

        iso = nfs.host_file(os.path.join(os.getcwd(), iso))
        h.boot_iso_redfish(iso)
        h.ssh_connect("core")
        logger.info("connected")
        logger.info(h.run("hostname"))

    def _create_bf_workers(self) -> None:
        cluster_name = self._cc.name
        infra_env_name = f"{cluster_name}-arm"

        self._ai.allow_add_workers(cluster_name)

        cfg = {}
        cfg["cluster"] = cluster_name
        cfg["pull_secret"] = self._secrets_path
        cfg["cpu_architecture"] = "arm64"
        cfg["openshift_version"] = self._cc.version
        if self._cc.proxy:
            cfg["proxy"] = self._cc.proxy
        if self._cc.noproxy:
            cfg["noproxy"] = self._cc.noproxy

        self._ai.ensure_infraenv_created(infra_env_name, cfg)

        self._download_iso(infra_env_name, self._iso_path)

        ssh_priv_key_path = self._get_discovery_ign_ssh_priv_key(infra_env_name)

        coreosBuilder.ensure_fcos_exists()
        shutil.copyfile(ssh_priv_key_path, os.path.join(self._iso_path, "ssh_priv_key"))

        def boot_iso_bf_helper(worker: NodeConfig, iso: str) -> str:
            return self.boot_iso_bf(worker, iso)

        executor = ThreadPoolExecutor(max_workers=len(self._cc.workers))
        futures = []
        for h in self._cc.workers:
            f = executor.submit(boot_iso_bf_helper, h, f"{infra_env_name}.iso")
            futures.append(f)

        for h, f in zip(self._cc.workers, futures):
            h.ip = f.result()
            if h.ip is None:
                logger.info(f"Couldn't find ip of worker {h.name}")
                sys.exit(-1)

        self._rename_workers(infra_env_name)
        self._wait_known_state(e.name for e in self._cc.workers)
        self._ai.start_infraenv(infra_env_name)
        self.wait_for_workers()

    def _download_iso(self, infra_env_name: str, iso_path: str) -> None:
        logger.info(f"Download iso from {infra_env_name} to {iso_path}, will retry until success")
        while True:
            try:
                self._ai.download_iso(infra_env_name, iso_path)
                logger.info(f"iso for {infra_env_name} downloaded to {iso_path}")
                break
            except Exception:
                time.sleep(5)

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
        for file in glob.glob("/root/.ssh/*.pub"):
            with open(file, 'r') as f:
                key = " ".join(f.read().split(" ")[:-1])
                if key.split()[0] == ssh_pub_key.split()[0]:
                    logger.info(f"Found matching public key at {file}")
                    ssh_priv_key = os.path.splitext(file)[0]
                    logger.info(f"Found matching private key at {ssh_priv_key}")
        return ssh_priv_key

    def update_etc_hosts(self) -> None:
        cluster_name = self._cc.name
        api_name = f"api.{cluster_name}.redhat.com"
        api_vip = self._ai.get_ai_cluster_info(cluster_name).api_vip

        hosts = Hosts()
        hosts.remove_all_matching(name=api_name)
        hosts.add([HostsEntry(entry_type='ipv4', address=api_vip, names=[api_name])])
        hosts.write()

        # libvirtd also runs dnsmasq, and dnsmasq reads /etc/hosts.
        # For that reason, restart libvirtd to re-read the changes.
        lh = host.LocalHost()
        lh.run("systemctl restart libvirtd")

    def boot_iso_bf(self, worker: NodeConfig, iso: str) -> str:
        lh = host.LocalHost()
        nfs = NFS(lh, self._cc.external_port)

        host_name = worker.node
        logger.info(f"Preparing BF on host {host_name}")
        bmc = host.bmc_from_host_name_or_ip(worker.node, worker.bmc_ip, worker.bmc_user, worker.bmc_password)
        h = host.HostWithBF2(host_name, bmc)
        skip_boot = False
        if h.ping():
            try:
                h.ssh_connect("core")
                skip_boot = h.running_fcos()
            except paramiko.ssh_exception.AuthenticationException:
                logger.info("Authentication failed, will not be able to skip boot")

        if skip_boot:
            logger.info(f"Skipping booting {host_name}, already booted with FCOS")
        else:
            nfs_file = nfs.host_file("/root/iso/fedora-coreos.iso")
            h.boot_iso_redfish(nfs_file)
            time.sleep(10)
            h.ssh_connect("core")

        if not h.running_fcos():
            logger.error("Expected FCOS after booting host {host_name} but booted something else")
            sys.exit(-1)

        nfs_iso = nfs.host_file(f"/root/iso/{iso}")
        nfs_key = nfs.host_file("/root/iso/ssh_priv_key")
        output = h.bf_pxeboot(nfs_iso, nfs_key)
        logger.debug(output)
        if output.returncode:
            logger.info(f"Failed to run pxeboot on bf {host_name}")
            sys.exit(-1)
        else:
            logger.info(f"succesfully ran pxeboot on bf {host_name}")

        # ip is printed as the last thing when bf is pxeboot'ed
        bf_ip = output.out.strip().split("\n")[-1].strip()
        h.connect_to_bf(bf_ip)
        tries = 3
        bf_interfaces = ["enp3s0f0", "enp3s0f0np0"]
        logger.info(f'Will try {tries} times to get an IP on {" or ".join(bf_interfaces)}')
        ip = None
        for _ in range(tries):
            ipa = h.run_on_bf("ip -json a").out
            detected = common.ipa_to_entries(ipa)
            found = [e for e in detected if e.ifname in bf_interfaces]
            if len(found) != 1:
                logger.error(f"Failed to find expected number of interfaces on bf {host_name}")
                logger.error(f"Output was: {ipa}")
                sys.exit(-1)

            ip = None
            for e in found[0].addr_info:
                if e.family == "inet":
                    ip = e.local
            if ip is None:
                logger.info(f"IP missing on {found[0]}, output was {ipa}")
            else:
                break
            time.sleep(10)

        if ip is None:
            sys.exit(-1)
        logger.info(f"Detected ip {ip}")
        return ip

    def wait_for_workers(self) -> None:
        logger.info(f'waiting for {len(self._cc.workers)} workers')
        lh = host.LocalHost()
        bf_workers = list(x for x in self._cc.workers if x.kind == "bf")
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
