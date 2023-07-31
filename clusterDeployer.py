import os
import sys
import time
import json
import xml.etree.ElementTree as et
import shutil
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import Future
from typing import Optional
from typing import Dict
from clustersConfig import ClustersConfig
import host
import secrets
import re
from k8sClient import K8sClient
from nfs import NFS
import requests
import socket
import coreosBuilder
from extraConfigBFB import ExtraConfigBFB, ExtraConfigSwitchNicMode
from extraConfigSriov import ExtraConfigSriov, ExtraConfigSriovOvSHWOL, ExtraConfigSriovOvSHWOL_NewAPI
from extraConfigDpuTenant import ExtraConfigDpuTenantMC, ExtraConfigDpuTenant, ExtraConfigDpuTenant_NewAPI
from extraConfigDpuInfra import ExtraConfigDpuInfra, ExtraConfigDpuInfra_NewAPI
from extraConfigOvnK import ExtraConfigOvnK
from extraConfigCNO import ExtraConfigCNO
import paramiko
import common
from virshPool import VirshPool
import glob
from logger import logger
import logging


def ensure_dhcp_entry(h: host.Host, name: str, ip: str, mac: str):
    # If adding a worker node fails, one might want to retry w/o tearing down the whole cluster
    # In that case, the DHCP entry might already be present, with wrong mac -> remove it

    cmd = "virsh net-dumpxml default"
    ret = h.run_or_die(cmd)
    if name in ret.out:
        logger.info(f"{name} already configured as static DHCP entry - removing before adding back with proper configuration")
        host_xml = f"<host name='{name}'/>"
        cmd = f"virsh net-update default delete ip-dhcp-host \"{host_xml}\" --live --config"
        h.run_or_die(cmd)

    host_xml = f"<host mac='{mac}' name='{name}' ip='{ip}'/>"
    logger.info(f"Creating static DHCP entry for VM {name}")
    cmd = f"virsh net-update default add ip-dhcp-host \"{host_xml}\" --live --config"
    h.run_or_die(cmd)


def setup_vm(h: host.Host, virsh_pool: VirshPool, cfg: dict, iso_path: str):
    name = cfg["name"]
    ip = cfg["ip"]
    mac = "52:54:"+":".join(re.findall("..", secrets.token_hex()[:8]))
    ensure_dhcp_entry(h, name, ip, mac)

    OS_VARIANT = "rhel8.5"
    RAM_MB = 32784
    DISK_GB = cfg['disk_size']
    CPU_CORE = 8
    SPARSE = cfg['sparse']
    network = "default"

    cmd = f"""
    virt-install
        --connect qemu:///system
        -n {name}
        -r {RAM_MB}
        --vcpus {CPU_CORE}
        --os-variant={OS_VARIANT}
        --import
        --network=network:{network},mac={mac}
        --events on_reboot=restart
        --cdrom {iso_path}
        --disk pool={virsh_pool.name()},size={DISK_GB},sparse={SPARSE},format=raw
        --wait=-1
    """
    logger.info(f"Starting VM {name}")
    ret = h.run(cmd)
    if ret.returncode != 0:
        logger.info(f"Finished starting VM {name}, cmd = {cmd}, err=  error {ret}")
    else:
        logger.info(f"Finished starting VM {name} without any errors")
    return ret


def setup_all_vms(h: host.Host, vms, iso_path, virsh_pool) -> list:
    if not vms:
        return []

    virsh_pool.ensure_initialized()

    executor = ThreadPoolExecutor(max_workers=len(vms))
    futures = []
    for e in vms:
        futures.append(executor.submit(setup_vm, h, virsh_pool, e, iso_path))

        while not h.vm_is_running(e["name"]) and not futures[-1].done():
            time.sleep(1)

    return futures

def ensure_bridge_is_started(h: host.Host, bridge_xml: str):
    cmd = "virsh net-destroy default"
    h.run(cmd) # ignore return code - it might fail if net was not started

    cmd = "virsh net-undefine default"
    ret = h.run(cmd)
    if ret.returncode != 0 and "Network not found" not in ret.err:
        logger.error(ret)
        sys.exit(-1)

    cmd = f"virsh net-define {bridge_xml}"
    h.run_or_die(cmd)

    cmd = "virsh net-start default"
    h.run_or_die(cmd)

def configure_bridge(h: host.Host) -> None:
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
        logger.info("creating default-net.xml on localhost")
        contents = """
<network>
  <name>default</name>
  <forward mode='nat'/>
  <bridge name='virbr0' stp='off' delay='0'/>
  <ip address='192.168.122.1' netmask='255.255.0.0'>
    <dhcp>
      <range start='192.168.122.2' end='192.168.122.254'/>
    </dhcp>
  </ip>
</network>
"""
        bridge_xml = os.path.join("/tmp", 'vir_bridge.xml')
        h.write(bridge_xml, contents)
        ensure_bridge_is_started(h, bridge_xml)

        cmd = "systemctl restart libvirtd"
        h.run_or_die(cmd)

        # Not sure why/whether this is needed. But we saw failures w/o it.
        # We need to investigate how to remove the sleep to speed up
        time.sleep(5)

class ExtraConfigRunner():
    def __init__(self, cc: ClustersConfig):
        ec = {
            "bf_bfb_image": ExtraConfigBFB(cc),
            "switch_to_nic_mode": ExtraConfigSwitchNicMode(cc),
            "sriov_network_operator": ExtraConfigSriov(cc),
            "sriov_ovs_hwol": ExtraConfigSriovOvSHWOL(cc),
            "sriov_ovs_hwol_new_api": ExtraConfigSriovOvSHWOL_NewAPI(cc),
            "dpu_infra": ExtraConfigDpuInfra(cc),
            "dpu_infra_new_api": ExtraConfigDpuInfra_NewAPI(cc),
            "dpu_tenant_mc": ExtraConfigDpuTenantMC(cc),
            "dpu_tenant": ExtraConfigDpuTenant(cc),
            "dpu_tenant_new_api": ExtraConfigDpuTenant_NewAPI(cc),
            "ovnk8s": ExtraConfigOvnK(cc),
            "cno": ExtraConfigCNO(cc),
        }
        self._extra_config = ec

    def run(self, to_run, futures: Dict[str, Future]) -> None:
        if to_run["name"] not in self._extra_config:
            logger.info(f"{to_run['name']} is not an extra config")
            sys.exit(-1)
        else:
            logger.info(f"running extra config {to_run['name']}")
            self._extra_config[to_run['name']].run(to_run, futures)

class ClusterDeployer():
    def __init__(self, cc, ai, args, secrets_path: str):
        self._client = None
        self.args = args
        self._cc = cc
        self._ai = ai
        self._secrets_path = secrets_path
        self._iso_path = "/root/iso"
        os.makedirs(self._iso_path, exist_ok=True)
        self._extra_config = ExtraConfigRunner(cc)

        pool_name = f"{self._cc['name']}_guest_images"
        for e in self._cc["hosts"]:
            h = host.Host(e["name"])

            e["virsh_pool"] = VirshPool(h, pool_name, e["images_path"])

        def empty():
            f = Future()
            f.set_result(None)
            return f

        self._futures = {e["name"]: empty() for e in self._cc.all_nodes()}

    def local_host_config(self):
        return next(e for e in self._cc["hosts"] if e["name"] == "localhost")

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
        cluster_name = self._cc["name"]
        logger.info(f"Tearing down {cluster_name}")
        self._ai.ensure_cluster_deleted(self._cc["name"])

        lh = host.LocalHost()
        for m in self._cc.local_vms():
            assert m["node"] == "localhost"
            images_path = self.local_host_config()["virsh_pool"].images_path()
            name = m["name"]
            image = f"/{images_path}/{name}.img"
            if os.path.exists(image):
                os.remove(image)
            image = f"/{images_path}/{name}.qcow2"
            if os.path.exists(image):
                os.remove(image)

            # destroy the VM only if that really exists
            if lh.run(f"virsh desc {name}").returncode == 0:
                r = lh.run(f"virsh destroy {name}")
                logger.info(r.err if r.err else r.out.strip())
                r = lh.run(f"virsh undefine {name}")
                logger.info(r.err if r.err else r.out.strip())

        self._ai.ensure_infraenv_deleted(f"{cluster_name}-x86")
        self._ai.ensure_infraenv_deleted(f"{cluster_name}-arm")

        xml_str = lh.run("virsh net-dumpxml default").out
        q = et.fromstring(xml_str)
        removed_macs = []
        names = [x["name"] for x in self._cc.local_vms()]
        ips = [x["ip"] for x in self._cc.local_vms()]
        for e in q[-1][0][1:]:
            if e.attrib["name"] in names or e.attrib["ip"] in ips:
                mac = e.attrib["mac"]
                name = e.attrib["name"]
                ip = e.attrib["ip"]
                pre = "virsh net-update default delete ip-dhcp-host"
                cmd = f"{pre} \"<host mac='{mac}' name='{name}' ip='{ip}'/>\" --live --config"
                logger.info(lh.run(cmd))
                removed_macs.append(mac)

        fn = "/var/lib/libvirt/dnsmasq/virbr0.status"
        with open(fn) as f:
            contents = f.read()

        if contents:
            j = json.loads(contents)
            names = [x["name"] for x in self._cc.local_vms()]
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
                else:
                    logger.info(f'Kept entry {entry}')
                filtered.append(entry)

            logger.info(lh.run("virsh net-destroy default"))
            with open(fn, "w") as f:
                f.write(json.dumps(filtered, indent=4))
            logger.info(lh.run("virsh net-start default"))
            logger.info(lh.run("systemctl restart libvirtd"))

            vp = self.local_host_config()["virsh_pool"]
            vp.ensure_removed()

        if self.need_api_network():
            intif = self._validate_api_port(lh)
            if not intif:
                logger.info("can't find network API port")
            else:
                logger.info(lh.run(f"ip link set {intif} nomaster"))

        if os.path.exists(self._cc["kubeconfig"]):
            os.remove(self._cc["kubeconfig"])

    def _validate_external_port(self, lh) -> Optional[str]:
        # do automatic detection, if needed
        if self._cc["external_port"] == "auto":
            self._cc["external_port"] = lh.port_from_route("default")
            if not self._cc["external_port"]:
                return None

        # check that the interface really exists
        extif = self._cc["external_port"]
        if lh.port_exists(extif):
            logger.info(f"Using {extif} as external port")
            return extif
        return None

    def _validate_api_port(self, lh) -> Optional[str]:
        def carrier_no_addr(intf):
            return not intf["addr_info"] and "NO-CARRIER" not in intf["flags"]

        if self._cc["network_api_port"] == "auto":
            intif = common.first(carrier_no_addr, lh.ipa())
            if not intif:
                return None
            self._cc["network_api_port"] = intif["ifname"]

        port = self._cc["network_api_port"]
        logger.info(f'Validating API network port {port}')
        if not lh.port_exists(port):
            logger.error(f"Can't find API network port {port}")
            return None
        if not lh.port_has_carrier(port):
            logger.error(f"API network port {port} doesn't have a carrier")
            return None
        return port

    def _preconfig(self) -> None:
        for e in self._cc["preconfig"]:
            self._prepost_config(e)

    def _postconfig(self) -> None:
        for e in self._cc["postconfig"]:
            self._prepost_config(e)

    def _prepost_config(self, to_run) -> None:
        if not to_run:
            return
        self._extra_config.run(to_run, self._futures)

    def need_api_network(self):
        return len(self._cc.local_vms()) != len(self._cc.all_nodes())

    def ensure_linked_to_bridge(self) -> None:
        if not self.need_api_network():
            logger.info("Only running local VMs (virbr0 not connected to externally)")
            return

        api_network = self._cc["network_api_port"]
        logger.info(f"link {api_network} to virbr0")

        lh = host.LocalHost()
        interface = list(filter(lambda x: x["ifname"] == api_network, lh.all_ports()))
        if not interface:
            logger.info(f"Missing API network interface {api_network}")
            sys.exit(-1)

        interface = interface[0]
        bridge = "virbr0"

        configure_bridge(lh)
        cmd = "sed -e 's/#\\(user\\|group\\) = \".*\"$/\\1 = \"root\"/' -i /etc/libvirt/qemu.conf"
        lh.run(cmd)

        if "master" not in interface:
            logger.info(f"No master set for interface {api_network}, setting it to {bridge}")
            lh.run(f"ip link set {api_network} master {bridge}")
        elif interface["master"] != bridge:
            logger.info(f"Incorrect master set for interface {api_network}")
            sys.exit(-1)

    def need_external_network(self) -> bool:
        remote_workers = len(self._cc["workers"]) - len(self._cc.worker_vms())
        remote_masters = len(self._cc["masters"]) - len(self._cc.master_vms())
        if "workers" not in self.args.steps:
            remote_workers = 0
        if "masters" not in self.args.steps:
            remote_masters = 0
        return remote_masters != 0 or remote_workers != 0

    def _is_sno_configuration(self) -> bool:
        return len(self._cc["masters"]) == 1 and len(self._cc["workers"]) == 0

    def deploy(self) -> None:
        self._validate()

        if self._cc["masters"]:
            if "pre" in self.args.steps:
                self._preconfig()
            else:
                logger.info("Skipping pre configuration.")

            if "masters" in self.args.steps:
                self.teardown()
                self.create_cluster()
                self.create_masters()
            else:
                logger.info("Skipping master creation.")

            self.ensure_linked_to_bridge()
            if "workers" in self.args.steps:
                if self._cc["workers"]:
                    self.create_workers()
                else:
                    logger.info("Skipping worker creation.")

        if "post" in self.args.steps:
            self._postconfig()
        else:
            logger.info("Skipping post configuration.")

    def _validate(self):
        if self._is_sno_configuration():
            logger.info("Setting up a Single Node OpenShift (SNO) environment")
            self._cc["api_ip"] = self._cc["masters"][0]["ip"]
            self._cc["ingress_ip"] = self._cc["masters"][0]["ip"]

        lh = host.LocalHost()
        min_cores = 28
        cc = int(lh.run("nproc").out)
        if cc < min_cores:
            logger.info(f"Detected {cc} cores on localhost, but need at least {min_cores} cores")
            sys.exit(-1)
        if self.need_external_network() and not self._validate_external_port(lh):
            logger.info(f"Can't find a valid external port, config is {self._cc['external_port']}")
            sys.exit(-1)
        else:
            logger.info("Don't need external network so will not set it up")
        if self.need_api_network() and not self._validate_api_port(lh):
            logger.info(f"Can't find a valid network API port, config is {self._cc['network_api_port']}")
            sys.exit(-1)
        else:
            logger.info(f"Using {self._cc['network_api_port']} as network API port")

    def client(self) -> K8sClient:
        if self._client is None:
            self._client = K8sClient(self._cc["kubeconfig"])
        return self._client

    def create_cluster(self) -> None:
        cluster_name = self._cc["name"]
        cfg = {}
        cfg["openshift_version"] = self._cc["version"]
        cfg["cpu_architecture"] = "multi"
        cfg["pull_secret"] = self._secrets_path
        cfg["infraenv"] = "false"

        cfg["api_ip"] = self._cc["api_ip"]
        cfg["ingress_ip"] = self._cc["ingress_ip"]
        cfg["vip_dhcp_allocation"] = False
        cfg["additional_ntp_source"] = "clock.redhat.com"
        cfg["base_dns_domain"] = "redhat.com"
        cfg["sno"] = self._is_sno_configuration()

        logger.info("Creating cluster")
        logger.info(cfg)
        self._ai.create_cluster(cluster_name, cfg)

    def create_masters(self) -> None:
        for e in self._cc["masters"]:
            self._futures[e["name"]].result()
        cluster_name = self._cc["name"]
        infra_env = f"{cluster_name}-x86"
        logger.info(f"Ensuring infraenv {infra_env} exists.")

        cfg = {}
        cfg["cluster"] = cluster_name
        cfg["pull_secret"] = self._secrets_path
        cfg["cpu_architecture"] = "x86_64"
        cfg["openshift_version"] = self._cc["version"]
        self._ai.ensure_infraenv_created(infra_env, cfg)
        self._ai.download_iso_with_retry(infra_env)

        lh = host.LocalHost()
        # TODO: clean this up. Currently just skipping this
        # since self.local_host_config() is not present if no local vms
        if self._cc.local_vms():
            futures = setup_all_vms(lh, self._cc["masters"],
                                    os.path.join(os.getcwd(), f"{infra_env}.iso"),
                                    self.local_host_config()["virsh_pool"])
        else:
            self._create_physical_x86_nodes(self._cc["masters"])
            futures = []

        def cb():
            finished = [p for p in futures if p.done()]
            if finished:
                raise Exception(f"Can't install VMs {finished[0].result()}")
        names = (e["name"] for e in self._cc["masters"])
        self._wait_known_state(names, cb)
        self._ai.start_until_success(cluster_name)

        self._ai.wait_cluster(cluster_name)
        for p in futures:
            p.result()
        self.ensure_linked_to_bridge()
        logger.info(f'downloading kubeconfig to {self._cc["kubeconfig"]}')
        self._ai.download_kubeconfig(self._cc["name"], os.path.dirname(self._cc["kubeconfig"]))
        self._update_etc_hosts()

    def _print_logs(self, name):
        ip = self._ai.get_ai_ip(name)
        if ip is None:
            return
        rh = host.RemoteHost(ip)
        logger.info(f"Gathering logs from {name}")
        logger.info(rh.run("sudo journalctl TAG=agent --no-pager").out)

    def _get_status(self, name: str):
        h = self._ai.get_ai_host(name)
        return h["status"] if h is not None else None

    def _wait_known_state(self, names, cb=lambda: None) -> None:
        names = list(names)
        logger.info(f"Waiting for {names} to be in \'known\' state")
        status = {n: "" for n in names}
        while not all(v == "known" for v in status.values()):
            new_status = {n: self._get_status(n) for n in names}
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

    def _verify_package_is_installed(self, worker, package: str) -> bool:
        ai_ip = self._ai.get_ai_ip(worker["name"])
        rh = host.RemoteHost(ai_ip)
        rh.ssh_connect("core")
        ret = rh.run(f"rpm -qa | grep {package}")
        return not ret.returncode

    def _perform_worker_health_check(self, workers) -> None:
        for w in workers:
            err_str = "Required rpm 'kernel-modules-extra' is not installed"
            assert self._verify_package_is_installed(w, "kernel-modules-extra"), err_str

    def create_workers(self) -> None:
        for e in self._cc["workers"]:
            self._futures[e["name"]].result()
        is_bf = (x["type"] == "bf" for x in self._cc["workers"])

        if any(is_bf):
            if not all(is_bf):
                logger.info("Not yet supported to have mixed BF and non-bf workers")
            else:
                self._create_bf_workers()
        else:
            self._create_x86_workers()

        logger.info("Setting password to for root to redhat")
        for w in self._cc["workers"]:
            ai_ip = self._ai.get_ai_ip(w["name"])
            assert ai_ip is not None
            rh = host.RemoteHost(ai_ip)
            rh.ssh_connect("core")
            rh.run("echo root:redhat | sudo chpasswd")
        
        self._perform_worker_health_check(self._cc["workers"])

    def _create_physical_x86_nodes(self, nodes) -> None:
        def boot_helper(worker, iso):
            return self.boot_iso_x86(worker, iso)

        executor = ThreadPoolExecutor(max_workers=len(nodes))
        futures = []

        nodes = list(x for x in nodes if x["type"] == "physical")
        cluster_name = self._cc["name"]
        infra_env_name = f"{cluster_name}-x86"
        for h in nodes:
            futures.append(executor.submit(boot_helper, h, f"{infra_env_name}.iso"))

        for f in futures:
            logger.info(f.result())

        for w in nodes:
            w["ip"] = socket.gethostbyname(w["node"])

    def _create_vm_x86_workers(self) -> None:
        cluster_name = self._cc["name"]
        infra_env = f"{cluster_name}-x86"
        vm = list(x for x in self._cc["workers"] if x["type"] == "vm")
        logger.info(infra_env)
        lh = host.LocalHost()
        # TODO: clean this up. Currently just skipping this
        # since self.local_host_config() is not present if no local vms
        if self._cc.local_vms():
            _ = setup_all_vms(lh, vm,
                                     os.path.join(os.getcwd(), f"{infra_env}.iso"),
                                     self.local_host_config()["virsh_pool"])
        self._wait_known_state(e["name"] for e in vm)

    def _create_x86_workers(self) -> None:
        logger.info("Setting up x86 workers")
        cluster_name = self._cc["name"]
        infra_env_name = f"{cluster_name}-x86"

        self._ai.allow_add_workers(cluster_name)

        cfg = {}
        cfg["cluster"] = cluster_name
        cfg["pull_secret"] = self._secrets_path
        cfg["cpu_architecture"] = "x86_64"
        cfg["openshift_version"] = self._cc["version"]

        self._ai.ensure_infraenv_created(infra_env_name, cfg)

        os.makedirs(self._iso_path, exist_ok=True)
        self._download_iso(infra_env_name, self._iso_path)

        self._create_physical_x86_nodes(self._cc["workers"])
        self._create_vm_x86_workers()

        logger.info("renaming workers")
        self._rename_workers(infra_env_name)
        self._wait_known_state(e["name"] for e in self._cc["workers"])
        logger.info("starting infra env")
        self._ai.start_infraenv(infra_env_name)
        logger.info("waiting for workers to be ready")
        self.wait_for_workers()

    def _rename_workers(self, infra_env_name: str) -> None:
        logger.info("Waiting for connectivity to all workers")
        hosts = []
        for w in self._cc["workers"]:
            rh = host.RemoteHost(w['ip'])
            rh.ssh_connect("core")
            hosts.append(rh)
        subnet = "192.168.122.0/24"
        logger.info(f"Connectivity established to all workers; checking that they have an IP in {subnet}")

        def addresses(h):
            ret = []
            for e in h.ipa():
                if "addr_info" not in e:
                    continue
                for k in e["addr_info"]:
                    ret.append(k["local"])
            return ret

        def addr_ok(a):
            return common.ip_in_subnet(a, subnet)

        any_worker_bad = False
        for w, h in zip(self._cc["workers"], hosts):
            if all(not addr_ok(a) for a in addresses(h)):
                logger.info(f"Worker {w['name']} doesn't have an IP in {subnet}.")
                any_worker_bad = True

        if any_worker_bad:
            sys.exit(-1)

        logger.info("Connectivity established to all workers, renaming them in Assited installer")
        logger.info(f"looking for workers with ip {[w['ip'] for w in self._cc['workers']]}")
        while True:
            renamed = self._try_rename_workers(infra_env_name)
            expected = len(self._cc["workers"])
            if renamed == expected:
                logger.info(f"Found and renamed {renamed} workers")
                break
            elif renamed:
                logger.info(f"Found and renamed {renamed} workers, but waiting for {expected}, retrying")
                time.sleep(5)

    def _try_rename_workers(self, infra_env_name: str) -> int:
        infra_env_id = self._ai.get_infra_env_id(infra_env_name)
        renamed = 0

        for w in self._cc["workers"]:
            for h in filter(lambda x: x["infra_env_id"] == infra_env_id, self._ai.list_hosts()):
                if "inventory" not in h:
                    continue
                nics = json.loads(h["inventory"]).get("interfaces")
                addresses = sum((nic["ipv4_addresses"] for nic in nics), [])
                addresses = list(a.split("/")[0] for a in addresses)

                if w["ip"] in addresses:
                    name = w["name"]
                    self._ai.update_host(h["id"], {"name": name})
                    logger.info(f"renamed {name}")
                    renamed += 1
        return renamed

    def boot_iso_x86(self, worker: dict, iso: str) -> None:
        host_name = worker["node"]
        logger.info(f"trying to boot {host_name}")

        lh = host.LocalHost()
        nfs = NFS(lh, self._cc["external_port"])

        h = host.HostWithBF2(host_name, worker["bmc_ip"], worker["bmc_user"], worker["bmc_password"])

        iso = nfs.host_file(f"/root/iso/{iso}")
        h.boot_iso_redfish(iso)
        h.ssh_connect("core")
        logger.info("connected")
        logger.info(h.run("hostname"))

    def _create_bf_workers(self) -> None:
        cluster_name = self._cc["name"]
        infra_env_name = f"{cluster_name}-arm"

        self._ai.allow_add_workers(cluster_name)

        cfg = {}
        cfg["cluster"] = cluster_name
        cfg["pull_secret"] = self._secrets_path
        cfg["cpu_architecture"] = "arm64"
        cfg["openshift_version"] = self._cc["version"]

        self._ai.ensure_infraenv_created(infra_env_name, cfg)

        self._download_iso(infra_env_name, self._iso_path)

        ssh_priv_key_path = self._get_discovery_ign_ssh_priv_key(infra_env_name)

        coreosBuilder.ensure_fcos_exists()
        shutil.copyfile(ssh_priv_key_path, os.path.join(self._iso_path, "ssh_priv_key"))

        def boot_iso_bf_helper(worker, iso):
            return self.boot_iso_bf(worker, iso)

        executor = ThreadPoolExecutor(max_workers=len(self._cc["workers"]))
        futures = []
        for h in self._cc["workers"]:
            f = executor.submit(boot_iso_bf_helper, h, f"{infra_env_name}.iso")
            futures.append(f)

        for (h, f) in zip(self._cc["workers"], futures):
            h["ip"] = f.result()
            if h["ip"] is None:
                logger.info(f"Couldn't find ip of worker {h['name']}")
                sys.exit(-1)

        self._rename_workers(infra_env_name)
        self._wait_known_state(e["name"] for e in self._cc["workers"])
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

    def _update_etc_hosts(self) -> None:
        cluster_name = self._cc["name"]
        api_name = f"api.{cluster_name}.redhat.com"
        api_ip = self._ai.info_cluster(cluster_name).api_vip
        found = False
        etchost = ""
        with open("/etc/hosts", "r") as f:
            etchost = f.read()
        for e in etchost.split("\n"):
            if e and e.split()[1] == api_name:
                found = True
                break
        if not found:
            with open("/etc/hosts", "a") as f:
                f.write(f"{api_ip} {api_name}\n")
        # libvirtd also runs dnsmasq, and dnsmasq reads /etc/hosts.
        # For that reason, restart libvirtd to re-read the changes.
        lh = host.LocalHost()
        lh.run("systemctl restart libvirtd")

    def boot_iso_bf(self, worker: dict, iso: str) -> str:
        lh = host.LocalHost()
        nfs = NFS(lh, self._cc["external_port"])

        host_name = worker["node"]
        logger.info(f"Preparing BF on host {host_name}")
        h = host.HostWithBF2(host_name, worker["bmc_ip"], worker["bmc_user"], worker["bmc_password"])
        skip_boot = False
        if h.ping():
            try:
                h.ssh_connect("core")
                skip_boot = h.running_fcos()
            except paramiko.ssh_exception.AuthenticationException as e:
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
            ipa = json.loads(h.run_on_bf("ip -json a").out)
            detected = common.extract_interfaces(ipa)
            found = list(set(detected).intersection(set(bf_interfaces)))
            if len(found) != 1:
                logger.error(f"Failed to find expected number of interfaces on bf {host_name}")
                logger.error(f"Output was: {ipa}")
                sys.exit(-1)

            found = found[0]
            try:
                ip = common.extract_ip(ipa, found)
                break
            except Exception:
                ip = None
                logger.info(f"Failed to find ip on {found}, output was {ipa}")
            time.sleep(10)

        if ip is None:
            sys.exit(-1)
        logger.info(f"Detected ip {ip}")
        return ip

    def wait_for_workers(self) -> None:
        logger.info(f'waiting for {self._cc["workers"]} workers')
        lh = host.LocalHost()
        bf_workers = list(filter(lambda x: x["type"] == "bf", self._cc["workers"]))
        connections = {}
        while True:
            workers = [w["name"] for w in self._cc["workers"]]
            if all(self.client().is_ready(w) for w in workers):
                break

            self.client().approve_csr()

            if len(connections) != len(bf_workers):
                for e in filter(lambda x: x["name"] not in connections, bf_workers):
                    ai_ip = self._ai.get_ai_ip(e["name"])
                    if ai_ip is None:
                        continue
                    h = host.Host(ai_ip)
                    h.ssh_connect("core")
                    logger.info(f'connected to {e["name"]}, setting user:pw')
                    h.run("echo root:redhat | sudo chpasswd")
                    connections[e["name"]] = h

            # Workaround: Time is not set and consequently HTTPS doesn't work
            for w in filter(lambda x: x["type"] == "bf", self._cc["workers"]):
                if w["name"] not in connections:
                    continue
                h = connections[w["name"]]
                host.sync_time(lh, h)

                # Workaround: images might become corrupt for an unknown reason. In that case, remove it to allow retries
                out = h.run("sudo podman images", logging.DEBUG).out
                e = re.search(r".*Top layer (\w+) of image (\w+) not found in layer tree. The storage may be corrupted, consider running", out)
                if e:
                    logger.warn(f'Removing corrupt image from worker {w["name"]}')
                    logger.warn(h.run(f"sudo podman rmi {e.group(2)}"))
                try:
                    out = h.run("sudo podman images --format json", logging.DEBUG).out
                    podman_images = json.loads(out)
                    for image in podman_images:
                        inspect_output = h.run(f"sudo podman image inspect {image['Id']}", logging.DEBUG).out
                        if "A storage corruption might have occurred" in inspect_output:
                            logger.warn("Corrupt image found")
                            h.run(f"sudo podman rmi {image['id']}")
                except Exception as e:
                    logger.info(e)
                    pass

            time.sleep(30)
