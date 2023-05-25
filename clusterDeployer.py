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
import secrets
import re
import glob
import socket
import paramiko
from clustersConfig import ClustersConfig
import host
from k8sClient import K8sClient
from nfs import NFS
import coreosBuilder
from extraConfigBFB import ExtraConfigBFB, ExtraConfigSwitchNicMode
from extraConfigSriov import ExtraConfigSriov, ExtraConfigSriovOvSHWOL, ExtraConfigSriovOvSHWOL_NewAPI
from extraConfigDpuTenant import ExtraConfigDpuTenantMC, ExtraConfigDpuTenant, ExtraConfigDpuTenant_NewAPI
from extraConfigDpuInfra import ExtraConfigDpuInfra, ExtraConfigDpuInfra_NewAPI
from extraConfigOvnK import ExtraConfigOvnK
from extraConfigCNO import ExtraConfigCNO
import common
from virshPool import VirshPool


def setup_vm(lh, rh, virsh_pool: VirshPool, cfg: dict, iso_path: str):
    # lh is the localhost, on which bridge configuration is always done
    # rh is where the vms are installed. It can be localhost as well as remote hosts
    hostname = rh.get_hostname()
    print(f"\tSetting up vm on {hostname}")
    name = cfg["name"]
    ip = cfg["ip"]
    mac = "52:54:"+":".join(re.findall("..", secrets.token_hex()[:8]))

    # If adding a worker node fails, one might want to retry w/o tearing down the whole cluster
    # In that case, the DHCP entry might already be present, with wrong mac -> remove it
    cmd = "virsh net-dumpxml default"
    ret = lh.run(cmd)
    if name in ret.out:
        print(f"\t{name} already configured as static DHCP entry - removing before adding back with proper configuration")
        host_xml = f"<host name='{name}'/>"
        cmd = f"virsh net-update default delete ip-dhcp-host \"{host_xml}\" --live --config"
        ret = lh.run(cmd)

    host_xml = f"<host mac='{mac}' name='{name}' ip='{ip}'/>"
    print(f"\tCreating static DHCP entry for VM {name}")
    cmd = f"virsh net-update default add ip-dhcp-host \"{host_xml}\" --live --config"
    ret = lh.run(cmd)
    if ret.err:
        print(cmd)
        print(ret.err)
        sys.exit(-1)

    OS_VARIANT = "rhel8.5"
    RAM_MB = 32784
    DISK_GB = 48
    CPU_CORE = 8

    if hostname == "localhost":
        network = "network=default"
    else:
        network = "bridge=virbr0"

    cmd = f""" virt-install \
        --connect qemu:///system \
        -n {name} \
        -r {RAM_MB} \
        --vcpus {CPU_CORE} \
        --os-variant={OS_VARIANT} \
        --import \
        --network {network},mac={mac} \
        --events on_reboot=restart \
        --cdrom {iso_path} \
        --disk pool={virsh_pool.name()},size={DISK_GB},sparse=false \
        --wait=-1 """
    print(f"Starting VM {name}")
    ret = rh.run(cmd)
    if ret.returncode != 0:
        print(f"Finished starting VM {name}, cmd = {cmd}, err=  error {ret}")
    else:
        print(f"Finished starting VM {name} without any errors")
    return ret


def copy_iso_on_remote(rh, iso_path, virsh_pool) -> str:
    hostname = rh.get_hostname()
    virsh_pool.ensure_initialized()
    print(f"\tCopying {iso_path} to {hostname}:/{virsh_pool.images_path()}")
    rh.scp(iso_path, virsh_pool.images_path())
    basename = os.path.basename(iso_path)
    iso_path = os.path.join(virsh_pool.images_path(), basename)
    print(f"\tiso_path modified to {iso_path}")
    return iso_path


def run_cmd(h, cmd):
    ret = h.run(cmd)
    if ret.returncode:
        print(f"{cmd} failed: {ret.err}")
        sys.exit(-1)


def setup_all_vms(lh, rh, vms, iso_path, virsh_pool) -> list:
    if not vms:
        return []

    hostname = rh.get_hostname()
    print(f"\tSetting up vms on {hostname}")
    virsh_pool.ensure_initialized()

    executor = ThreadPoolExecutor(max_workers=len(vms))
    futures = []
    for e in vms:
        futures.append(executor.submit(setup_vm, lh, rh, virsh_pool, e, iso_path))

        while not rh.vm_is_running(e["name"]) and not futures[-1].done():
            time.sleep(1)

    return futures


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
            print(f"\t{to_run['name']} is not an extra config")
            sys.exit(-1)
        else:
            print(f"\trunning extra config {to_run['name']}")
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
        print(f"Starting ClusterDeployer with pool {pool_name}")
        for e in self._cc["hosts"]:
            if e["name"] == "localhost":
                h = host.LocalHost()
            else:
                h = host.RemoteHost(e["name"])

            print(f"\tCreating virsh_pool for {e['name']}")
            e["virsh_pool"] = VirshPool(h, pool_name, e["images_path"])

        def empty():
            f = Future()
            f.set_result(None)
            return f

        self._futures = {e["name"]: empty() for e in self._cc.all_nodes()}

    def local_host_config(self, hostname: Optional[str] = "localhost"):
        return next(e for e in self._cc["hosts"] if e["name"] == hostname)

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
        print(f"Tearing down {cluster_name}")
        self._ai.ensure_cluster_deleted(self._cc["name"])

        lh = host.LocalHost()
        for m in self._cc.local_vms():
            assert m["node"] == "localhost"
            images_path = self.local_host_config()["virsh_pool"].images_path()
            name = m["name"]
            image = f"/{images_path}/{name}.qcow2"
            if os.path.exists(image):
                os.remove(image)

            # destroy the VM only if that really exists
            if lh.run(f"virsh desc {name}").returncode == 0:
                r = lh.run(f"virsh destroy {name}")
                print("\t" + r.err if r.err else "\t" + r.out)
                r = lh.run(f"virsh undefine {name}")
                print("\t" + r.err if r.err else "\t" + r.out)

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
                r = lh.run(cmd)
                print("\t" + r.err if r.err else "\t" + r.out)
                removed_macs.append(mac)

        fn = "/var/lib/libvirt/dnsmasq/virbr0.status"
        with open(fn) as f:
            contents = f.read()

        if contents:
            j = json.loads(contents)
            names = [x["name"] for x in self._cc.local_vms()]
            print(f'\tCleaning up {fn}')
            print(f'\tremoving hosts with mac in {removed_macs} or name in {names}')
            filtered = []
            for entry in j:
                if entry["mac-address"] in removed_macs:
                    print(f'\tRemoved host with mac {entry["mac-address"]}')
                    continue
                if "hostname" in entry and entry["hostname"] in names:
                    print(f'\tRemoved host with name {entry["hostname"]}')
                    continue
                print(f'\tKept entry {entry}')
                filtered.append(entry)

            r = lh.run("virsh net-destroy default")
            print("\t" + r.err if r.err else "\t" + r.out)
            with open(fn, "w") as f:
                f.write(json.dumps(filtered, indent=4))
            r = lh.run("virsh net-start default")
            print("\t" + r.err if r.err else "\t" + r.out)
            r = lh.run("systemctl restart libvirtd")
            print("\t" + r.err if r.err else "\t" + r.out)

            vp = self.local_host_config()["virsh_pool"]
            vp.ensure_removed()

        if self.need_api_network():
            intif = self._validate_api_port(lh)
            if not intif:
                print("\tcan't find network API port")
            else:
                r = lh.run(f"ip link set {intif} nomaster")
                print("\t" + r.err if r.err else "\t" + r.out)

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
            print(f"\tUsing {extif} as external port")
            return extif
        return None

    def _validate_api_port(self, lh) -> Optional[str]:
        if self._cc["network_api_port"] == "auto":
            def carrier_no_addr(intf):
                return not intf["addr_info"] and "NO-CARRIER" not in intf["flags"]

            intif = common.first(carrier_no_addr, lh.ipa())
            if not intif:
                return None
            self._cc["network_api_port"] = intif["ifname"]

        intif = self._cc["network_api_port"]
        if lh.port_exists(intif):
            print(f"\tUsing {intif} as network API port")
            return intif
        return None

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

    def configure_bridge_and_net(self, h) -> None:
        cmd = "sed -e 's/#\\(user\\|group\\) = \".*\"$/\\1 = \"root\"/' -i /etc/libvirt/qemu.conf"
        run_cmd(h, cmd)

        hostname = h.get_hostname()
        cmd = "systemctl enable libvirtd"
        run_cmd(h, cmd)
        cmd = "systemctl start libvirtd"
        run_cmd(h, cmd)

        # stp must be disabled or it might conflict with default configuration of some physical switches
        # 'bridge' section of network 'default' can't be updated => destroy and recreate
        # check that default exists and contains stp=off
        cmd = "virsh net-dumpxml default"
        ret = h.run(cmd)

        if "stp='off'" not in ret.out:
            print("=================== !!!!!!!!!!!!!!!!!!!!!! ====================")
            print(" !!!!!!!!!!!!! Destoying and recreating bridge !!!!!!!!!!!!!!!!")
            print("=================== !!!!!!!!!!!!!!!!!!!!!! ====================")
            print(f"\tcreating default-net.xml on {hostname}")
            if hostname == "localhost":
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
            else:
                contents = """
<network>
  <name>default</name>
  <forward mode='nat'/>
  <bridge name='virbr0' stp='off' delay='0'/>
  <ip address='192.168.123.250' netmask='255.255.0.0'/>
</network>
"""
            bridge_xml = os.path.join("/tmp", 'vir_bridge.xml')
            with open(bridge_xml, 'w') as outfile:
                outfile.write(contents)
            if h.get_hostname() != "localhost":
                h.scp(bridge_xml, bridge_xml)

            cmd = "virsh net-destroy default"
            h.run(cmd) # ignore return code - it might fail if net was not started

            cmd = "virsh net-undefine default"
            ret = h.run(cmd)
            if ret.returncode != 0 and "Network not found" not in ret.err:
                print(ret)
                sys.exit(-1)

            cmd = f"virsh net-define {bridge_xml}"
            run_cmd(h, cmd)

            cmd = "virsh net-start default"
            run_cmd(h, cmd)

        cmd = "systemctl restart libvirtd"
        run_cmd(h, cmd)


    def ensure_linked_to_bridge(self, h, network_api_port: Optional[str] = "auto") -> None:
        if not self.need_api_network():
            print("\tOnly running local VMs (virbr0 not connected to externally)")
            return

        if network_api_port == "auto":
            api_network = self._cc["network_api_port"]
        else:
            api_network = network_api_port

        print(f"\tlink {api_network} to virbr0")

        interface = list(filter(lambda x: x["ifname"] == api_network, h.all_ports()))
        if not interface:
            print(f"\tMissing API network interface {api_network}")
            sys.exit(-1)

        interface = interface[0]
        bridge = "virbr0"

        self.configure_bridge_and_net(h)
        if "master" not in interface:
            print(f"\tNo master set for interface {api_network}, setting it to {bridge}")
            # set interface down before starting bridge as otherwise bridge start might fail if interface
            # already got an IP address in same network as bridge
            h.run(f"ip link set {api_network} down")
            h.run(f"ip link set {api_network} master {bridge}")
            h.run(f"ip link set {api_network} up")
        elif interface["master"] != bridge:
            print(f"\tIncorrect master set for interface {api_network}")
            sys.exit(-1)

    def need_external_network(self) -> bool:
        vm_bm = list(x for x in self._cc["workers"] if x["type"] == "vm" and x["node"] != 'localhost')
        return ("workers" in self.args.steps) and \
               (len(self._cc["workers"]) > len(self._cc.worker_vms()) or len(vm_bm) > 0)

    def _is_sno_configuration(self) -> bool:
        return len(self._cc["masters"]) == 1 and len(self._cc["workers"]) == 0

    def deploy(self) -> None:
        if self._cc["masters"]:
            if self._is_sno_configuration():
                print("Setting up a Single Node OpenShift (SNO) environment.")
                self._cc["api_ip"] = self._cc["masters"][0]["ip"]
                self._cc["ingress_ip"] = self._cc["masters"][0]["ip"]

            lh = host.LocalHost()
            min_cores = 32
            cc = int(lh.run("nproc").out)
            if cc < min_cores:
                print(f"\t{cc} cores on localhost but need at least {min_cores}")
                sys.exit(-1)
            if self.need_external_network() and not self._validate_external_port(lh):
                print(f"\tCan't find a valid external port, config is {self._cc['external_port']}")
                sys.exit(-1)
            if self.need_api_network() and not self._validate_api_port(lh):
                print(f"\tCan't find a valid network API port, config is {self._cc['network_api_port']}")
                sys.exit(-1)

            if "pre" in self.args.steps:
                self._preconfig()
            else:
                print("Skipping pre configuration.")

            if "masters" in self.args.steps:
                self.teardown()
                self.create_cluster()
                self.create_masters()
            else:
                print("Skipping master creation.")

            self.ensure_linked_to_bridge(lh)
            if "workers" in self.args.steps:
                if self._cc["workers"]:
                    self.create_workers()
                else:
                    print("Skipping worker creation.")

        if "post" in self.args.steps:
            self._postconfig()
        else:
            print("Skipping post configuration.")

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

        print("Creating cluster")
        print(cfg)
        self._ai.create_cluster(cluster_name, cfg)

    def create_masters(self) -> None:
        for e in self._cc["masters"]:
            self._futures[e["name"]].result()
        cluster_name = self._cc["name"]
        infra_env = f"{cluster_name}-x86"
        print(f"\tEnsuring infraenv {infra_env} exists.")

        cfg = {}
        cfg["cluster"] = cluster_name
        cfg["pull_secret"] = self._secrets_path
        cfg["cpu_architecture"] = "x86_64"
        cfg["openshift_version"] = self._cc["version"]
        self._ai.ensure_infraenv_created(infra_env, cfg)
        self._ai.download_iso_with_retry(infra_env)

        lh = host.LocalHost()
        futures = setup_all_vms(lh, lh, self._cc["masters"],
                                os.path.join(os.getcwd(), f"{infra_env}.iso"),
                                self.local_host_config()["virsh_pool"])

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
        self.ensure_linked_to_bridge(lh)
        print(f'downloading kubeconfig to {self._cc["kubeconfig"]}')
        self._ai.download_kubeconfig(self._cc["name"], os.path.dirname(self._cc["kubeconfig"]))
        self._update_etc_hosts()

    def _print_logs(self, name):
        ip = self._ai.get_ai_ip(name)
        if ip is None:
            return
        rh = host.RemoteHost(ip)
        print(f"Gathering logs from {name}")
        print(rh.run("sudo journalctl TAG=agent --no-pager").out)

    def _get_status(self, name: str):
        h = self._ai.get_ai_host(name)
        return h["status"] if h is not None else None

    def _wait_known_state(self, names, cb=lambda: None) -> None:
        names = list(names)
        print(f"\tWaiting for {names} to be in \'known\' state")
        status = {n: "" for n in names}
        while not all(v == "known" for v in status.values()):
            new_status = {n: self._get_status(n) for n in names}
            if new_status != status:
                print(f"latest status: {new_status}")
                status = new_status
            if any(v == "error" for v in status.values()):
                for e in names:
                    self._print_logs(e)
                print("Error encountered in one of the nodes, quitting...")
                sys.exit(-1)
            cb()
            time.sleep(5)

    def create_workers(self) -> None:
        for e in self._cc["workers"]:
            self._futures[e["name"]].result()
        is_bf = (x["type"] == "bf" for x in self._cc["workers"])

        if any(is_bf):
            if not all(is_bf):
                print("Not yet supported to have mixed BF and non-bf workers")
            else:
                self._create_bf_workers()
        else:
            self._create_x86_workers()

        print("Setting password to for root to redhat")
        for w in self._cc["workers"]:
            ai_ip = self._ai.get_ai_ip(w["name"])
            assert ai_ip is not None
            rh = host.RemoteHost(ai_ip)
            rh.ssh_connect("core")
            rh.run("echo root:redhat | sudo chpasswd")

    def _create_physical_x86_workers(self) -> None:
        def boot_helper(worker, iso):
            return self.boot_iso_x86(worker, iso)

        print("=== Setting up physical x86 workers ===")
        executor = ThreadPoolExecutor(max_workers=len(self._cc["workers"]))
        futures = []

        workers = list(x for x in self._cc["workers"] if x["type"] == "physical")
        cluster_name = self._cc["name"]
        infra_env_name = f"{cluster_name}-x86"
        for h in workers:
            futures.append(executor.submit(boot_helper, h, f"{infra_env_name}.iso"))

        for f in futures:
            print(f.result())

        for w in workers:
            w["ip"] = socket.gethostbyname(w["node"])

    def _create_vm_x86_workers(self) -> None:
        print("=== Setting up vm x86 workers on localhost ===")
        cluster_name = self._cc["name"]
        infra_env = f"{cluster_name}-x86"
        vm = list(x for x in self._cc["workers"] if x["type"] == "vm" and x["node"] == 'localhost')

        print(f"\tinfra_env = {infra_env}")
        lh = host.LocalHost()
        setup_all_vms(lh, lh, vm,
                      os.path.join(os.getcwd(), f"{infra_env}.iso"),
                      self.local_host_config()["virsh_pool"])
        self._wait_known_state(e["name"] for e in vm)

    def _create_remote_vm_x86_workers(self) -> None:
        print("=== Setting up vm x86 workers on remote hosts ===")
        cluster_name = self._cc["name"]
        infra_env = f"{cluster_name}-x86"
        bm_hostnames = set()
        bms = []
        for x in self._cc["workers"]:
            if x["node"] not in bm_hostnames and x["type"] == "vm" and x["node"] != 'localhost':
                bms.append(x)
                bm_hostnames.add(x["node"])
        print(f"\tinfra_env = {infra_env}")
        for bm in bms:
            rh = host.RemoteHost(bm["node"])
            host_config = self.local_host_config(bm["node"])
            rh.ssh_connect(host_config["username"], host_config["password"])
            cmd = "yum -y install libvirt qemu-img qemu-kvm virt-install"
            run_cmd(rh, cmd)

        lh = host.LocalHost()
        vms = []
        for bm in bms:
            rh = host.RemoteHost(bm["node"])
            print(f"==== Setting up vms on {bm['node']} ====")
            host_config = self.local_host_config(bm["node"])
            rh.ssh_connect(host_config["username"], host_config["password"])

            # TODO validate api port
            self.ensure_linked_to_bridge(rh, host_config["network_api_port"])

            iso_path = copy_iso_on_remote(rh, os.path.join(os.getcwd(), f"{infra_env}.iso"),
                                          self.local_host_config(bm["node"])["virsh_pool"])

            vm = list(x for x in self._cc["workers"] if x["type"] == "vm" and x["node"] == bm["node"])
            vms.extend(vm)
            print(f"Starting {len(vm)} VMs on {bm['node']}")
            setup_all_vms(lh, rh, vm, iso_path,
                          self.local_host_config(bm["node"])["virsh_pool"])
        self._wait_known_state(e["name"] for e in vms)


    def _create_x86_workers(self) -> None:
        print("== Setting up x86 workers ==")
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

        self._create_physical_x86_workers()
        self._create_vm_x86_workers()
        self._create_remote_vm_x86_workers()

        print("\trenaming workers")
        self._rename_workers(infra_env_name)
        self._wait_known_state(e["name"] for e in self._cc["workers"])
        print("\tstarting infra env")
        self._ai.start_infraenv(infra_env_name)
        print("\twaiting for workers to be ready")
        self.wait_for_workers()

    def _rename_workers(self, infra_env_name: str) -> None:
        print("\tWaiting for connectivity to all workers")
        hosts = []
        for w in self._cc["workers"]:
            rh = host.RemoteHost(w['ip'])
            rh.ssh_connect("core")
            hosts.append(rh)
        print("\tConnectivity established to all workers, now checking that they have an IP in 192.168.122/24")

        def addresses(h):
            ret = []
            for e in h.ipa():
                if "addr_info" not in e:
                    continue
                for k in e["addr_info"]:
                    ret.append(k["local"])
            return ret

        subnet = "192.168.122.0/24"

        def addr_ok(a):
            return common.ip_in_subnet(a, subnet)

        for w, h in zip(self._cc["workers"], hosts):
            if all(not addr_ok(a) for a in addresses(h)):
                print(f'\tWorker {w["name"]} doesn\'t have an IP in {subnet}.')
                sys.exit(-1)

        print("\tConnectivity established to all workers, renaming them in Assited installer")
        print(f"\tlooking for workers with ip {[w['ip'] for w in self._cc['workers']]}")
        while True:
            renamed = self._try_rename_workers(infra_env_name)
            expected = len(self._cc["workers"])
            if renamed == expected:
                print(f"\tFound and renamed {renamed} workers")
                break
            if renamed:
                print(f"\tFound and renamed {renamed} workers, but waiting for {expected}, retrying")
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
                    print(f"renamed {name}")
                    renamed += 1
        return renamed

    def boot_iso_x86(self, worker: dict, iso: str) -> None:
        host_name = worker["node"]
        print(f"\ttrying to boot {host_name}")

        lh = host.LocalHost()
        nfs = NFS(lh, self._cc["external_port"])

        h = host.RemoteHostWithBF2(host_name, worker["bmc_ip"], worker["bmc_user"], worker["bmc_password"])

        iso = nfs.host_file(f"/root/iso/{iso}")
        h.boot_iso_redfish(iso)
        h.ssh_connect("core")
        print(f"{host_name} connected")
        r = h.run("hostname")
        print("\t" + r.err if r.err else "\t" + r.out)

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
                print(f"Couldn't find ip of worker {h['name']}")
                sys.exit(-1)

        self._rename_workers(infra_env_name)
        self._wait_known_state(e["name"] for e in self._cc["workers"])
        self._ai.start_infraenv(infra_env_name)
        self.wait_for_workers()

    def _download_iso(self, infra_env_name: str, iso_path: str) -> None:
        print(f"\tDownload iso from {infra_env_name} to {iso_path}, will retry until success")

        while True:
            try:
                self._ai.download_iso(infra_env_name, iso_path)
                print(f"\tiso for {infra_env_name} downloaded to {iso_path}")
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
        print(f"\tThe SSH key that the discovery ISO will use is: {ssh_pub_key}")
        for file in glob.glob("/root/.ssh/*.pub"):
            with open(file, 'r') as f:
                key = " ".join(f.read().split(" ")[:-1])
                if key.split()[0] == ssh_pub_key.split()[0]:
                    print(f"\tFound matching public key at {file}")
                    ssh_priv_key = os.path.splitext(file)[0]
                    print(f"\tFound matching private key at {ssh_priv_key}")
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

    def boot_iso_bf(self, worker: dict, iso: str) -> str:
        lh = host.LocalHost()
        nfs = NFS(lh, self._cc["external_port"])

        host_name = worker["node"]
        print(f"\tPreparing BF on host {host_name}")
        h = host.RemoteHostWithBF2(host_name, worker["bmc_ip"], worker["bmc_user"], worker["bmc_password"])
        skip_boot = False
        if h.ping():
            try:
                h.ssh_connect("core")
                d = h.os_release()
                print(d)
                skip_boot = d["NAME"] == 'Fedora Linux' and d['VARIANT'] == 'CoreOS'
            except paramiko.ssh_exception.AuthenticationException:
                print("\tAuthentication failed, will not be able to skip boot")

        if skip_boot:
            print(f"\tSkipping booting {host_name}, already booted with FCOS")
        else:
            nfs_file = nfs.host_file("/root/iso/fedora-coreos.iso")
            h.boot_iso_redfish(nfs_file)
            time.sleep(10)
            h.ssh_connect("core")

        nfs_iso = nfs.host_file(f"/root/iso/{iso}")
        nfs_key = nfs.host_file("/root/iso/ssh_priv_key")
        output = h.bf_pxeboot(nfs_iso, nfs_key)
        print(output)
        if output.returncode:
            print(f"\tFailed to run pxeboot on bf {host_name}")
            sys.exit(-1)
        else:
            print(f"\tsuccesfully ran pxeboot on bf {host_name}")

        ipa = json.loads(output.out.strip().split("\n")[-1].strip())
        detected = common.extract_interfaces(ipa)
        bf_interfaces = ["enp3s0f0", "enp3s0f0np0"]
        found = [x for x in bf_interfaces if x in detected]
        if len(found) != 1:
            print("\tFailed to find any of {bf_interfaces} on bf {host_name}")
            print(f"\tOutput was: {ipa}")
        found = found[0]
        try:
            ip = common.extract_ip(ipa, found)
            print(ip)
        except Exception:
            ip = None
            print(f"\tFailed to find ip on {found}, output was {ipa}")
            sys.exit(-1)
        return ip

    def wait_for_workers(self) -> None:
        print(f'waiting for {self._cc["workers"]} workers')
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
                    h = host.RemoteHost(ai_ip, None, None)
                    h.ssh_connect("core")
                    print(f'\tconnected to {e["name"]}, setting user:pw')
                    h.run("echo root:redhat | sudo chpasswd")
                    connections[e["name"]] = h

            # Workaround: Time is not set and consequently HTTPS doesn't work
            for w in filter(lambda x: x["type"] == "bf", self._cc["workers"]):
                if w["name"] not in connections:
                    continue
                h = connections[w["name"]]
                host.sync_time(lh, h)

                # Workaround: images might become corrupt for an unknown reason. In that case, remove it to allow retries
                out = h.run("sudo podman images").out
                e = re.search(r".*Top layer (\w+) of image (\w+) not found in layer tree. The storage may be corrupted, consider running", out)
                if e:
                    print(f'\tRemoving corrupt image from worker {w["name"]}')
                    print(h.run(f"sudo podman rmi {e.group(2)}"))
                try:
                    out = h.run("sudo podman images --format json").out
                    podman_images = json.loads(out)
                    for image in podman_images:
                        inspect_output = h.run(f"sudo podman image inspect {image['Id']}").out
                        if "A storage corruption might have occurred" in inspect_output:
                            print("\tCorrupt image found")
                            h.run(f"sudo podman rmi {image['id']}")
                except Exception as e:
                    print(e)

            time.sleep(10)
