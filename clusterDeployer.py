import os
import sys
import time
import json
import xml.etree.ElementTree as et
import shutil
from concurrent.futures import ThreadPoolExecutor
import host
import secrets
import re
from k8sClient import K8sClient
import nfs
import requests
import socket
import coreosBuilder
from extraConfigBFB import ExtraConfigBFB, ExtraConfigSwitchNicMode
from extraConfigSriov import ExtraConfigSriov, ExtraConfigSriovOvSHWOL
from extraConfigDpuTenant import ExtraConfigDpuTenant
from extraConfigDpuInfra import ExtraConfigDpuInfra
from extraConfigOvnK import ExtraConfigOvnK
import paramiko
import common
from virshPool import VirshPool


def setup_vm(h: host.LocalHost, virsh_pool: VirshPool, cfg: dict, iso_path: str):
    print("Creating static DHCP entry")
    name = cfg["name"]
    ip = cfg["ip"]
    mac = "52:54:"+":".join(re.findall("..", secrets.token_hex()[:8]))
    host_xml = f"<host mac='{mac}' name='{name}' ip='{ip}'/>"
    cmd = f"virsh net-update default add ip-dhcp-host \"{host_xml}\" --live --config"
    ret = h.run(cmd)
    if ret.err:
        print(cmd)
        print(ret.err)
        sys.exit(-1)
    else:
        print(ret.out)

    OS_VARIANT = "rhel8.5"
    RAM_MB = 32784
    DISK_GB = 64
    CPU_CORE = 8
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
        --disk pool={virsh_pool.name()},size={DISK_GB}
        --wait=-1
    """
    print(f"starting virsh {cmd}")
    ret = h.run(cmd)
    print(f"Finished running {cmd} with result {ret}")
    time.sleep(3)
    return ret


def setup_all_vms(h: host.LocalHost, vms, iso_path, virsh_pool) -> list:
    virsh_pool.ensure_initialized()

    executor = ThreadPoolExecutor(max_workers=len(vms))
    futures = []
    for e in vms:
        futures.append(executor.submit(setup_vm, h, virsh_pool, e, iso_path))

    return futures

class ClusterDeployer():
    def __init__(self, cc, ai, args, secrets_path: str):
        self._client = None
        self.args = args
        self._cc = cc
        self._ai = ai
        self._secrets_path = secrets_path
        self._iso_path = "/root/iso"
        os.makedirs(self._iso_path, exist_ok=True)
        self._extra_config = {}

        pool_name = f"{self._cc['name']}_guest_images"
        for e in self._cc["hosts"]:
            if e["name"] == "localhost":
                h = host.LocalHost()
            else:
                h = host.RemoteHost(e["name"])

            e["virsh_pool"] = VirshPool(h, pool_name, e["images_path"])

        self._futures = {}

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
        print(f"Tearing down {cluster_name}")
        self._ai.ensure_cluster_deleted(self._cc["name"])

        lh = host.LocalHost()
        for m in self._cc.local_vms():
            assert(m["node"] == "localhost")
            images_path = self.local_host_config()["virsh_pool"].images_path()
            name = m["name"]
            image = f"/{images_path}/{name}.qcow2"
            if os.path.exists(image):
                os.remove(image)

            # destroy the VM only if that really exists
            if lh.run(f"virsh desc {name}").returncode == 0:
                r = lh.run(f"virsh destroy {name}")
                print(r.err if r.err else r.out)
                r = lh.run(f"virsh undefine {name}")
                print(r.err if r.err else r.out)

        self._ai.ensure_infraenv_deleted(f"{cluster_name}-x86")
        self._ai.ensure_infraenv_deleted(f"{cluster_name}-arm")

        xml_str = lh.run("virsh net-dumpxml default").out
        q = et.fromstring(xml_str)
        removed_macs = []
        for e in q[-1][0][1:]:
            if (e.attrib["name"] in [x["name"] for x in self._cc.local_vms()] or
                e.attrib["ip"] in [x["ip"] for x in self._cc.local_vms()]):
                mac = e.attrib["mac"]
                name = e.attrib["name"]
                ip = e.attrib["ip"]
                pre = "virsh net-update default delete ip-dhcp-host"
                cmd = f"{pre} \"<host mac='{mac}' name='{name}' ip='{ip}'/>\" --live --config"
                print(lh.run(cmd))
                removed_macs.append(mac)

        fn = "/var/lib/libvirt/dnsmasq/virbr0.status"
        with open(fn) as f:
            contents = f.read()

        if contents:
            j = json.loads(contents)
            names = [x["name"] for x in self._cc.local_vms()]
            print(f'Cleaning up {fn}')
            print(f'removing hosts with mac in {removed_macs} or name in {names}')
            filtered = []
            for entry in j:
                if entry["mac-address"] in removed_macs:
                    print(f'Removed host with mac {entry["mac-address"]}')
                    continue
                if "hostname" in entry and entry["hostname"] in names:
                    print(f'Removed host with name {entry["hostname"]}')
                    continue
                else:
                    print(f'Kept entry {entry}')
                filtered.append(entry)

            print(lh.run("virsh net-destroy default"))
            with open(fn, "w") as f:
                f.write(json.dumps(filtered, indent=4))
            print(lh.run("virsh net-start default"))
            print(lh.run("systemctl restart libvirtd"))

            vp = self.local_host_config()["virsh_pool"]
            vp.ensure_removed()

        print(lh.run(f"ip link set eno1 nomaster"))

    def _preconfig(self) -> None:
        for e in self._cc["preconfig"]:
            self._prepost_config(e)

    def _postconfig(self) -> None:
        for e in self._cc["postconfig"]:
            self._prepost_config(e)

    def _prepost_config(self, to_run) -> None:
        if not to_run:
            return

        if not self._extra_config:
            self._extra_config["bf_bfb_image"] = ExtraConfigBFB(self._cc)
            self._extra_config["switch_to_nic_mode"] = ExtraConfigSwitchNicMode(self._cc)
            self._extra_config["sriov_network_operator"] = ExtraConfigSriov(self._cc)
            self._extra_config["sriov_ovs_hwol"] = ExtraConfigSriovOvSHWOL(self._cc)
            self._extra_config["dpu_infra"] = ExtraConfigDpuInfra(self._cc)
            self._extra_config["dpu_tenant"] = ExtraConfigDpuTenant(self._cc)
            self._extra_config["ovnk8s"] = ExtraConfigOvnK(self._cc)

        if to_run["name"] not in self._extra_config:
            print(f"{to_run['name']} is not an extra config")
            sys.exit(-1)
        else:
            print(f"running extra config {to_run['name']}")
            self._extra_config[to_run['name']].run(to_run)

    def ensure_linked_to_bridge(self) -> None:
        if len(self._cc.local_vms()) == len(self._cc.all_nodes()):
            print("Only running local VMs (virbr0 not connected to externally)")
            return
        print("link eno1 to virbr0")

        lh = host.LocalHost()
        interface = list(filter(lambda x: x["ifname"] == "eno1", lh.ipa()))
        if not interface:
            print("Missing interface eno1")

        interface = interface[0]

        bridge = "virbr0"
        api_network = "eno1"

        if "master" not in interface:
            print(f"No master set for interface {api_network}, setting it to {bridge}")
            lh.run(f"ip link set {api_network} master {bridge}")
        elif interface["master"] != bridge:
            print(f"Incorrect master set for interface {api_network}")
            sys.exit(-1)

    def deploy(self) -> None:
        if self._cc["masters"]:
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

            self.ensure_linked_to_bridge()
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

        print("Creating cluster")
        print(cfg)
        self._ai.create_cluster(cluster_name, cfg)

    def create_masters(self) -> None:
        cluster_name = self._cc["name"]
        infra_env = f"{cluster_name}-x86"
        print(f"Creating infraenv {infra_env}")

        cfg = {}
        cfg["cluster"] = cluster_name
        cfg["pull_secret"] = self._secrets_path
        cfg["cpu_architecture"] = "x86_64"
        self._ai.create_infra_env(infra_env, cfg)
        self._ai.download_iso_with_retry(infra_env)

        lh = host.LocalHost()
        futures = setup_all_vms(lh, self._cc["masters"],
                                os.path.join(os.getcwd(), f"{infra_env}.iso"),
                                self.local_host_config()["virsh_pool"])

        def cb():
            if any(p.done() for p in futures):
                raise Exception("Can't install VMs")
        names = (e["name"] for e in self._cc["masters"])
        self._wait_known_state(names, cb)
        self._ai.start_until_success(cluster_name)

        self._ai.wait_cluster(cluster_name)
        for p in futures:
            p.result()
        self.ensure_linked_to_bridge()
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
        print(f"Waiting for {names} to be in \'known\' state")
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
        is_bf = (x["type"] == "bf" for x in self._cc["workers"])

        nfs.export(self._iso_path)
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

    def _allow_add_workers(self, cluster_name: str) -> None:
        uuid = self._ai.info_cluster(cluster_name).to_dict()["id"]
        requests.post(f"http://{self._ai.url}/api/assisted-install/v2/clusters/{uuid}/actions/allow-add-workers")

    def _create_physical_x86_workers(self) -> None:
        def boot_helper(worker, iso):
            return self.boot_iso_x86(worker, iso)

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
        cluster_name = self._cc["name"]
        infra_env = f"{cluster_name}-x86"
        vm = list(x for x in self._cc["workers"] if x["type"] == "vm")
        print(infra_env)
        lh = host.LocalHost()
        futures = setup_all_vms(lh, vm,
                                os.path.join(os.getcwd(), f"{infra_env}.iso"),
                                self.local_host_config()["virsh_pool"])
        self._wait_known_state(e["name"] for e in vm)


    def _create_x86_workers(self) -> None:
        print("Setting up x86 workers")
        cluster_name = self._cc["name"]
        infra_env_name = f"{cluster_name}-x86"

        self._allow_add_workers(cluster_name)

        cfg = {}
        cfg["cluster"] = cluster_name
        cfg["pull_secret"] = self._secrets_path
        cfg["cpu_architecture"] = "x86_64"

        if all(map(lambda x: x["name"] != infra_env_name, self._ai.list_infra_envs())):
            print(f"Creating infraenv {infra_env_name}")
            self._ai.create_infra_env(infra_env_name, cfg)

        os.makedirs(self._iso_path, exist_ok = True)
        self._download_iso(infra_env_name, self._iso_path)

        self._create_physical_x86_workers()
        self._create_vm_x86_workers()

        print("renaming workers")
        self._rename_workers(infra_env_name)
        self._wait_known_state(e["name"] for e in self._cc["workers"])
        print("starting infra env")
        self._ai.start_infraenv(infra_env_name)
        print("waiting for workers to be ready")
        self.wait_for_workers()

    def _rename_workers(self, infra_env_name: str) -> None:
        print(f"looking for workers with ip {[w['ip'] for w in self._cc['workers']]}")
        while True:
            renamed = self._try_rename_workers(infra_env_name)
            expected = len(self._cc["workers"])
            if renamed == expected:
                print(f"Found and renamed {renamed} workers")
                break
            elif renamed:
                print(f"Found and renamed {renamed} workers, but waiting for {expected}, retrying")
                time.sleep(5)

    def _try_rename_workers(self, infra_env_name: str) -> int:
        infra_env_id = self._ai.get_infra_env_id(infra_env_name)
        renamed = 0

        for w in self._cc["workers"]:
            for h in filter(lambda x: x["infra_env_id"] == infra_env_id, self._ai.list_hosts()):
                if not "inventory" in h:
                    continue
                nics = json.loads(h["inventory"]).get("interfaces")
                addresses = sum((nic["ipv4_addresses"] for nic in nics), [])
                addresses = list(a.split("/")[0] for a in addresses)

                if w["ip"] in addresses:
                    name = w["name"]
                    self._ai.update_host(h["id"], {"name" : name})
                    print(f"renamed {name}")
                    renamed += 1
        return renamed

    def boot_iso_x86(self, worker: dict, iso: str) -> None:
        host_name = worker["node"]
        print(f"trying to boot {host_name}")

        lh = host.LocalHost()
        nfs_server = common.extract_ip(lh.run("ip -json a").out, "eno3")

        h = host.RemoteHostWithBF2(host_name, worker["bmc_user"], worker["bmc_password"])

        h.boot_iso_redfish(f"{nfs_server}:/root/iso/{iso}")
        h.ssh_connect("core")
        print("connected")
        print(h.run("hostname"))

    def _create_bf_workers(self) -> None:
        cluster_name = self._cc["name"]
        infra_env_name = f"{cluster_name}-arm"

        self._allow_add_workers(cluster_name)

        cfg = {}
        cfg["cluster"] = cluster_name
        cfg["pull_secret"] = self._secrets_path
        cfg["cpu_architecture"] = "arm64"

        if all(map(lambda x: x["name"] != infra_env_name, self._ai.list_infra_envs())):
            print(f"Creating infraenv {infra_env_name}")
            self._ai.create_infra_env(infra_env_name, cfg)

        self._download_iso(infra_env_name, self._iso_path)

        id_rsa_file = "/root/.ssh/id_rsa"
        coreosBuilder.ensure_fcos_exists()
        shutil.copyfile(id_rsa_file, os.path.join(self._iso_path, "id_rsa"))

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
        print(f"Download iso from {infra_env_name} to {iso_path}, will retry until success")
        while True:
            try:
                self._ai.download_iso(infra_env_name, iso_path)
                print(f"iso for {infra_env_name} downloaded to {iso_path}")
                break
            except:
                time.sleep(5)

    def _update_etc_hosts(self) -> None:
        cluster_name = self._cc["name"]
        api_name = f"api.{cluster_name}.redhat.com"
        api_ip = self._cc["api_ip"]
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
        nfs_server = common.extract_ip(lh.run("ip -json a").out, "eno3")

        host_name = worker["node"]
        print(f"Preparing BF on host {host_name}")
        h = host.RemoteHostWithBF2(host_name, worker["bmc_user"], worker["bmc_password"])
        skip_boot = False
        if h.ping():
            try:
                h.ssh_connect("core")
                d = h.os_release()
                print(d)
                skip_boot = d["NAME"] == 'Fedora Linux' and d['VARIANT'] == 'CoreOS'
            except paramiko.ssh_exception.AuthenticationException as e:
                print("Authentication failed, will not be able to skip boot")

        if skip_boot:
            print(f"Skipping booting {host_name}, already booted with FCOS")
        else:
            h.boot_iso_redfish(f"{nfs_server}:/root/iso/fedora-coreos.iso")
            time.sleep(10)
            h.ssh_connect("core")

        output = h.bf_pxeboot(iso, nfs_server)
        print(output)
        if output.returncode:
            print(f"Failed to run pxeboot on bf {host_name}")
            sys.exit(-1)
        else:
            print(f"succesfully ran pxeboot on bf {host_name}")

        ipa_json = output.out.strip().split("\n")[-1].strip()
        bf_interface = "enp3s0f0"
        try:
            ip = common.extract_ip(ipa_json, bf_interface)
            print(ip)
        except:
            ip = None
            print(f"Failed to find ip on {bf_interface}, output was {ipa_json}")
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

            d = lh.run("date").out.strip()
            if len(connections) != len(bf_workers):
                for e in filter(lambda x: x["name"] not in connections, bf_workers):
                    ai_ip = self._ai.get_ai_ip(e["name"])
                    if ai_ip is None:
                        continue
                    h = host.RemoteHost(ai_ip, None, None)
                    h.ssh_connect("core")
                    print(f'connected to {e["name"]}, setting user:pw')
                    h.run("echo root:redhat | sudo chpasswd")
                    connections[e["name"]] = h

            # Workaround: Time is not set and consequently HTTPS doesn't work
            for w in filter(lambda x: x["type"] == "bf", self._cc["workers"]):
                if w["name"] not in connections:
                    continue
                h = connections[w["name"]]
                h.run(f"sudo date -s '{d}'")

                # Workaround: images might become corrupt for an unknown reason. In that case, remove it to allow retries
                out = "".join(h.run("sudo podman images").out)
                e = re.search(r".*Top layer (\w+) of image (\w+) not found in layer tree. The storage may be corrupted, consider running", out)
                if e:
                    print(f'Removing corrupt image from worker {w["name"]}')
                    print(h.run(f"sudo podman rmi {e.group(2)}"))
                try:
                    out = "".join(h.run("sudo podman images --format json").out)
                    podman_images = json.loads(out)
                    for image in podman_images:
                        inspect_output = "".join(h.run(f"sudo podman image inspect {image['Id']}").out)
                        if "A storage corruption might have occurred" in inspect_output:
                            print("Corrupt image found")
                            h.run(f"sudo podman rmi {image['id']}")
                except Exception as e:
                    print(e)
                    pass

            time.sleep(10)
