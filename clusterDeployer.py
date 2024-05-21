import itertools
import os
import sys
import time
import json
import shutil
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Optional
from typing import Generator
from typing import Union
from typing import Callable
import re
import logging
from assistedInstaller import AssistedClientAutomation
import host
from clustersConfig import ClustersConfig, ExtraConfigArgs
from k8sClient import K8sClient
import common
from python_hosts import Hosts, HostsEntry
from logger import logger
import microshift
from extraConfigRunner import ExtraConfigRunner
from clusterHost import ClusterHost
import dnsutil
from virshPool import VirshPool
from arguments import PRE_STEP, WORKERS_STEP, MASTERS_STEP, POST_STEP
import isoCluster


def match_to_proper_version_format(version_cluster_config: str) -> str:
    regex_pattern = r'^\d+\.\d+'
    match = re.match(regex_pattern, version_cluster_config)
    logger.info(f"getting version to match with format XX.X using regex {regex_pattern}")
    if not match:
        logger.error_and_exit(f"Invalid match {match}")
    return match.group(0)


class ClusterDeployer:
    def __init__(self, cc: ClustersConfig, ai: AssistedClientAutomation, steps: list[str], secrets_path: str):
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
        lh_config = list(filter(lambda hc: hc.name == lh.hostname(), self._cc.hosts))[0]
        self._local_host = ClusterHost(lh, lh_config, cc, cc.local_bridge_config)
        self._remote_hosts = {bm.name: ClusterHost(host.RemoteHost(bm.name), bm, cc, cc.remote_bridge_config) for bm in self._cc.hosts if bm.name != lh.hostname()}
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

    def _all_hosts_with_masters(self) -> set[ClusterHost]:
        return {ch for ch in self._all_hosts if len(ch.k8s_master_nodes) > 0}

    def _all_hosts_with_workers(self) -> set[ClusterHost]:
        return {ch for ch in self._all_hosts if len(ch.k8s_worker_nodes) > 0}

    def _all_hosts_with_only_workers(self) -> set[ClusterHost]:
        return {ch for ch in self._all_hosts if len(ch.k8s_worker_nodes) > 0 and not ch.k8s_master_nodes}

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

    def teardown_masters(self) -> None:
        cluster_name = self._cc.name
        if MASTERS_STEP not in self.steps:
            logger.info(f"Not tearing down {cluster_name}")
            return

        logger.info(f"Tearing down {cluster_name}")
        self._ai.ensure_cluster_deleted(self._cc.name)

        self.update_dnsmasq(setup=False)

        for h in self._all_hosts_with_masters():
            h.teardown_nodes(h.k8s_master_nodes)

        self._ai.ensure_infraenv_deleted(f"{cluster_name}-x86_64")
        self._ai.ensure_infraenv_deleted(f"{cluster_name}-arm64")

        self._local_host.bridge.remove_dhcp_entries(self._cc.master_vms())

        image_paths = {os.path.dirname(n.image_path) for n in self._cc.local_vms()}
        for image_path in image_paths:
            vp = VirshPool(
                name=os.path.basename(image_path),
                rsh=self._local_host.hostconn,
            )
            vp.ensure_removed()

        for h in self._all_hosts_with_masters():
            h.ensure_not_linked_to_network()

        AssistedClientAutomation.delete_kubeconfig_and_secrets(self._cc.name, self._cc.kubeconfig)

    def teardown_workers(self) -> None:
        cluster_name = self._cc.name

        # If workers not in steps (and masters set), teardown the workers to avoid dangling vms.
        if WORKERS_STEP in self.steps and MASTERS_STEP not in self.steps:
            logger.info(f"Tearing down (some) workers on {cluster_name}")
        elif MASTERS_STEP in self.steps:
            logger.info(f"Tearing down (some) workers on {cluster_name} before tearing down masters")
        else:
            return

        for h in self._all_hosts_with_workers():
            h.teardown_nodes(h.k8s_worker_nodes)

        self._local_host.remove_dhcp_entries(self._cc.worker_vms())

        # Find whether the host will still hosts some vms after tearing down what's configured.
        for h in self._all_hosts_with_only_workers():
            installed_vms = []
            if h.hosts_vms:
                installed_vms = h.hostconn.run("virsh list --all --name").out.strip().split()
            if not installed_vms:
                h.ensure_not_linked_to_network()
            else:
                logger.debug(f"bridge not unlinked as {installed_vms} remaining on {h.config.name}")

        # if masters in steps, following steps are not needed as tearing down masters take care of this.
        if MASTERS_STEP in self.steps:
            return

        for w in self._cc.workers:
            logger.info(f"Deleting worker {w.name}")
            self.client().delete_node(w.name)
            self._ai.delete_host(w.name)

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

    def need_external_network(self) -> bool:
        vm_bm = [x for x in self._cc.workers if x.kind == "vm" and x.node != "localhost"]
        remote_workers = len(self._cc.workers) - len(self._cc.worker_vms())
        remote_masters = len(self._cc.masters) - len(self._cc.master_vms())
        if WORKERS_STEP not in self.steps:
            remote_workers = 0
        if MASTERS_STEP not in self.steps:
            remote_masters = 0
        return remote_masters != 0 or remote_workers != 0 or len(vm_bm) != 0

    def deploy(self) -> None:
        if self._cc.masters:
            if PRE_STEP in self.steps:
                self._preconfig()
            else:
                logger.info("Skipping pre configuration.")

            if self._cc.kind != "microshift":
                if WORKERS_STEP in self.steps or MASTERS_STEP in self.steps:
                    self.teardown_workers()
                if MASTERS_STEP in self.steps:
                    self.teardown_masters()
                    self.create_cluster()
                    self.create_masters()
                else:
                    logger.info("Skipping master creation.")

                if WORKERS_STEP in self.steps:
                    if len(self._cc.workers) != 0:
                        self.create_workers()
                    else:
                        logger.info("No worker to setup. Skip")
                else:
                    logger.info("Skipping worker creation.")
        if self._cc.kind == "microshift":
            version = match_to_proper_version_format(self._cc.version)

            if len(self._cc.masters) == 1:
                microshift.deploy(self._cc.fullConfig["name"], self._cc.masters[0], self._cc.external_port, version)
            else:
                logger.error_and_exit("Masters must be of length one for deploying microshift")
        if POST_STEP in self.steps:
            self._postconfig()
            cmd = "apply -f manifests/monitoring-config.yaml"
            self.client().oc_run_or_die(cmd)
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
        self._cc.validate_node_ips()

    def _get_status(self, name: str) -> Optional[str]:
        h = self._ai.get_ai_host(name)
        return h.status if h is not None else None

    def _wait_known_state(self, names_gen: Generator[str, None, None], cb: Callable[[], None] = lambda: None) -> None:
        names = list(names_gen)
        logger.info(f"Waiting for {names} to be in \'known\' state")
        status: dict[str, Optional[str]] = {n: "" for n in names}
        while not all(v == "known" for v in status.values()):
            new_status: dict[str, Optional[str]] = {n: self._get_status(n) for n in names}
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
        cfg: dict[str, Union[str, bool, list[str], list[dict[str, str]]]] = {}
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
        self._local_host.bridge.setup_dhcp_entries(self._cc.master_vms())

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
            h.wait_for_masters_boot(self._cc.full_ip_range)

        def cb() -> None:
            finished = [p for p in futures if p.done()]
            for f in finished:
                result = f.result()
                if result is not None and result.returncode != 0:
                    raise Exception(f"Can't install masters {result}")

        names = (e.name for e in self._cc.masters)
        self._wait_known_state(names, cb)
        self._ai.start_until_success(cluster_name)

        self._ai.download_kubeconfig_and_secrets(self._cc.name, self._cc.kubeconfig)

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
            h.ensure_linked_to_network(self._local_host.bridge)

        logger.info("Setting password to for root to redhat")
        for h in hosts_with_masters:
            for master in h.k8s_master_nodes:
                master.set_password()

        self.update_dnsmasq()

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

        self._local_host.setup_dhcp_entries(self._cc.worker_vms())
        for h in hosts_with_workers:
            h.ensure_linked_to_network(self._local_host.bridge)

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
            h.wait_for_workers_boot(self._cc.full_ip_range)

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

    def _rename_workers(self, infra_env: str) -> None:
        logger.info("Waiting for connectivity to all workers")
        hosts = []
        workers = []
        for bm in self._all_hosts:
            for k8s_node in bm.k8s_worker_nodes:
                rh = host.RemoteHost(k8s_node.ip())
                rh.ssh_connect("core")
                hosts.append(rh)
                workers.append(k8s_node)

        ip_range = self._cc.full_ip_range
        logger.info(f"Connectivity established to all workers; checking that they have an IP in range: {ip_range}")

        def any_address_in_range(h: host.Host, ip_range: tuple[str, str]) -> bool:
            for ipaddr in common.ip_addrs(h):
                for ainfo in ipaddr.addr_info:
                    if ainfo.family != "inet":
                        continue
                    if not common.ip_range_contains(ip_range, ainfo.local):
                        continue
                    return True
            return False

        any_worker_bad = False
        for w, h in zip(workers, hosts):
            if not any_address_in_range(h, ip_range):
                logger.error(f"Worker {w.config.name} doesn't have an IP in range {ip_range}.")
                any_worker_bad = True

        if any_worker_bad:
            sys.exit(-1)

        logger.info("Connectivity established to all workers, renaming them in Assisted installer")
        logger.info(f"looking for workers with ip {[w.ip() for w in workers]}")
        for try_count in itertools.count(0):
            renamed = self._try_rename_workers(infra_env)
            expected = len(workers)
            if renamed == expected:
                logger.info(f"Found and renamed {renamed} workers")
                break
            if renamed:
                logger.info(f"Found and renamed {renamed} workers, but waiting for {expected}, retrying (try #{try_count})")
                time.sleep(5)

    def _try_rename_workers(self, infra_env: str) -> int:
        infra_env_id = self._ai.get_infra_env_id(infra_env)
        renamed = 0

        for bm in self._all_hosts:
            for k8s_node in bm.k8s_worker_nodes:
                for h in filter(lambda x: x["infra_env_id"] == infra_env_id, self._ai.list_hosts()):
                    if "inventory" not in h:
                        continue
                    nics = json.loads(h["inventory"]).get("interfaces")
                    addresses: list[str] = sum((nic["ipv4_addresses"] for nic in nics), [])
                    stripped_addresses = [a.split("/")[0] for a in addresses]

                    if k8s_node.ip() in stripped_addresses:
                        self._ai.update_host(h["id"], {"name": k8s_node.config.name})
                        logger.info(f"renamed {k8s_node.config.name}")
                        renamed += 1
        return renamed

    def _get_discovery_ign_ssh_priv_key(self, infra_env: str) -> str:
        self._ai.download_discovery_ignition(infra_env, "/tmp")

        # In a provisioning system where there could be multiple keys, it is not guaranteed that
        # AI will use id_rsa. Thus we need to properly extract the key from the discovery ignition.
        ssh_priv_key = "/root/.ssh/id_rsa"
        with open(os.path.join("/tmp", f"discovery.ign.{infra_env}")) as f:
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

    def update_dnsmasq(self, *, setup: bool = True) -> None:
        cluster_name = self._cc.name
        if setup:
            api_vip = self._ai.get_ai_cluster_info(cluster_name).api_vip
        else:
            api_vip = None
        dnsutil.dnsmasq_update(cluster_name, api_vip)

    def wait_for_workers(self) -> None:
        logger.info(f'waiting for {len(self._cc.workers)} workers')
        lh = host.LocalHost()
        bf_workers = [x for x in self._cc.workers if x.kind == "bf"]
        connections: dict[str, host.Host] = {}
        for try_count in itertools.count(0):
            workers = [w.name for w in self._cc.workers]
            n_not_ready_workers = sum(1 for w in workers if not self.client().is_ready(w))
            if n_not_ready_workers == 0:
                break

            logger.info(f"Not all workers ready (try #{try_count}). {n_not_ready_workers} are not ready yet.")
            self.client().approve_csr()

            if len(connections) != len(bf_workers):
                for e in filter(lambda x: x.name not in connections, bf_workers):
                    ai_ip = self._ai.get_ai_ip(e.name, self._cc.full_ip_range)
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


class IsoDeployer(ClusterDeployer):
    def __init__(self, cc: ClustersConfig, steps: list[str]):
        self.steps = steps
        self._cc = cc
        self._extra_config = ExtraConfigRunner(cc)

        if len(self._cc.masters) != 1:
            logger.error("Masters must be of length one for deploying from iso")
            sys.exit(-1)
        self._master = self._cc.masters[0]

        def empty() -> Future[Optional[host.Result]]:
            f: Future[Optional[host.Result]] = Future()
            f.set_result(None)
            return f

        self._futures = {self._master.name: empty()}
        self._validate()

    def _validate(self) -> None:
        if self._master.mac is None:
            logger.error_and_exit(f"No MAC address provided for cluster {self._cc.name}, exiting")
        if self._master.ip is None:
            logger.error_and_exit(f"No IP address provided for cluster {self._cc.name}, exiting")
        if self._master.name is None:
            logger.error_and_exit(f"No name provided for cluster {self._cc.name}, exiting")
        if not self._cc.network_api_port or self._cc.network_api_port == "auto":
            logger.error_and_exit(f"Network API port with connection to {self._cc.name} must be specified, exiting")

    def deploy(self) -> None:
        if self._cc.masters:
            if PRE_STEP in self.steps:
                self._preconfig()
            else:
                logger.info("Skipping pre configuration.")

            if MASTERS_STEP in self.steps:
                isoCluster.IPUIsoBoot(self._cc, self._master, self._cc.install_iso)
            else:
                logger.info("Skipping master creation.")

        if POST_STEP in self.steps:
            self._postconfig()
        else:
            logger.info("Skipping post configuration.")
