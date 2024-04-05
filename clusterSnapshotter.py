from assistedInstaller import AssistedClientAutomation as ACA
from assistedInstallerService import AssistedInstallerService as AIS
from clustersConfig import ClustersConfig, NodeConfig
from clusterDeployer import ClusterDeployer
from clusterNode import VmClusterNode
import host
import os
from logger import logger
import coreosBuilder
from concurrent.futures import ThreadPoolExecutor
from nfs import NFS


def get_part_table(h: host.Host, drive: str) -> list[str]:
    fdisk_output = h.run(f"sudo fdisk -l {drive}").out.strip().split()
    parts = [x.split()[0] for x in fdisk_output if x.startswith(drive)]
    parts = [x for x in parts if ":" not in x]
    return parts


def fsarchiver() -> str:
    url = "quay.io/bnemeth/fsarchiver"
    return f"podman run --user 0 --privileged -v /mnt:/mnt -v /dev:/dev {url}"


class ClusterSnapshotter:
    def __init__(self, cc: ClustersConfig, ais: AIS, ai: ACA, name: str):
        self._ais = ais
        self._ai = ai
        self._cc = cc
        self._name = name

    def export_cluster(self) -> None:
        self._cc.prepare_external_port()
        lh = host.LocalHost()
        lh.run(f"mkdir -p {self._snapshot_dir()}")
        self._ais.export_snapshot(self._snapshot_dir())

        def save_phys(node: str) -> None:
            coreosBuilder.ensure_fcos_exists()
            rh = host.RemoteHost(node)
            nfs = NFS(host.LocalHost(), self._cc.external_port)
            file = nfs.host_file("/root/iso/fedora-coreos.iso")

            bmc = host.BMC.from_bmc(rh.hostname())
            bmc.boot_iso_redfish(file)

            logger.info(f"Backing up node {node}")
            rh.ssh_connect("core")
            rh.run("sudo mount /dev/sdb1 /mnt/")

            for e in get_part_table(rh, "/dev/sda"):
                name = os.path.basename(e)
                dest = f"/mnt/fsarchiver_backup.{name}.fsa"
                dest_dd = f"/mnt/{name}.dd"
                rh.run(f"sudo rm -f {dest} {dest_dd}")
                ret = rh.run(f"sudo {fsarchiver()} savefs {dest} {e}")
                logger.info(ret)
                if ret.returncode != 0:
                    rh.run(f"sudo dd if={e} of={dest_dd}")
            logger.info(f"Finished backing up node {node}")
            rh.run("sudo systemctl reboot")

        def save_vms() -> None:
            lh = host.LocalHost()
            vms = lh.run("virsh list --all --name").out.strip().split()
            for e in self._cc.all_vms():
                if e.name in vms:
                    self._export_vm(e)

        not_vms = [x for x in self._cc.all_nodes() if x.kind == "physical"]
        executor = ThreadPoolExecutor(max_workers=len(not_vms) + 1)
        futures = []
        for e in not_vms:
            futures.append(executor.submit(save_phys, e.node))
        futures.append(executor.submit(save_vms))
        for x in futures:
            x.result()

    def import_cluster(self) -> None:
        self._cc.prepare_external_port()
        self._ais.import_snapshot(self._snapshot_dir())
        ai_nodes = [h["requested_hostname"] for h in self._ai.list_hosts()]
        active_vms = [x for x in self._cc.all_vms() if x.name in ai_nodes]

        def load_vms() -> None:
            for e in active_vms:
                self._import_vm(e)

            lh = host.LocalHost()
            for e in active_vms:
                lh.run(f'virsh destroy {e.name}')
            for e in active_vms:
                lh.run(f'virsh start {e.name}')

        def load_phys(node: str) -> None:
            coreosBuilder.ensure_fcos_exists()
            rh = host.RemoteHost(node)
            nfs = NFS(host.LocalHost(), self._cc.external_port)
            file = nfs.host_file("/root/iso/fedora-coreos.iso")

            bmc = host.BMC.from_bmc(rh.hostname())
            bmc.boot_iso_redfish(file)

            logger.info(f"Restoring node {node}")
            rh.ssh_connect("core")
            rh.run("sudo mount /dev/sdb1 /mnt/")
            rh.run("sudo sfdisk /dev/sda < /mnt/sda")

            for e in get_part_table(rh, "/dev/sda"):
                name = os.path.basename(e)
                backup = f"/mnt/fsarchiver_backup.{name}.fsa"
                backup_dd = f"/mnt/{name}.dd"
                ret = rh.run(f"sudo {fsarchiver()} restfs {backup} id=0,dest=/{e}")
                logger.info(ret)
                if ret.returncode != 0:
                    rh.run(f"sudo dd if={backup_dd} of={e}")
            logger.info(f"Finished restorting node {node}")
            rh.run("sudo systemctl reboot")

        not_vms = [x for x in self._cc.all_nodes() if x.kind == "physical"]

        executor = ThreadPoolExecutor(max_workers=len(not_vms) + 1)
        futures = []
        for e in not_vms:
            futures.append(executor.submit(load_phys, e.node))
        futures.append(executor.submit(load_vms))
        for x in futures:
            x.result()

        self._ai.download_kubeconfig_and_secrets(self._cc.name, self._cc.kubeconfig)

    def _export_vm(self, config: NodeConfig) -> None:
        lh = host.LocalHost()
        src = config.image_path
        dst = os.path.join(self._snapshot_dir(), os.path.basename(src))
        logger.info(f"Copying {src} to {dst}")
        lh.copy_to(src, dst)

    def _import_vm(self, config: NodeConfig) -> None:
        lh = host.LocalHost()
        src = config.image_path
        os.makedirs(os.path.dirname(src), exist_ok=True)
        dst = os.path.join(self._snapshot_dir(), os.path.basename(src))
        logger.info(f"Copying {dst} to {src}")
        lh.copy_to(dst, src)
        VmClusterNode(lh, config).setup_vm(config.image_path)
        ClusterDeployer(self._cc, self._ai, [], "").update_etc_hosts()

    def _snapshot_dir(self) -> str:
        return os.path.join("/root/snapshots", self._name)
