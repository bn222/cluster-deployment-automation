from assistedInstaller import AssistedClientAutomation
from assistedInstallerService import AssistedInstallerService
from clustersConfig import ClustersConfig
from clusterDeployer import setup_vm
import host
import os
from logger import logger


class ClusterSnapshotter:
    def __init__(self, cc: ClustersConfig, ais: AssistedInstallerService, ai: AssistedClientAutomation, name: str):
        self._ais = ais
        self._ai = ai
        self._cc = cc
        self._name = name

    def export_cluster(self):
        lh = host.LocalHost()
        lh.run(f"mkdir -p {self._snapshot_dir()}")
        self._ais.export_snapshot(self._snapshot_dir())

        lh = host.LocalHost()
        vms = lh.run("virsh list --all --name").out.strip().split()
        for e in self._cc.all_vms():
            if e["name"] in vms:
                self._export_vm(e)

    def import_cluster(self):
        self._ais.import_snapshot(self._snapshot_dir())

        ai_nodes = [h["requested_hostname"] for h in self._ai.list_hosts()]
        active_vms = [x for x in self._cc.all_vms() if x["name"] in ai_nodes]

        for e in active_vms:
            self._import_vm(e)

        lh = host.LocalHost()
        for e in active_vms:
            lh.run(f'virsh destroy {e["name"]}')
        for e in active_vms:
            lh.run(f'virsh start {e["name"]}')
        self._ai.download_kubeconfig(self._cc["name"], self._cc["kubeconfig"])

    def _export_vm(self, config):
        lh = host.LocalHost()
        src = config["image_path"]
        dst = os.path.join(self._snapshot_dir(), os.path.basename(src))
        logger.info(f"Copying {src} to {dst}")
        lh.copy(src, dst)

    def _import_vm(self, config):
        lh = host.LocalHost()
        src = config["image_path"]
        dst = os.path.join(self._snapshot_dir(), os.path.basename(src))
        logger.info(f"Copying {dst} to {src}")
        lh.copy(dst, src)
        setup_vm(lh, config, config["image_path"])

    def _snapshot_dir(self):
        return os.path.join("/root/snapshots", self._name)
