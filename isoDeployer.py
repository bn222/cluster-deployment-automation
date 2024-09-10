import host
import common
from logger import logger
from arguments import PRE_STEP, MASTERS_STEP, POST_STEP, WORKERS_STEP
import isoCluster
import ipu
from baseDeployer import BaseDeployer
from clustersConfig import ClustersConfig
from concurrent.futures import ThreadPoolExecutor
import timer
from ktoolbox.common import unwrap


class IsoDeployer(BaseDeployer):
    def __init__(self, cc: ClustersConfig, steps: list[str]):
        super().__init__(cc, steps)
        self._master = self._cc.cluster_config.single_master
        self._futures[self._master.name] = common.empty_future(host.Result)

    def deploy(self) -> None:
        duration = {k: timer.Timer() for k in self.steps}
        if PRE_STEP in self.steps:
            duration[PRE_STEP].start()
            self._preconfig()
            duration[PRE_STEP].stop()
        else:
            logger.info("Skipping pre configuration.")

        if MASTERS_STEP in self.steps:
            duration[MASTERS_STEP].start()
            self._deploy_master()
            duration[MASTERS_STEP].stop()
        else:
            logger.info("Skipping master creation.")
        duration[WORKERS_STEP].start_stop()

        if POST_STEP in self.steps:
            duration[POST_STEP].start()
            self._postconfig()
            duration[POST_STEP].stop()
        else:
            logger.info("Skipping post configuration.")
        for k, v in duration.items():
            logger.info(f"{k}: {v.duration()}")

    def _deploy_master(self) -> None:
        if self._master.kind == "ipu":
            node = ipu.IPUClusterNode(self._master, self._cc.get_external_port(), unwrap(self._cc.cluster_config.network_api_port))
            executor = ThreadPoolExecutor(max_workers=len(self._cc.masters))
            node.start(unwrap(self._cc.cluster_config.install_iso), executor)
            node.future.result()
        elif self._master.kind == "marvell-dpu":
            isoCluster.MarvellIsoBoot(self._cc, self._master, unwrap(self._cc.cluster_config.install_iso))
        else:
            raise ValueError(f"unexpected master kind {self._master.kind}")
