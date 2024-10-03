import host
import common
from logger import logger
from arguments import PRE_STEP, MASTERS_STEP, POST_STEP
import isoCluster
from baseDeployer import BaseDeployer
from clustersConfig import ClustersConfig
import sys


class IsoDeployer(BaseDeployer):
    def __init__(self, cc: ClustersConfig, steps: list[str]):
        super().__init__(cc, steps)

        if len(self._cc.masters) != 1:
            logger.error("Masters must be of length one for deploying from iso")
            sys.exit(-1)
        self._master = self._cc.masters[0]
        self._futures[self._master.name] = common.empty_future(host.Result)
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
                # TODO: We need to either auto-detect the hardware (IPU versus some other vendor) or take this as an additional config param.
                isoCluster.IPUIsoBoot(self._cc, self._master, self._cc.install_iso)
            else:
                logger.info("Skipping master creation.")

        if POST_STEP in self.steps:
            self._postconfig()
        else:
            logger.info("Skipping post configuration.")
