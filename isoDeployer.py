import host
import common
from logger import logger
from arguments import PRE_STEP, MASTERS_STEP, POST_STEP
import marvell
import ipu
from baseDeployer import BaseDeployer
from clustersConfig import ClustersConfig
from concurrent.futures import ThreadPoolExecutor
from dpuVendor import detect_dpu
import sys
import dhcpConfig


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
        duration = self._empty_timers()
        if self._cc.masters:
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

        if POST_STEP in self.steps:
            duration[POST_STEP].start()
            self._postconfig()
            duration[POST_STEP].stop()
        else:
            logger.info("Skipping post configuration.")
        for k, v in duration.items():
            logger.info(f"{k}: {v.duration()}")

    def _deploy_master(self) -> None:
        self._setup_dhcp()
        assert self._master.kind == "dpu"
        assert self._master.bmc is not None
        dpu_kind = detect_dpu(self._master)
        if dpu_kind == "ipu":
            node = ipu.IPUClusterNode(self._master, self._cc.get_external_port(), self._cc.network_api_port)
            executor = ThreadPoolExecutor(max_workers=len(self._cc.masters))
            future = executor.submit(node.start, self._cc.install_iso)
            future.result()
            node.post_boot()
        elif dpu_kind == "marvell":
            marvell.MarvellIsoBoot(self._master, self._cc.install_iso)
        else:
            logger.error("Unknown DPU")
            sys.exit(-1)

    def _setup_dhcp(self) -> None:
        assert self._master.ip is not None
        dhcpConfig.configure_iso_network_port(self._cc.network_api_port, self._master.ip)
        dhcpConfig.configure_dhcpd(self._master)
