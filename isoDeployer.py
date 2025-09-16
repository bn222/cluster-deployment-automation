import host
import common
from logger import logger
from arguments import PRE_STEP, MASTERS_STEP, POST_STEP
import marvell
import ipu
from baseDeployer import BaseDeployer
from clustersConfig import ClustersConfig
from clusterNode import ClusterNode
from dpuVendor import detect_dpu
from state_file import StateFile
import sys
import dhcpConfig


class IsoDeployer(BaseDeployer):
    def __init__(self, cc: ClustersConfig, steps: list[str], state_file: StateFile, should_resume: bool):
        super().__init__(cc, steps)

        if len(self._cc.masters) != 1:
            logger.error("Masters must be of length one for deploying from iso")
            sys.exit(-1)
        self._master = self._cc.masters[0]
        self._futures[self._master.name] = common.empty_future(host.Result)
        self._validate()
        self.state = state_file
        if not should_resume:
            logger.info(f"Resetting state file at {self.state.path}")
            self.state.clear_state()

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
            if PRE_STEP in self.steps and not self.state.deployed("pre-step"):
                duration[PRE_STEP].start()
                self._preconfig()
                duration[PRE_STEP].stop()
                self.state["pre-step"] = "deployed"
            else:
                logger.info("Skipping pre configuration.")

            if MASTERS_STEP in self.steps and not self.state.deployed("masters"):
                duration[MASTERS_STEP].start()
                self._deploy_master()
                duration[MASTERS_STEP].stop()
                self.state["masters"] = "deployed"
            else:
                logger.info("Skipping master creation.")

        if POST_STEP in self.steps and not self.state.deployed("post-step"):
            duration[POST_STEP].start()
            self._postconfig()
            duration[POST_STEP].stop()
            self.state["post-step"] = "deployed"
        else:
            logger.info("Skipping post configuration.")
        for k, v in duration.items():
            logger.info(f"{k}: {v}")

    def _deploy_master(self) -> None:
        self._setup_networking()
        assert self._master.kind == "dpu"
        assert self._master.bmc is not None

        dpu_bmc = detect_dpu(self._master, get_external_port=self._cc.get_external_port)

        cluster_node: ClusterNode
        if isinstance(dpu_bmc, ipu.IPUBMC):
            cluster_node = ipu.IPUClusterNode(self._master, self._cc.get_external_port(), self._cc.network_api_port)
        elif isinstance(dpu_bmc, marvell.MarvellBMC):
            cluster_node = marvell.MarvellClusterNode(self._master)
        else:
            logger.error_and_exit("Unknown DPU")

        cluster_node.start(self._cc.install_iso)
        cluster_node.post_boot()

    def _setup_networking(self) -> None:
        assert self._master.ip is not None
        gw = common.ip_to_gateway(self._master.ip, "255.255.255.0")
        self.configure_iso_network_port(self._cc.network_api_port, gw)
        dhcpConfig.configure_dhcpd(self._master)

    def configure_iso_network_port(self, api_port: str, gateway_ip: str) -> None:
        lh = host.LocalHost()
        logger.info(f"Flushing cluster port {api_port} and setting ip to {gateway_ip}")
        lh.run_or_die(f"ip addr flush dev {api_port}")
        lh.run_or_die(f"ip addr add {gateway_ip}/24 dev {api_port}")
        lh.run(f"ip link set {api_port} up")
