from extraConfigBFB import ExtraConfigBFB, ExtraConfigSwitchNicMode
from extraConfigSriov import ExtraConfigSriov, ExtraConfigSriovSubscription, ExtraConfigSriovOvSHWOL, ExtraConfigSriovOvSHWOL_NewAPI
from extraConfigDpuTenant import ExtraConfigDpuTenantMC, ExtraConfigDpuTenant, ExtraConfigDpuTenant_NewAPI
from extraConfigDpuInfra import ExtraConfigDpuInfra, ExtraConfigDpuInfra_NewAPI
from extraConfigOvnK import ExtraConfigOvnK
from extraConfigCustomOvn import ExtraConfigCustomOvn
from extraConfigImageRegistry import ExtraConfigImageRegistry
from extraConfigCNO import ExtraConfigCNO
from extraConfigRT import ExtraConfigRT
from extraConfigDualStack import ExtraConfigDualStack
from extraConfigCX import ExtraConfigCX
from clustersConfig import ClustersConfig
from clustersConfig import ExtraConfigArgs
from concurrent.futures import Future
from typing import Callable, Optional
from logger import logger
import sys
import host


class ExtraConfigRunner:
    def __init__(self, cc: ClustersConfig):
        self._cc = cc
        self._extra_config: dict[str, Callable[[ClustersConfig, ExtraConfigArgs, dict[str, Future[Optional[host.Result]]]], None]] = {
            "bf_bfb_image": ExtraConfigBFB,
            "switch_to_nic_mode": ExtraConfigSwitchNicMode,
            "sriov_network_operator": ExtraConfigSriov,
            "sriov_network_operator_subscription": ExtraConfigSriovSubscription,
            "sriov_ovs_hwol": ExtraConfigSriovOvSHWOL,
            "sriov_ovs_hwol_new_api": ExtraConfigSriovOvSHWOL_NewAPI,
            "dpu_infra": ExtraConfigDpuInfra,
            "dpu_infra_new_api": ExtraConfigDpuInfra_NewAPI,
            "dpu_tenant_mc": ExtraConfigDpuTenantMC,
            "dpu_tenant": ExtraConfigDpuTenant,
            "dpu_tenant_new_api": ExtraConfigDpuTenant_NewAPI,
            "ovnk8s": ExtraConfigOvnK,
            "ovn_custom": ExtraConfigCustomOvn,
            "image_registry": ExtraConfigImageRegistry,
            "cno": ExtraConfigCNO,
            "rt": ExtraConfigRT,
            "dualstack": ExtraConfigDualStack,
            "cx_firmware": ExtraConfigCX,
        }

    def run(self, to_run: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
        if to_run.name not in self._extra_config:
            logger.info(f"{to_run.name} is not an extra config")
            sys.exit(-1)
        else:
            logger.info(f"running extra config {to_run.name}")
            self._extra_config[to_run.name](self._cc, to_run, futures)
