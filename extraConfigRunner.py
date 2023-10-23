from extraConfigBFB import ExtraConfigBFB, ExtraConfigSwitchNicMode
from extraConfigSriov import ExtraConfigSriov, ExtraConfigSriovOvSHWOL, ExtraConfigSriovOvSHWOL_NewAPI
from extraConfigDpuTenant import ExtraConfigDpuTenantMC, ExtraConfigDpuTenant, ExtraConfigDpuTenant_NewAPI
from extraConfigDpuInfra import ExtraConfigDpuInfra, ExtraConfigDpuInfra_NewAPI
from extraConfigOvnK import ExtraConfigOvnK
from extraConfigCNO import ExtraConfigCNO
from extraConfigRT import ExtraConfigRT
from extraConfigDualStack import ExtraConfigDualStack
from clustersConfig import ClustersConfig
from concurrent.futures import Future
from typing import Dict
from logger import logger
import sys


class ExtraConfigRunner:
    def __init__(self, cc: ClustersConfig):
        self._cc = cc
        self._extra_config = {
            "bf_bfb_image": ExtraConfigBFB,
            "switch_to_nic_mode": ExtraConfigSwitchNicMode,
            "sriov_network_operator": ExtraConfigSriov,
            "sriov_ovs_hwol": ExtraConfigSriovOvSHWOL,
            "sriov_ovs_hwol_new_api": ExtraConfigSriovOvSHWOL_NewAPI,
            "dpu_infra": ExtraConfigDpuInfra,
            "dpu_infra_new_api": ExtraConfigDpuInfra_NewAPI,
            "dpu_tenant_mc": ExtraConfigDpuTenantMC,
            "dpu_tenant": ExtraConfigDpuTenant,
            "dpu_tenant_new_api": ExtraConfigDpuTenant_NewAPI,
            "ovnk8s": ExtraConfigOvnK,
            "cno": ExtraConfigCNO,
            "rt": ExtraConfigRT,
            "dualstack": ExtraConfigDualStack,
        }

    def run(self, to_run, futures: Dict[str, Future[None]]) -> None:
        if to_run["name"] not in self._extra_config:
            logger.info(f"{to_run['name']} is not an extra config")
            sys.exit(-1)
        else:
            logger.info(f"running extra config {to_run['name']}")
            self._extra_config[to_run['name']](self._cc, to_run, futures)
