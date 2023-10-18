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
            "bf_bfb_image": ExtraConfigBFB(cc),
            "switch_to_nic_mode": ExtraConfigSwitchNicMode(cc),
            "sriov_network_operator": ExtraConfigSriov(cc),
            "sriov_ovs_hwol": ExtraConfigSriovOvSHWOL(cc),
            "sriov_ovs_hwol_new_api": ExtraConfigSriovOvSHWOL_NewAPI(cc),
            "dpu_infra": ExtraConfigDpuInfra(cc),
            "dpu_infra_new_api": ExtraConfigDpuInfra_NewAPI(cc),
            "dpu_tenant_mc": ExtraConfigDpuTenantMC(cc),
            "dpu_tenant": ExtraConfigDpuTenant(cc),
            "dpu_tenant_new_api": ExtraConfigDpuTenant_NewAPI(cc),
            "ovnk8s": ExtraConfigOvnK(cc),
            "cno": ExtraConfigCNO(cc),
            "rt": ExtraConfigRT(cc),
            "dualstack": ExtraConfigDualStack(cc),
        }

    def run(self, to_run, futures: Dict[str, Future]) -> None:
        if to_run["name"] not in self._extra_config:
            logger.info(f"{to_run['name']} is not an extra config")
            sys.exit(-1)
        else:
            logger.info(f"running extra config {to_run['name']}")
            self._extra_config[to_run['name']].run(to_run, futures)
