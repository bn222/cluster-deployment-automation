from clustersConfig import ClustersConfig
import host
import coreosBuilder
from concurrent.futures import ThreadPoolExecutor
from nfs import NFS
from concurrent.futures import Future
from typing import Dict, Optional
import sys
from logger import logger
from clustersConfig import ExtraConfigArgs
from host import BMC

"""
The "ExtraConfigCX" is used to put the CX in a known good state. This is achieved by
1) Having a CoreOS Fedora image ready and mounted on NFS. This is needed for loading
a known good state on each of the workers.
2) Then SSH-ing into the load CoreOS Fedora image, we can run a pod with all the BF2
tools available. https://github.com/bn222/dpu-tools/
3) The scripts will try to update the firmware of the CX with mlxup.
4) Then the worker node is cold booted. This will also cold boot the CX.
"""


def ExtraConfigCX(cc: ClustersConfig, _: ExtraConfigArgs, futures: Dict[str, Future[Optional[host.Result]]]) -> None:
    coreosBuilder.ensure_fcos_exists()
    logger.info("Updating CX firmware on all workers")
    lh = host.LocalHost()
    nfs = NFS(lh, cc.external_port)
    iso_url = nfs.host_file("/root/iso/fedora-coreos.iso")

    def helper(h: host.HostWithCX) -> Optional[host.Result]:
        def check(result: host.Result) -> None:
            if result.returncode != 0:
                logger.info(result)
                sys.exit(-1)

        h.boot_iso_redfish(iso_url)
        h.ssh_connect("core")
        check(h.cx_firmware_upgrade())
        h.cold_boot()
        return None

    executor = ThreadPoolExecutor(max_workers=len(cc.workers))
    # Assuming all workers have CX that need to update their firmware
    for e in cc.workers:
        bmc = BMC.from_bmc(e.bmc, e.bmc_user, e.bmc_password)
        h = host.HostWithCX(e.node, bmc)
        futures[e.name].result()
        f = executor.submit(helper, h)
        futures[e.name] = f
    logger.info("CX setup complete")
