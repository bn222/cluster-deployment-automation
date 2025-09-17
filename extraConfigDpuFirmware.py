from clustersConfig import ClustersConfig
import host
from logger import logger
from clustersConfig import ExtraConfigArgs
from concurrent.futures import Future
from typing import Optional
import ipu
import dpuVendor


# Detect which DPU is running and ensure that the right version is in place, only works with IPU for now
def ExtraConfigDpuFirmware(cc: ClustersConfig, cfg: ExtraConfigArgs, _: dict[str, Future[Optional[host.Result]]]) -> None:
    logger.info("Running pre config step to flash MeV firmware on IPU IMC")

    # This preconfig step is expected to run on an IMC only
    assert cc.kind == "iso"
    master = cc.masters[0]
    assert master.kind == "dpu"
    assert master.bmc is not None
    assert master.bmc_host is not None

    dpu_bmc = dpuVendor.detect_dpu_maybe(master, get_external_port=cc.get_external_port)

    if isinstance(dpu_bmc, ipu.IPUBMC):
        dpu_bmc.ensure_firmware(cfg.force_firmware_update, cfg.mev_version)
    else:
        logger.warning("Skipping DPU firmware setup since it's not an IPU")
