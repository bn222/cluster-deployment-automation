from clustersConfig import ClustersConfig
import host
from logger import logger
from clustersConfig import ExtraConfigArgs
from bmc import BMC
from concurrent.futures import Future
from typing import Optional
import time
import ipu

LATEST_MEV_FW = "1.8.0.10052"


def ExtraConfigMevFwUp(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    logger.info("Running pre config step to flash MeV firmware on IPU IMC")

    # This preconfig step is expected to run on an IMC only
    assert cc.kind == "iso"
    master = cc.masters[0]
    assert master.kind == "dpu"
    assert master.bmc is not None
    ipu_bmc = ipu.IPUBMC(master.bmc)
    assert ipu_bmc.is_ipu()

    assert master.host_side_bmc is not None
    assert master.bmc is not None
    imc = host.Host(master.bmc.url)

    # Check if a particular firmware version is being requested or if we will use default
    if cfg.mev_version == "":
        logger.info("Desired MeV fw release not specified, will install the latest by default")
        cfg.mev_version = LATEST_MEV_FW
    logger.info(f"Will ensure {master.bmc} is on firmware version: {cfg.mev_version}")

    # We should only perform an update if it is required, or if the user insists we do so
    if not cfg.force_mev_fw_up:
        logger.info("Checking if firmware update is required")
        if imc.ping():
            imc.ssh_connect(master.bmc.user, master.bmc.password)
            ret = imc.run("cat /etc/issue.net")
            if cfg.mev_version in ret.out:
                logger.info(f"Current MeV fw version is {ret.out.strip()}, no need to update")
                return

    # Perform upgrade
    lh = host.LocalHost()

    logger.info("Starting flash of SSD/SPI (this will take some time ~40min)")
    fw_up_cmd = f"--dpu-type ipu --imc-address {master.bmc} firmware up --version {cfg.mev_version}"
    ret = lh.run_in_container(fw_up_cmd, interactive=True)

    if not ret.success():
        logger.error_and_exit(f"Failed to flash new firmware. Error: {ret.err}")

    # Perform coldboot to apply the change
    ipu_host_bmc = BMC.from_bmc(master.host_side_bmc)
    ipu_host_bmc.cold_boot()
    # Cold boot should also reboot IMC, give time to settle before trying to ping IMC
    time.sleep(20)

    # Access the IMC to validate the flash was successful
    imc.ssh_connect(master.bmc.user, master.bmc.password)
    ret = imc.run("cat /etc/issue.net")
    if cfg.mev_version not in ret.out or ret.returncode != 0:
        logger.error_and_exit(f"Mev firmware release is not the expected version: {ret.out}")

    logger.info("MeV firmware flash complete")
