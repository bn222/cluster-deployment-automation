import sys
import os
from concurrent.futures import Future
from concurrent.futures import ThreadPoolExecutor
from typing import Dict
from typing import List
from logger import logger
from clustersConfig import ClustersConfig
from clustersConfig import ExtraConfigArgs
import host
import common
import urllib.parse


"""
ExtraConfigIPU is used to provision and IPUs specified via Redfish through the IMC.
This works by making some assumptions about the current state of the IPU:
- The IMC is on MeV 1.2 / Mev 1.3
- BMD_CONF has been set to allow for iso Boot
- ISCSI attempt has been added to allow for booting into the installed media
- The specified ISO contains full installation kickstart / kargs required for automated boot
- The specified ISO architecture is aarch64
"""


def is_http_url(url: str) -> bool:
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


def _redfish_boot_ipu(cc: ClustersConfig, imcs: List[str], iso: str) -> None:
    def helper(imc: str) -> str:
        logger.info(f"Booting {imc} with {iso_address}")
        bmc = host.BMC.from_bmc(imc)
        bmc.boot_iso_redfish(iso_path=iso_address, retries=5, retry_delay=15)
        # TODO: We need a way to monitor when the installation is complete
        # since the acc will not have connectivity on reboot
        return f"Finished booting imc {imc}"

    # If an http address is provided, we will boot from here.
    # Otherwise we will assume a local file has been provided and host it.
    if is_http_url(iso):
        logger.debug(f"Booting IPU from iso served at {iso}")
        iso_address = iso
        executor = ThreadPoolExecutor(max_workers=len(imcs))
        f = []
        for imc in imcs:
            f.append(executor.submit(helper, imc))

        for thread in f:
            logger.info(thread.result())
    else:
        logger.debug(f"Booting IPU from local iso {iso}")
        if not os.path.exists(iso):
            logger.error(f"ISO file {iso} does not exist, exiting")
            sys.exit(-1)
        serve_path = os.path.dirname(iso)
        iso_name = os.path.basename(iso)
        lh = host.LocalHost()
        cc.prepare_external_port()
        lh_ip = common.port_to_ip(lh, cc.external_port)

        with common.HttpServerManager(serve_path, 8000) as http_server:
            iso_address = f"http://{lh_ip}:{str(http_server.port)}/{iso_name}"
            executor = ThreadPoolExecutor(max_workers=len(imcs))
            f = []
            for imc in imcs:
                f.append(executor.submit(helper, imc))

            for thread in f:
                logger.info(thread.result())


def ExtraConfigIPUIsoBoot(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: Dict[str, Future[None]]) -> None:
    logger.info("Running post config step to provision IPUs")

    if cfg.ipu_imcs is None:
        logger.error("Error no IMCs were provided to provision, exiting")
        sys.exit(-1)

    # TODO: The user should not have to provide the iso, we should make a call to pull / build the iso from CDA
    if cfg.ipu_iso is None:
        logger.error("No ISO file was provided to install on the IMCs, exiting")
        sys.exit(-1)

    _redfish_boot_ipu(cc, cfg.ipu_imcs, cfg.ipu_iso)


def IPUIsoBoot(cc: ClustersConfig, imc: str, iso: str) -> None:
    logger.info(f"Running ISO boot of IPU {imc} with {iso}")
    _redfish_boot_ipu(cc, [imc], iso)


def main() -> None:
    pass


if __name__ == "__main__":
    main()
