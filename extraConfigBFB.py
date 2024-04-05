from clustersConfig import ClustersConfig
import host
import coreosBuilder
from concurrent.futures import ThreadPoolExecutor
from k8sClient import K8sClient
from nfs import NFS
from concurrent.futures import Future
from typing import Optional
import sys
from logger import logger
from clustersConfig import ExtraConfigArgs
from host import BMC

"""
The "ExtraConfigBFB" is used to put the BF2 in a known good state. This is achieved by
1) Having a CoreOS Fedora image ready and mounted on NFS. This is needed for loading
a known good state on each of the workers.
2) Then SSH-ing into the load CoreOS Fedora image, we can run a pod with all the BF2
tools available. https://github.com/bn222/bluefield-2-tools
3) The scripts will try to update the firmware of the BF2. Then defaults are applied,
just in case there are lingering configurations.
4) Then the worker node is cold booted. This will also cold boot the BF2.
5) Again the CoreOS Fedora image is used again. However this time we want the BF2
to be in a good state.
6) This is done by loading the DOCA Ubuntu BFB image officially supported by NVIDIA.
7) This is done via rshim to load the image.
"""


def ExtraConfigBFB(cc: ClustersConfig, _: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    coreosBuilder.ensure_fcos_exists()
    logger.info("Loading BF-2 with BFB image on all workers")
    lh = host.LocalHost()
    nfs = NFS(lh, cc.external_port)
    iso_url = nfs.host_file("/root/iso/fedora-coreos.iso")

    def helper(h: host.HostWithBF2, bmc: host.BMC) -> Optional[host.Result]:
        def check(result: host.Result) -> None:
            if result.returncode != 0:
                logger.info(result)
                sys.exit(-1)

        bmc.boot_iso_redfish(iso_url)
        h.ssh_connect("core")
        check(h.bf_firmware_upgrade())
        check(h.bf_firmware_defaults())
        bmc.cold_boot()
        bmc.boot_iso_redfish(iso_url)
        h.ssh_connect("core")
        check(h.bf_load_bfb())
        return None

    executor = ThreadPoolExecutor(max_workers=len(cc.workers))
    # Assuming that all workers have BF that need to reset to bfb image in
    # dpu mode
    for e in cc.workers:
        bmc = BMC.from_bmc(e.bmc, e.bmc_user, e.bmc_password)
        h = host.HostWithBF2(e.node)
        futures[e.name].result()
        f = executor.submit(helper, h, bmc)
        futures[e.name] = f
    logger.info("BFB setup complete")


def ExtraConfigSwitchNicMode(cc: ClustersConfig, _: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    client = K8sClient(cc.kubeconfig)

    client.oc("create -f manifests/nicmode/pool.yaml")

    # label nodes
    for e in cc.workers:
        logger.info(client.oc(f'label node {e.name} --overwrite=true feature.node.kubernetes.io/network-sriov.capable=true'))

    client.oc("delete -f manifests/nicmode/switch.yaml")
    client.oc("create -f manifests/nicmode/switch.yaml")
    logger.info("Waiting for mcp to update")
    client.wait_for_mcp("sriov", "switch.yaml")
