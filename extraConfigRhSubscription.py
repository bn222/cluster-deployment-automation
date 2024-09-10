from concurrent.futures import Future, ThreadPoolExecutor
from typing import Optional
import sys
from logger import logger
from clustersConfig import ClustersConfig, NodeConfig
from clustersConfig import ExtraConfigArgs
import host
from extraConfigMicroshift import masquarade
from ktoolbox.common import unwrap


def ExtraConfigRhSubscription(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]

    lh = host.LocalHost()
    masquarade(lh, cc)

    logger.info("Running post config step to attach Red Hat subscription")

    def helper(node: NodeConfig) -> host.Result:
        logger.info(f"attaching subscription on {node.name}")
        assert node.ip is not None
        h = host.Host(node.ip)
        h.ssh_connect("root", "redhat")
        ret = h.run(f"rhc connect -o {unwrap(cfg.organization_id)} -a {unwrap(cfg.activation_key)}", quiet=True)
        return ret

    executor = ThreadPoolExecutor(max_workers=len(cc.all_nodes()))
    # Assume we are attaching subscription on all nodes

    f = []
    for node in cc.all_nodes():
        f.append(executor.submit(helper, node))

    for thread in f:
        ret = thread.result()
        logger.info(ret.out)
        if ret.returncode != 0:
            logger.error(f"Failed to attach subscription: {ret.err}")
            sys.exit(-1)
