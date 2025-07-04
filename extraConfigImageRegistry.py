from clustersConfig import ClustersConfig
from imageRegistry import InClusterRegistry
from concurrent.futures import Future
from typing import Optional
from logger import logger
from clustersConfig import ExtraConfigArgs
import host


def ExtraConfigImageRegistry(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to enable cluster registry")

    # Reference documentation:
    # https://docs.openshift.com/container-platform/4.15/registry/configuring-registry-operator.html

    reg = InClusterRegistry(cc.kubeconfig)
    reg.deploy()


def main() -> None:
    pass


if __name__ == "__main__":
    main()
