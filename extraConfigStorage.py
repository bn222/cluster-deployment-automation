from clustersConfig import ClustersConfig
from concurrent.futures import Future
from typing import Optional
from logger import logger
from clustersConfig import ExtraConfigArgs
import host
from clusterStorage import ClusterStorage


def ExtraConfigStorage(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to deploy cluster storage")

    # Deploy hostPath storage foundation (StorageClass + directories)
    storage = ClusterStorage(cc.kubeconfig)
    storage.undeploy_storage()
    storage.deploy_storage()

    logger.info("Cluster storage deployment completed successfully")


def main() -> None:
    pass


if __name__ == "__main__":
    main()
