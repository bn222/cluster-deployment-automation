from clustersConfig import ClustersConfig
from imageRegistry import InClusterRegistry, LocalRegistry, RegistryType
from concurrent.futures import Future
from typing import Optional
from logger import logger
from clustersConfig import ExtraConfigArgs
import host
from clusterStorage import ClusterStorage


def ExtraConfigImageRegistry(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to enable cluster registry")

    if cfg.registry_type == RegistryType.IN_CLUSTER.value:
        # Reference documentation:
        # https://docs.openshift.com/container-platform/4.15/registry/configuring-registry-operator.html
        storage = ClusterStorage(cc.kubeconfig)
        in_cluster_reg = InClusterRegistry(cc.kubeconfig, storage_class=storage.get_storage_class_name())

        logger.info("Redeploying in-cluster registry...")
        in_cluster_reg.undeploy()
        storage.undeploy_storage()

        # Deploy storage foundation (StorageClass + directories)
        logger.info("Deploying storage foundation...")
        storage.deploy_storage()

        # Deploy in-cluster registry with configurable storage size
        logger.info("Deploying in-cluster registry...")
        registry_storage_size = getattr(cc, 'in_cluster_registry_storage_size', '10Gi')
        in_cluster_reg = InClusterRegistry(cc.kubeconfig, storage_class=storage.get_storage_class_name(), storage_size=registry_storage_size)
        in_cluster_reg.deploy()

    elif cfg.registry_type == RegistryType.LOCAL.value:
        lh = host.LocalHost()
        local_reg = LocalRegistry(lh)
        local_reg.deploy()


def main() -> None:
    pass


if __name__ == "__main__":
    main()
