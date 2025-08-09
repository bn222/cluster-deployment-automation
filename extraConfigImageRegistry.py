from concurrent.futures import Future
from typing import Optional
from logger import logger
from clustersConfig import ClustersConfig, ExtraConfigArgs
import host
from imageRegistry import InClusterRegistry, LocalRegistry, RegistryType
from clusterStorage import create_cluster_storage, StorageType


def ExtraConfigImageRegistry(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to enable cluster registry")

    if cfg.registry_type == RegistryType.IN_CLUSTER.value:
        # Reference documentation:
        # https://docs.openshift.com/container-platform/4.15/registry/configuring-registry-operator.html

        # Get registry node information
        registry_node = cc.get_registry_storage_node()

        logger.info(f"Using node '{registry_node.name}' for registry storage")

        # Create ClusterStorage instance targeting the specific registry node
        from clusterStorage import HostPathStorage
        registry_storage_path = "/var/lib/registry-storage"

        cluster_storage = create_cluster_storage(kubeconfig_path=cc.kubeconfig, storage_type=StorageType.HOSTPATH, target_node_hostname=registry_node.name, storage_path=registry_storage_path)
        # Cast to specific type to access HostPath-specific methods
        hostpath_storage = cluster_storage if isinstance(cluster_storage, HostPathStorage) else None
        if not hostpath_storage:
            logger.error_and_exit("Expected HostPathStorage implementation for registry storage")
        in_cluster_reg = InClusterRegistry(kubeconfig=cc.kubeconfig, storage=hostpath_storage)

        logger.info("Redeploying in-cluster registry...")
        in_cluster_reg.undeploy()
        cluster_storage.undeploy_storage()
        # Deploy storage foundation (StorageClass + directories)
        logger.info("Deploying storage foundation...")
        cluster_storage.deploy_storage()

        # Create persistent volume for registry storage
        logger.info("Creating persistent volume for registry storage...")
        registry_storage_size = cc.get_registry_storage_node().in_cluster_registry_storage_size
        hostpath_storage.create_pv_with_node_affinity(pv_name="registry-pv", storage_size=registry_storage_size, storage_path=registry_storage_path)

        # Deploy in-cluster registry with configurable storage size
        logger.info("Deploying in-cluster registry...")
        in_cluster_reg.deploy()

    elif cfg.registry_type == RegistryType.LOCAL.value:
        lh = host.LocalHost()
        local_reg = LocalRegistry(lh)
        local_reg.deploy()


def main() -> None:
    pass


if __name__ == "__main__":
    main()
