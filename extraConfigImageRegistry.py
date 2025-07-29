from concurrent.futures import Future
from typing import Optional
from k8sClient import K8sClient
from logger import logger
from clustersConfig import ClustersConfig, ExtraConfigArgs
import host
from imageRegistry import InClusterRegistry, LocalRegistry, MicroshiftRegistry, RegistryType
from clusterStorage import create_cluster_storage, StorageType, HostPathStorage


def ExtraConfigImageRegistry(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to enable cluster registry")

    match cfg.registry_type:
        case RegistryType.IN_CLUSTER.value:
            # Reference documentation:
            # https://docs.openshift.com/container-platform/4.15/registry/configuring-registry-operator.html

            # Get registry node information
            registry_node = cc.get_registry_storage_node()

            logger.info(f"Using node '{registry_node.name}' for registry storage")

            registry_storage_size = cc.get_registry_storage_node().in_cluster_registry_storage_size
            # Create ClusterStorage instance targeting the specific registry node

            registry_storage_path = "/var/lib/registry-storage"
            cluster_storage = create_cluster_storage(kubeconfig_path=cc.kubeconfig, storage_type=StorageType.HOSTPATH, target_node_hostname=registry_node.name, storage_path=registry_storage_path)
            # Ensure we have HostPathStorage for registry storage
            if not isinstance(cluster_storage, HostPathStorage):
                logger.error_and_exit("Expected HostPathStorage implementation for registry storage")

            in_cluster_reg = InClusterRegistry(kubeconfig=cc.kubeconfig, storage=cluster_storage, storage_size=registry_storage_size)

            logger.info("Redeploying in-cluster registry...")
            in_cluster_reg.undeploy()
            cluster_storage.undeploy_storage()
            # Deploy storage foundation (StorageClass + directories)
            logger.info("Deploying storage foundation...")
            cluster_storage.deploy_storage()

            # Deploy in-cluster registry with configurable storage size
            logger.info("Deploying in-cluster registry...")
            in_cluster_reg.deploy()
            lh = host.LocalHost()
            ensure_test_images_in_registry(in_cluster_reg.get_url(), lh)

        case RegistryType.LOCAL.value:
            rh = host.LocalHost()
            client = K8sClient(cc.kubeconfig)
            local_reg = LocalRegistry(rh)
            local_reg.ensure_running(delete_all=True)
            local_reg.trust()
            local_reg.ocp_trust(client)
        case RegistryType.MICROSHIFT.value:
            # Get registry node information (usually the single master node for DPU clusters)

            registry_node = cc.get_registry_storage_node()
            logger.info(f"Using node '{registry_node.name}' for MicroShift registry storage")

            # Get remote host for the DPU node
            assert registry_node.ip is not None
            rh = host.RemoteHost(registry_node.ip)
            rh.ssh_connect("root", "redhat")
            # Set up storage configuration for MicroShift, in this case MicroShift already has HostPathStorage deployed so we just "attach" to it
            registry_storage_size = registry_node.in_cluster_registry_storage_size
            microshift_storage = HostPathStorage(kubeconfig_path=cc.kubeconfig, target_node_hostname=registry_node.name, storage_path="/var/lib/registry-storage")

            # Create MicroShift registry instance
            microshift_reg = MicroshiftRegistry(host=rh, kubeconfig=cc.kubeconfig, external_ip=registry_node.ip, storage=microshift_storage, storage_size=registry_storage_size)

            logger.info("Redeploying MicroShift registry...")
            # Undeploy existing registry, pv and pvc first
            microshift_reg.undeploy()

            logger.info("Deploying storage foundation for MicroShift registry...")
            k8s_client = K8sClient(cc.kubeconfig)
            k8s_client.oc("create namespace openshift-image-registry")

            # Deploy MicroShift registry
            logger.info("Deploying MicroShift registry...")
            microshift_reg.deploy()

            lh = host.LocalHost()
            # Trust the registry certificates on the remote host
            microshift_reg.trust(lh)
            ensure_test_images_in_registry(microshift_reg.get_url(), lh)
        case _:
            logger.error_and_exit(f"Invalid registry type: {cfg.registry_type}")


def ensure_test_images_in_registry(registry_url: str, host: host.Host) -> None:
    host.run_or_die(f"skopeo copy docker://ghcr.io/ovn-kubernetes/kubernetes-traffic-flow-tests:latest docker://{registry_url}/in-cluster-registry/kubernetes-traffic-flow-tests:latest")


def main() -> None:
    pass


if __name__ == "__main__":
    main()
