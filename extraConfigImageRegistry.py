from clustersConfig import ClustersConfig
from k8sClient import K8sClient
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

    client = K8sClient(cc.kubeconfig)
    client.oc_run_or_die("patch configs.imageregistry.operator.openshift.io cluster --type=merge --patch '{\"spec\":{\"managementState\":\"Managed\"}}'")
    client.oc_run_or_die("patch configs.imageregistry.operator.openshift.io cluster --type=merge --patch '{\"spec\":{\"storage\":{\"emptyDir\":{},\"managementState\":\"Managed\"}}}'")


def main() -> None:
    pass


if __name__ == "__main__":
    main()
