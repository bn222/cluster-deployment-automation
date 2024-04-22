from clustersConfig import ClustersConfig
from k8sClient import K8sClient
from concurrent.futures import Future
from typing import Optional
from logger import logger
from clustersConfig import ExtraConfigArgs
import host
import itertools


def ExtraConfigImageRegistry(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to enable cluster registry")

    # Reference documentation:
    # https://docs.openshift.com/container-platform/4.15/registry/configuring-registry-operator.html

    client = K8sClient(cc.kubeconfig)
    client.oc_run_or_die("patch configs.imageregistry.operator.openshift.io cluster --type=merge --patch '{\"spec\":{\"managementState\":\"Managed\"}}'")
    client.oc_run_or_die("patch configs.imageregistry.operator.openshift.io cluster --type=merge --patch '{\"spec\":{\"storage\":{\"emptyDir\":{},\"managementState\":\"Managed\"}}}'")

    # Wait for the change to rollout and for the operators to be ready.
    client.oc_run_or_die("wait --for=jsonpath='{.status.readyReplicas}'=1 configs.imageregistry.operator.openshift.io/cluster")
    timeout = "30s"
    logger.info("Waiting for all cluster operators to be aavailable, not progressing, not degraded")

    for tries in itertools.count(0):
        rc1 = client.oc(f"wait co --all --for='condition=AVAILABLE=True' --timeout={timeout}")
        rc2 = client.oc(f"wait co --all --for='condition=PROGRESSING=False' --timeout={timeout}")
        rc3 = client.oc(f"wait co --all --for='condition=DEGRADED=False' --timeout={timeout}")
        if rc1.success() and rc2.success() and rc3.success():
            logger.info(f"All cluster operators ready after {tries} tries, at {timeout} intervals")
            break


def main() -> None:
    pass


if __name__ == "__main__":
    main()
