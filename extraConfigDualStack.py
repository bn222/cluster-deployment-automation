from concurrent.futures import Future
from typing import Dict, Optional
from clustersConfig import ClustersConfig
from logger import logger
from k8sClient import K8sClient
from clustersConfig import ExtraConfigArgs
import host


def ExtraConfigDualStack(cc: ClustersConfig, _: ExtraConfigArgs, futures: Dict[str, Future[Optional[host.Result]]]) -> None:
    # https://docs.openshift.com/container-platform/4.13/networking/ovn_kubernetes_network_provider/converting-to-dual-stack.html
    # https://issues.redhat.com/browse/OCPBUGS-6040
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to load custom OVN-K")

    client = K8sClient(cc.kubeconfig)
    client.oc("patch network.config.openshift.io cluster --type='json' --patch-file manifests/patch_dual.yaml")

    ns = "openshift-cluster-node-tuning-operator"
    ret = client.oc(f"get pods -n {ns} -l openshift-app=tuned --field-selector=status.phase=Running --no-headers -o name")
    for i, pod in enumerate(ret.out.strip().split("\n")):
        client.oc(f"exec -n {ns} {pod} -- ip -6 addr add fd00:172:22::{i}/64 dev br-ex")
        client.oc(f"exec -n {ns} {pod} -- ip -6 route add default via fd00:172:22::1 dev br-ex")


def main() -> None:
    pass


if __name__ == "__main__":
    main()
