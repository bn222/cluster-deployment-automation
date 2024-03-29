from clustersConfig import ClustersConfig
from k8sClient import K8sClient
from concurrent.futures import Future
from typing import Dict, Optional
from logger import logger
from clustersConfig import ExtraConfigArgs
import host


def ExtraConfigCustomOvn(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: Dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to build custom OVN from source")
    iclient = K8sClient(cc.kubeconfig)

    logger.info("Apply custom OVN daemonset")
    iclient.oc_run_or_die("project openshift-ovn-kubernetes")
    iclient.oc_run_or_die("create -f manifests/ovn/build_ovn_ds.yaml")

    # Wait for all build pods to become ready (the new image is available
    # then).
    iclient.oc_run_or_die(f"rollout status --timeout={cfg.custom_ovn_build_timeout} daemonset/ovn-from-source")

    logger.info("Custom OVN build done, deleting daemonset.")
    iclient.oc_run_or_die("delete daemonset ovn-from-source")


def main() -> None:
    pass


if __name__ == "__main__":
    main()
