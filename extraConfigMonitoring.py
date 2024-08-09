from clustersConfig import ClustersConfig
from k8sClient import K8sClient
from concurrent.futures import Future
from typing import Optional
from logger import logger
from clustersConfig import ExtraConfigArgs
import host


def ExtraConfigMonitoring(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to apply monitoring-config.yaml.")
    iclient = K8sClient(cc.kubeconfig)

    iclient.oc_run_or_die("apply -f manifests/monitoring-config.yaml")


def main() -> None:
    pass


if __name__ == "__main__":
    main()
