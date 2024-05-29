from clustersConfig import ClustersConfig
from k8sClient import K8sClient
from concurrent.futures import Future
from typing import Optional
from logger import logger
from clustersConfig import ExtraConfigArgs
import host


def ExtraConfigMastersSchedulable(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    schedulable = "true" if cfg.schedulable else "false"
    logger.info(f"Running post config step to set \"mastersSchedulable\" to \"{schedulable}\".")
    iclient = K8sClient(cc.kubeconfig)

    iclient.oc_run_or_die(f"patch scheduler cluster --type merge -p '{{\"spec\":{{\"mastersSchedulable\":{schedulable}}}}}'")


def main() -> None:
    pass


if __name__ == "__main__":
    main()
