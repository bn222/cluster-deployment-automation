from clustersConfig import ClustersConfig
from k8sClient import K8sClient
from logger import logger
from concurrent.futures import Future
from typing import Dict


def ExtraConfigRT(cc: ClustersConfig, _: Dict[str, str], futures: Dict[str, Future[None]]) -> None:
    [f.result() for (_, f) in futures.items()]

    is_sno = cc.is_sno()

    logger.info("Running post config command to install rt kernel on worker nodes")
    client = K8sClient(cc["kubeconfig"])

    resource = "sno-realtime.yaml" if is_sno else "worker-realtime.yaml"
    client.oc(f"create -f manifests/rt/{resource}")

    logger.info("Waiting for mcp to update")
    name = "master" if is_sno else "worker"
    client.wait_for_mcp(name, resource)


def main() -> None:
    pass


if __name__ == "__main__":
    main()
