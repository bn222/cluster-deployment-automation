from clustersConfig import ClustersConfig
from k8sClient import K8sClient
from configOperators import ConfigCVO
import sys
from concurrent.futures import Future
from typing import Dict
from logger import logger
from clustersConfig import ExtraConfigArgs


def ExtraConfigCNO(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: Dict[str, Future[None]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to load custom CNO")
    iclient = K8sClient(cc.kubeconfig)

    if cfg.image is None:
        logger.info("Error image not provided to load custom CNO")
        sys.exit(-1)

    image = cfg.image

    logger.info(f"Image {image} provided to load custom CNO")

    patch = f"""spec:
  template:
    spec:
      containers:
      - name: network-operator
        image: {image}
"""

    configCVO = ConfigCVO()
    configCVO.scaleDown(iclient)
    iclient.oc(f'patch -p "{patch}" deploy network-operator -n openshift-network-operator')


def main() -> None:
    pass


if __name__ == "__main__":
    main()
