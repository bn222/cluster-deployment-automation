from clustersConfig import ClustersConfig
from k8sClient import K8sClient
from configOperators import ConfigCVO
import sys
from concurrent.futures import Future
from typing import Dict
from logger import logger


def ExtraConfigOvnK(cc: ClustersConfig, cfg: Dict[str, str], futures: Dict[str, Future[None]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to load custom OVN-K")
    iclient = K8sClient(cc["kubeconfig"])

    if "image" not in cfg:
        logger.info("Error image not provided to load custom OVN-K")
        sys.exit(-1)

    image = cfg["image"]

    logger.info(f"Image {image} provided to load custom OVN-K")

    patch = f"""spec:
  template:
    spec:
      containers:
      - name: network-operator
        env:
        - name: OVN_IMAGE
          value: {image}
"""

    configCVO = ConfigCVO()
    configCVO.scaleDown(iclient)
    iclient.oc(f'patch -p "{patch}" deploy network-operator -n openshift-network-operator')

    # TODO: wait for all ovn-k pods to become ready again


def main() -> None:
    pass


if __name__ == "__main__":
    main()
