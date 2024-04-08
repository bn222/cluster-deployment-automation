from clustersConfig import ClustersConfig
from k8sClient import K8sClient
from configOperators import ConfigCVO
import sys
from concurrent.futures import Future
from typing import Optional
from logger import logger
from clustersConfig import ExtraConfigArgs
import host


def ExtraConfigOvnK(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to load custom OVN-K")
    iclient = K8sClient(cc.kubeconfig)

    if cfg.image is None:
        logger.info("Error image not provided to load custom OVN-K")
        sys.exit(-1)

    image = cfg.image

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
    iclient.oc_run_or_die(f'patch -p "{patch}" deploy network-operator -n openshift-network-operator')

    # To avoid a race between CNO restarting and rollout status checks
    # trigger a daemonset restart ourselves.
    iclient.oc_run_or_die("project openshift-ovn-kubernetes")
    iclient.oc_run_or_die("rollout restart daemonset/ovnkube-node")

    # Wait for the new image to roll out.
    iclient.oc_run_or_die(f"rollout status --timeout={cfg.ovnk_rollout_timeout} daemonset/ovnkube-node")


def main() -> None:
    pass


if __name__ == "__main__":
    main()
