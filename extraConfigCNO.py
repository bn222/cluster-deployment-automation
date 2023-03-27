from k8sClient import K8sClient
from configCVO import ConfigCVO
import sys


class ExtraConfigCNO:
    def __init__(self, cc):
        self._cc = cc

    def run(self, cfg):
        print("Running post config step to load custom CNO")
        iclient = K8sClient(self._cc["kubeconfig"])

        if "image" not in cfg:
            print("Error image not provided to load custom CNO")
            sys.exit(-1)

        image = cfg["image"]

        print(f"Image {image} provided to load custom CNO")

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


def main():
    pass


if __name__ == "__main__":
    main()
