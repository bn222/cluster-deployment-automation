from git import Repo
from k8sClient import K8sClient
import os
import host
import time


class ExtraConfigOvnK:
    def __init__(self, cc):
        self._cc = cc

    def run(self, cfg):
        print("Running post config step to load custom ovn-k")
        iclient = K8sClient("/root/kubeconfig.infracluster")

        patch = f"""spec:
  template:
    spec:
      containers:
      - name: network-operator
        env:
        - name: OVN_IMAGE
          value: {cfg["image"]}
"""

        iclient.oc("scale --replicas=0 deploy/cluster-version-operator -n openshift-cluster-version")
        iclient.oc(f'patch -p "{patch}" deploy network-operator -n openshift-network-operator')

        # TODO: wait for all ovn-k pods to become ready again

def main():
    pass


if __name__ == "__main__":
    main()
