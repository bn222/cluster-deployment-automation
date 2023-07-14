from k8sClient import K8sClient
from logger import logger

class ConfigCVO:
    def scaleDown(self, client: K8sClient) -> None:
        logger.info("Scaling down the cluster-version-operator deployment.")
        client.oc("scale --replicas=0 deploy/cluster-version-operator -n openshift-cluster-version")

class ConfigCNO:
    def scaleDown(self, client: K8sClient) -> None:
        logger.info("Scaling down the cluster-network-operator deployment.")
        client.oc("scale --replicas=0 deploy/network-operator -n openshift-network-operator")


def main():
    pass


if __name__ == "__main__":
    main()
