from k8sClient import K8sClient
from logger import logger


def apply_common_pathches(client: K8sClient):
    patch_dns(client)
    patch_ingress(client)
    patch_monitoring(client)


def patch_dns(client: K8sClient):
    logger.info("Apply dns patch")
    client.oc("patch --type=merge --patch='{\"spec\":{\"nodePlacement\": {\"nodeSelector\": "
              "{\"node-role.kubernetes.io/master\": \"\"}}}}' dns.operator/default")


def patch_ingress(client: K8sClient):
    logger.info("Apply ingress patch")
    client.oc("patch --type=merge --patch='{\"spec\":{\"nodePlacement\": {\"nodeSelector\": {\"matchLabels\": "
              "{\"node-role.kubernetes.io/master\": \"\"}}}}}' "
              "-n openshift-ingress-operator  ingresscontroller/default")


def patch_monitoring(client: K8sClient):
    logger.info("Apply monitoring patches")
    client.oc("create -f manifests/common/monitor-patch-cm.yaml")
