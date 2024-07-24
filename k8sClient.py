import kubernetes
import yaml
import time
import host
import sys
from typing import Optional
from typing import Callable
from logger import logger
from common import calculate_elapsed_time

oc_url = "https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/"


class K8sClient:
    def __init__(self, kubeconfig: str, host: host.Host = host.LocalHost()):
        self._kc = kubeconfig
        c = yaml.safe_load(host.read_file(kubeconfig))
        self._api_client = kubernetes.config.new_client_from_config_dict(c)
        self._client = kubernetes.client.CoreV1Api(self._api_client)
        self._host = host

    def is_ready(self, name: str) -> bool:
        for e in self._client.list_node().items:
            for con in e.status.conditions:
                if con.type == "Ready":
                    if name == e.metadata.name:
                        return str(con.status) == "True"
        return False

    def get_nodes(self) -> list[str]:
        return [e.metadata.name for e in self._client.list_node().items]

    def wait_ready(self, name: str, cb: Callable[[], None] = lambda : None) -> None:
        logger.info(f"waiting for {name} to be ready")
        while True:
            if self.is_ready(name):
                break
            else:
                time.sleep(1)
            cb()
            self.approve_csr()

    def wait_ready_all(self, cb: Callable[[], None] = lambda : None) -> None:
        for n in self.get_nodes():
            self.wait_ready(n, cb)

    def delete_node(self, node: str) -> None:
        logger.info(f"Deleting node {node}")
        self.oc(f"delete node {node}")

    def approve_csr(self) -> None:
        certs_api = kubernetes.client.CertificatesV1Api(self._api_client)
        for e in certs_api.list_certificate_signing_request().items:
            if e.status.conditions is None:
                self.oc(f"adm certificate approve {e.metadata.name}")

    def get_ip(self, name: str) -> Optional[str]:
        for e in self._client.list_node().items:
            if name == e.metadata.name:
                for addr in e.status.addresses:
                    if addr.type == "InternalIP":
                        return str(addr.address)
        return None

    def oc(self, cmd: str, must_succeed: bool = False) -> host.Result:
        cmd = f"oc {cmd} --kubeconfig {self._kc}"
        if must_succeed:
            return self._host.run_or_die(cmd)
        else:
            return self._host.run(cmd)

    def oc_run_or_die(self, cmd: str) -> host.Result:
        return self.oc(cmd, must_succeed=True)

    def wait_for_mcp(self, mcp_name: str, resource: str = "resource") -> None:
        time.sleep(60)
        iteration = 0
        max_tries = 10
        start = time.time()
        while True:
            ret = self.oc(f"wait mcp {mcp_name} --for condition=updated --timeout=20m")
            if ret.returncode == 0:
                break
            if iteration >= max_tries:
                logger.info(ret)
                logger.error(f"mcp {mcp_name} failed to update for {resource} after {max_tries}, quitting ...")
                sys.exit(-1)
            iteration = iteration + 1
            time.sleep(60)
        minutes, seconds = divmod(int(time.time() - start), 60)
        logger.info(f"It took {minutes}m {seconds}s for {resource} (attempts: {iteration})")

    def wait_for_all_mcp(self) -> None:
        time.sleep(60)
        iteration = 0
        max_tries = 10
        start = time.time()
        while True:
            ret = self.oc("wait mcp --for condition=updated --all --timeout=20m")
            if ret.returncode == 0:
                break
            if iteration >= max_tries:
                logger.info(ret)
                logger.error(f"Not all mcp updated after {max_tries}, quitting ...")
                sys.exit(-1)
            iteration = iteration + 1
            time.sleep(60)
        minutes, seconds = divmod(int(time.time() - start), 60)
        logger.info(f"It took {minutes}m {seconds}s for all mcp to be updated (attempts: {iteration})")

    def wait_for_crd(self, name: str, cr_name: str, namespace: str) -> None:
        logger.info(f"Waiting for crd {cr_name} to become available")
        ret = self.oc(f"get {cr_name}/{name} -n {namespace}")
        retries = 10
        while ret.returncode != 0:
            time.sleep(10)
            ret = self.oc(f"get {cr_name}/{name} -n {namespace}")
            retries -= 1
            if retries <= 0:
                logger.error_and_exit(f"Failed to get cr {cr_name}/{name}")

    def wait_for_all_pods_in_namespace(self, namespace: str, condition: str = "Ready") -> None:
        logger.info(f"Waiting for all pods in namespace {namespace} to be '{condition}'")
        it = 0
        retries = 3
        start = time.time()
        # Keep away any race conditions of waiting for pods before deployment is available
        self.wait_for_deployment(deployment_name="sriov-network-operator", namespace=namespace, condition="available")
        while True:
            # My tests show it generally takes about 5 minutes for all pods to be ready
            ret = self.oc(f"wait --for=condition={condition} --timeout=5m pods --all -n {namespace}")
            if ret.returncode == 0:
                break
            if it >= retries:
                logger.info(ret)
                logger.error(f"Not all pods in namespace {namespace} became '{condition}' after {retries} retries, quitting ...")
                sys.exit(-1)
            it = it + 1
            time.sleep(30)
        minutes, seconds = calculate_elapsed_time(start, time.time())
        logger.info(f"All pods in {namespace} are '{condition}'")
        logger.info(f"It took {minutes} m {seconds}s for all pods in {namespace} to be '{condition}' (attempts: {it})")

    def wait_for_deployment(self, deployment_name: str, namespace: str, condition: str) -> None:
        logger.info(f"Waiting for deployment in namespace {namespace} to be '{condition}'")
        retries = 3
        it = 0
        start = time.time()
        while it <= retries:
            ret = self.oc(f"wait --for condition={condition} --timeout=30s -n {namespace} deployments/{deployment_name}")
            if ret.returncode == 0:
                break
            it += 1
            if it > retries:
                logger.info(ret)
                logger.error(f"The all pods in namespace {namespace} failed to become '{condition}' after {retries}, quitting ...")
                sys.exit(-1)
            time.sleep(30)
        minutes, seconds = calculate_elapsed_time(start, time.time())
        logger.info(f"Deployment {deployment_name} in {namespace} are '{condition}'")
        logger.info(f"It took {minutes} m {seconds}s for deployments/{deployment_name} in {namespace} to be '{condition}' (attempts: {it})")
