import common
import kubernetes
import yaml
import time
import host
import sys
from typing import Optional
from typing import Callable
from logger import logger

oc_url = "https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/"


class K8sClient:
    def __init__(self, kubeconfig: str):
        self._kc = kubeconfig
        with open(kubeconfig) as f:
            c = yaml.safe_load(f)
        self._api_client = kubernetes.config.new_client_from_config_dict(c)
        self._client = kubernetes.client.CoreV1Api(self._api_client)

    def is_ready(self, name: str) -> bool:
        for e in self._client.list_node().items:
            for con in e.status.conditions:
                if con.type == "Ready":
                    if name == e.metadata.name:
                        return str(con.status) == "True"
        return False

    def get_nodes(self) -> list[str]:
        return [e.metadata.name for e in self._client.list_node().items]

    def wait_ready(self, name: str, cb: Optional[Callable[[], None]] = None) -> None:
        logger.info(f"waiting for {name} to be ready")
        while True:
            if self.is_ready(name):
                break
            else:
                time.sleep(1)
            if cb:
                cb()
            self.approve_csr()

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
        lh = host.LocalHost()
        cmd = f"oc {cmd} --kubeconfig {self._kc}"
        if must_succeed:
            return lh.run_or_die(cmd)
        else:
            return lh.run(cmd)

    def oc_run_or_die(self, cmd: str) -> host.Result:
        return self.oc(cmd, must_succeed=True)

    def wait_for_mcp(self, mcp_name: str, resource: str = "resource") -> None:
        time.sleep(60)
        iteration = 0
        max_tries = 10
        start = time.monotonic()
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
        logger.info(f"It took {common.seconds_to_str(time.monotonic() - start)} for {resource} (attempts: {iteration})")
