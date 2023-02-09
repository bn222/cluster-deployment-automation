import kubernetes
import yaml
import time
import host
import os
import requests

oc_url = "https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/"


class K8sClient():
    def __init__(self, kubeconfig: str):
        self._kc = kubeconfig
        with open(kubeconfig) as f:
            c = yaml.safe_load(f)
        self._api_client = kubernetes.config.new_client_from_config_dict(c)
        self._client = kubernetes.client.CoreV1Api(self._api_client)
        self.ensure_oc_binary()

    def is_ready(self, name: str) -> bool:
        for e in self._client.list_node().items:
            for con in e.status.conditions:
                if con.type == "Ready":
                    if name == e.metadata.name:
                        return con.status == "True"
        return False

    def get_nodes(self) -> str:
        return [e.metadata.name for e in self._client.list_node().items]

    def wait_ready(self, name: str) -> None:
        print(f"waiting for {name} to be ready")
        while True:
            if self.is_ready(name):
                break
            else:
                time.sleep(1)
            self.approve_csr()

    def approve_csr(self) -> None:
        certs_api = kubernetes.client.CertificatesV1Api(self._api_client)
        for e in certs_api.list_certificate_signing_request().items:
            if e.status.conditions is None:
                self.oc(f"adm certificate approve {e.metadata.name}")

    def get_ip(self, name: str) -> str:
        for e in self._client.list_node().items:
            if name == e.metadata.name:
                for addr in e.status.addresses:
                    if addr.type == "InternalIP":
                        return addr.address

    def oc(self, cmd: str) -> host.Result:
        lh = host.LocalHost()
        return lh.run(f"{self.oc_bin} {cmd} --kubeconfig {self._kc}")

    def ensure_oc_binary(self) -> None:
        lh = host.LocalHost()
        assert os.path.exists("build")
        if not os.path.isfile(os.path.join(os.getcwd(), "build/oc")):
            url = oc_url + "openshift-client-linux.tar.gz"
            print(f"downloading oc command from {url} since it's missing from {os.getcwd() + '/build'}")
            response = requests.get(url)
            open("build/oc.tar.gz", "wb").write(response.content)
            lh.run("tar xf build/oc.tar.gz -C build")
            lh.run("rm build/oc.tar.gz")
        self.oc_bin = os.path.join(os.getcwd(), "build/oc")
