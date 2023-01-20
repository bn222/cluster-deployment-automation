import kubernetes
import yaml
import time
import host
import os
import requests

oc_url = "https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/"


class K8sClient():
    def __init__(self, kubeconfig):
        self._kc = kubeconfig
        with open(kubeconfig) as f:
            c = yaml.safe_load(f)
        self._api_client = kubernetes.config.new_client_from_config_dict(c)
        self._client = kubernetes.client.CoreV1Api(self._api_client)

    def is_ready(self, name):
        for e in self._client.list_node().items:
            for con in e.status.conditions:
                if con.type == "Ready":
                    if name == e.metadata.name:
                        return con.status == "True"
        return None

    def wait_ready(self, name):
        print(f"waiting for {name} to be ready")
        while True:
            if self.is_ready(name):
                break
            else:
                time.sleep(1)

    def approve_csr(self):
        certs_api = kubernetes.client.CertificatesV1Api(self._api_client)
        for e in certs_api.list_certificate_signing_request().items:
            if e.status.conditions is None:
                self.oc(f"adm certificate approve {e.name}")

    def get_ip(self, name):
        for e in self._client.list_node().items:
            if name == e.metadata.name:
                for addr in e.status.addresses:
                    if addr.type == "InternalIP":
                        return addr.address

    def oc(self, cmd):
        lh = host.LocalHost()

        assert os.path.exists("build")
        if not os.path.exists("build/oc"):
            print("downloading oc command")
            response = requests.get(oc_url + "openshift-client_linux.tar.gz")
            open("build/oc.tar.gz", "wb").write(response.content)
            lh.run("tar xf build/oc.tar.gz build/oc")
        return lh.run(f"build/oc {cmd} --kubeconfig {self._kc}")
