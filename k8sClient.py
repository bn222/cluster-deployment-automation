import common
import kubernetes
import yaml
import time
import host
import os
import shlex
import sys
from typing import Optional
from typing import Callable
from logger import logger

oc_url = "https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/"


class K8sClient:
    def __init__(self, kubeconfig: Optional[str] = None):
        if kubeconfig is None:
            kubeconfig = os.environ.get("KUBECONFIG")
            if kubeconfig is None:
                raise ValueError("No kubeconfig given and KUBECONFIG environment not set")
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

    def oc(self, cmd: str, must_succeed: bool = False, *, with_kubeconfig: Optional[bool] = True) -> host.Result:
        lh = host.LocalHost()
        cmd = f"oc {cmd}"

        env: Optional[dict[str, Optional[str]]]
        if with_kubeconfig is None:
            # keep the caller's environment
            env = None
        elif with_kubeconfig:
            # Overwrite the KUBECONFIG variable.
            env = {"KUBECONFIG": self._kc}
        else:
            # Explicitly unset the variable (if set)
            env = {"KUBECONFIG": None}

        return lh.run(cmd, env=env, die_on_error=must_succeed)

    def oc_run_or_die(self, cmd: str) -> host.Result:
        return self.oc(cmd, must_succeed=True)

    def kubeadmin_login(self, *, cluster_name: Optional[str] = None, kubeadminpassword: Optional[str] = None) -> str:
        # The purpose of logging in as kubeadmin (compared to using the
        # kubeconfig certifiate) is that it allows is to get a login token.
        #
        # That token can then for example be used by `podman login` to
        # authenticate against the internal container registry.
        #
        # Here, we call `oc login` for the kubeadmin user. That records the
        # login session in "~/.kube/config", which we need to get rid with a
        # subsequent kubeadmin_logout().
        #
        # There should be a simpler (stateless) way to create a login token,
        # where we don't mess with ~/.kube/config and don't need a subsequent
        # logout (just a invalidation of the token). If you find it, please
        # contribute it.

        if kubeadminpassword is None:
            if cluster_name is None:
                raise ValueError("kubeadmin_login() needs either a \"cluster_name\" or a \"kubeadminpassword\" argument")
            kubeadminpassword = common.kubeconfig_read_kubeadminpassword(cluster_name, self._kc)

        serverurl = self.show_server()

        ret = self.oc(
            f"login {shlex.quote(serverurl)} -u kubeadmin -p {shlex.quote(kubeadminpassword)} --insecure-skip-tls-verify=true",
            with_kubeconfig=False,
        )
        if not ret.success():
            raise RuntimeError("Failure to login as kubeadmin: {ret}")

        ret = self.oc("whoami -t", with_kubeconfig=False)
        if not ret.success():
            raise RuntimeError("Failure to get token")

        return ret.out.strip()

    def kubeadmin_logout(self) -> None:
        # After kubeadmin_login(), logout again.
        self.oc("logout", with_kubeconfig=False)

        # Hm. This behaves strange. After logout, sometimes kubeconfig no longer
        # works. But login also may not work, depending on whether TLS is valid.
        # Hack around by issuing some logins.
        self.oc("login -u system:admin --insecure-skip-tls-verify=true")
        self.oc("login -u system:admin --insecure-skip-tls-verify=false")

        ret = self.oc("whoami")
        if not ret.success() or ret.out.strip() != "system:admin":
            raise RuntimeError("logout failed to restore login for \"system:admin\" user")

    def show_server(self) -> str:
        ret = self.oc("whoami --show-server")
        if not ret.success():
            raise RuntimeError(f"failure to get the server url: {ret}")
        return ret.out.strip()

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

    def clusterca_get(self, *, retry_timeout: float = 5 * 60) -> str:

        # Get the certificates from an authentication pod.
        # See https://access.redhat.com/solutions/6088891

        retry_started_at = time.monotonic()
        while True:
            try:
                ret = self.oc("get po -n openshift-authentication -o jsonpath='{.items[0].metadata.name}'")
                if not ret.success():
                    raise RuntimeError(f"failure to get name of authentication pod: {ret}")
                auth_pod = ret.out.strip()

                ret = self.oc(f"rsh -n openshift-authentication {auth_pod} cat /run/secrets/kubernetes.io/serviceaccount/ca.crt")
                if not ret.success():
                    raise RuntimeError(f"failure to get certificate from authentication pod {auth_pod}: {ret}")
            except RuntimeError:
                if time.monotonic() < retry_started_at + retry_timeout:
                    time.sleep(2)
                    continue
                raise

            return ret.out

    @staticmethod
    def clusterca_etc_filename(cluster_name: str) -> str:
        return f"/etc/pki/ca-trust/source/anchors/cda-ingress-ca-{cluster_name}.crt"

    def clusterca_trust(self, cluster_name: str, certificate: Optional[str] = None, rsh: Optional[host.Host] = None) -> str:
        if certificate is None:
            certificate = self.clusterca_get()
        self.clusterca_trust_on_host(cluster_name, certificate, rsh)
        return certificate

    @classmethod
    def clusterca_trust_on_host(
        cls,
        cluster_name: str,
        certificate: str,
        rsh: Optional[host.Host] = None,
        sudo: Optional[bool] = None,
    ) -> None:
        # Install the cluster's certificate authority as trusted.
        #
        # Warning: the certificate may not be well protected. Somebody could
        # get it, and use it to spoof TSL connections. This is not what you
        # would do on production system.
        #
        # https://access.redhat.com/solutions/6088891

        if rsh is None:
            rsh = host.LocalHost()

        ca_file = cls.clusterca_etc_filename(cluster_name)

        logger.info(f"Trust self signed certificate of cluster {cluster_name} on host {rsh.hostname()} (file {ca_file})")

        rsh.write(ca_file, certificate, sudo=sudo)
        rsh.run("update-ca-trust", sudo=sudo)
