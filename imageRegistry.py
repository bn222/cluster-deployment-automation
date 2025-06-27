import json
import shlex
import os
import host
import k8sClient
from logger import logger
from abc import ABC, abstractmethod
import itertools
import time
import base64
import binascii
from enum import Enum
import urllib.request
import urllib.error
import ssl

CONTAINER_NAME = "local-container-registry"


class OCPSystemRole(str, Enum):
    """Cluster-wide OpenShift system roles used for image registry permissions."""

    BUILDER = "system:image-builder"
    """Allows pushing images to the internal OpenShift image registry."""

    PULLER = "system:image-puller"
    """Allows pulling images from the internal OpenShift image registry."""

    AUTHENTICATED = "system:authenticated"
    """Represents any authenticated user or service account in the cluster."""


class BaseRegistry(ABC):
    def __init__(self, host: host.Host) -> None:
        self.host = host

    @abstractmethod
    def deploy(self) -> None:
        """Deploy and configure the registry."""
        pass

    @abstractmethod
    def trust(self, target: host.Host | None = None) -> None:
        """Configure trust for the registry's certificate on the target host (or self)."""
        pass

    @abstractmethod
    def get_url(self) -> str:
        """Return the URL or hostname:port of the registry."""
        pass


class LocalRegistry(BaseRegistry):
    def __init__(self, rsh: host.Host, listen_port: int = 5000) -> None:
        super().__init__(rsh)
        self.listen_port = listen_port
        self._registry_base_directory = rsh.home_dir(".local-container-registry")

        ret = rsh.run("hostname -f")
        hostname = ret.out.strip().lower()
        if not ret.success() or not hostname:
            raise RuntimeError("Failure to get hostname")
        self.hostname = hostname

    def certificate_path(self) -> str:
        return os.path.join(self._registry_base_directory, "certs")

    def get_url(self) -> str:
        return f"{self.hostname}:{self.listen_port}"

    def deploy(self) -> None:
        self.ensure_running()

    def ensure_running(self, *, delete_all: bool = False) -> tuple[str, int]:
        dir_name = self._registry_base_directory

        if self.host.run(f"podman inspect -f '{{{{.State.Running}}}}' {CONTAINER_NAME}").out == "true":
            return dir_name, self.listen_port
        else:
            self.host.run(f"podman start {CONTAINER_NAME}")

        ret = self.host.run(f"podman inspect {CONTAINER_NAME} --format '{{{{.Id}}}}'")
        if ret.success() and self.host.run(shlex.join(['test', '-d', dir_name])).success():
            if not delete_all:
                return dir_name, self.listen_port
            self._delete_all()

        self._create_registry_dirs(dir_name)
        self._generate_certificates()
        self._run_registry_container()

        return dir_name, self.listen_port

    def _create_registry_dirs(self, base: str) -> None:
        for subdir in ["certs", "data", "auth"]:
            self.host.run(shlex.join(["mkdir", "-p", os.path.join(base, subdir)]))

    def _generate_certificates(self) -> None:
        certs = self.certificate_path()
        self.host.run_or_die(
            shlex.join(
                [
                    "openssl",
                    "req",
                    "-newkey",
                    "rsa:4096",
                    "-nodes",
                    "-sha256",
                    "-keyout",
                    os.path.join(certs, "domain.key"),
                    "-x509",
                    "-days",
                    "365",
                    "-out",
                    os.path.join(certs, "domain.crt"),
                    "-subj",
                    f"/CN={self.hostname}",
                    "-addext",
                    f"subjectAltName = DNS:{self.hostname}",
                ]
            )
        )
        self.host.run(shlex.join(["ln", "-snf", "domain.crt", os.path.join(certs, "domain.cert")]))

    def _run_registry_container(self) -> None:
        certs = os.path.join(self._registry_base_directory, "certs")
        data = os.path.join(self._registry_base_directory, "data")
        auth = os.path.join(self._registry_base_directory, "auth")
        self.host.run_or_die(
            shlex.join(
                [
                    "podman",
                    "run",
                    "--name",
                    CONTAINER_NAME,
                    "-p",
                    f"{self.listen_port}:5000",
                    "-v",
                    f"{data}:/var/lib/registry:z",
                    "-v",
                    f"{auth}:/auth:z",
                    "-v",
                    f"{certs}:/certs:z",
                    "-e",
                    "REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt",
                    "-e",
                    "REGISTRY_HTTP_TLS_KEY=/certs/domain.key",
                    "-e",
                    "REGISTRY_COMPATIBILITY_SCHEMA1_ENABLED=true",
                    f"--annotation=LOCAL_CONTAINER_REGISTRY_HOSTNAME={self.hostname}",
                    "-d",
                    "docker.io/library/registry:latest",
                ]
            )
        )

    def _delete_all(self) -> None:
        self.host.run(shlex.join(["podman", "rm", "-f", CONTAINER_NAME]))
        self.host.run(shlex.join(["rm", "-rf", self._registry_base_directory]))

    def delete_all(self) -> None:
        self._delete_all()

    def trust(self, target: host.Host | None = None) -> None:
        target = target or self.host
        cert_dir = self.certificate_path()

        logger.info(f"trusting files in {cert_dir} and placing them on {target.hostname()}")
        certs = {f"{file}-{self.hostname}": self.host.read_file(os.path.join(cert_dir, file)) for file in os.listdir(cert_dir)}
        trust_certificates(target, certs)

    def ocp_trust(self, client: k8sClient.K8sClient) -> None:
        cm_name = f"local-container-registry-{self.hostname}"
        crt_file = os.path.join(self._registry_base_directory, 'certs/domain.crt')
        crt_data = self.host.read_file(crt_file)

        lh = host.LocalHost()
        lh.write("/tmp/crt", crt_data)
        logger.info(f"trusting registry running on {self.hostname} in ocp with file /tmp/crt")

        client.oc(f"delete cm -n openshift-config {shlex.quote(cm_name)}")
        client.oc_run_or_die(f"create cm -n openshift-config {cm_name} " f"--from-file={self.hostname}..{self.listen_port}=/tmp/crt")
        lh.remove("/tmp/crt")

        data = {"spec": {"additionalTrustedCA": {"name": cm_name}}}
        client.oc("patch image.config.openshift.io/cluster " f"--patch {shlex.quote(json.dumps(data))} --type=merge")


def ensure_local_registry_running(rsh: host.Host, delete_all: bool = False) -> LocalRegistry:
    logger.info(f"Ensuring local registry running on {rsh.hostname()}")
    reg = LocalRegistry(rsh)
    reg.ensure_running(delete_all=delete_all)
    reg.trust(host.LocalHost())
    return reg


class InClusterRegistry(BaseRegistry):
    def __init__(
        self,
        kubeconfig: str,
        allow_external_access: bool = True,
        namespace: str = "in-cluster-registry",
        sa: str = "pusher",
    ) -> None:
        super().__init__(host.LocalHost())
        self.kubeconfig = kubeconfig
        self.allow_external = allow_external_access
        self.namespace = namespace
        self.sa = sa
        self.client = k8sClient.K8sClient(self.kubeconfig, self.host)

    def deploy(self) -> None:
        self._wait_for_registry_operator_ready()
        self._configure_ocp_registry()
        self._wait_for_registry_default_route()
        self._ensure_project_and_sa()
        self._grant_roles()
        self.podman_authenticate()

    def trust(self, target: host.Host | None = None) -> None:
        # https://docs.redhat.com/en/documentation/openshift_container_platform/4.18/html/registry/securing-exposing-registry#registry-exposing-default-registry-manually_securing-exposing-registry
        route = self.get_url()
        cert_b64 = self.client.oc_run_or_die("get secret -n openshift-ingress  router-certs-default -o go-template='{{index .data \"tls.crt\"}}'").out.strip()
        try:
            cert = base64.b64decode(cert_b64, validate=True).decode()
        except (binascii.Error, UnicodeDecodeError) as e:
            raise ValueError(f"Invalid certificate data: {e}")

        target = target or self.host
        trust_certificates(target, {f"{route}.crt": cert})

    def get_url(self) -> str:
        return self.client.oc_run_or_die("get route default-route -n openshift-image-registry --template='{{ .spec.host }}'").out.strip()

    def _wait_for_registry_operator_ready(self, timeout: str = "20s") -> None:
        logger.info("Waiting for registry operator to be available")
        for tries in itertools.count():
            if self.client.oc(f"wait deployment/cluster-image-registry-operator -n openshift-image-registry --for=condition=Available=True --timeout={timeout}").success():
                logger.info(f"Registry operator ready after {tries} tries")
                break

    def _wait_for_registry_default_route(self, timeout: float = 10.0, max_tries: int = 5) -> None:
        logger.info("Waiting for registry default route")
        for tries in range(max_tries):
            if self.client.oc("get route default-route -n openshift-image-registry --template='{{ .spec.host }}'").success():
                logger.info(f"Route available after {tries + 1} tries")
                break
            time.sleep(timeout)
        else:
            raise RuntimeError("Registry default route not available")

    def _configure_ocp_registry(self) -> None:
        # https://docs.redhat.com/en/documentation/openshift_container_platform/4.18/html/registry/setting-up-and-configuring-the-registry#configuring-registry-storage-baremetal

        # Set management state to Managed and wait for it to be applied
        logger.info("Setting registry management state to Managed")
        self.client.oc_run_or_die("patch configs.imageregistry.operator.openshift.io cluster --type=merge --patch '{\"spec\":{\"managementState\":\"Managed\"}}'")
        self.client.oc_run_or_die("wait --for=jsonpath='{.spec.managementState}'=Managed configs.imageregistry.operator.openshift.io/cluster --timeout=5m")

        # Configure storage with emptyDir and wait for it to be applied
        logger.info("Configuring registry storage with emptyDir")
        self.client.oc_run_or_die("patch configs.imageregistry.operator.openshift.io cluster --type=merge --patch '{\"spec\":{\"storage\":{\"emptyDir\":{}}}}'")
        self.client.oc_run_or_die("wait --for=jsonpath='{.spec.storage.emptyDir}' configs.imageregistry.operator.openshift.io/cluster --timeout=5m")

        # Configure default route if external access is allowed
        if self.allow_external:
            logger.info("Enabling registry default route for external access")
            self.client.oc_run_or_die("patch configs.imageregistry.operator.openshift.io/cluster --type merge -p '{\"spec\":{\"defaultRoute\":true}}'")
            self.client.oc_run_or_die("wait --for=jsonpath='{.spec.defaultRoute}'=true configs.imageregistry.operator.openshift.io/cluster --timeout=5m")

        # Wait for the registry to be ready
        logger.info("Waiting for registry to be ready")
        self.client.oc_run_or_die("wait --for=jsonpath='{.status.readyReplicas}'=1 configs.imageregistry.operator.openshift.io/cluster --timeout=15m")

    def _ensure_project_and_sa(self) -> None:
        # We want to create an orginization (similar to quay.io) and credentials to push and pull from externally
        if not self.client.oc(f"get namespace {self.namespace}").success():
            self.client.oc_run_or_die(f"create namespace {self.namespace}")
        if not self.client.oc(f"get sa {self.sa} -n {self.namespace}").success():
            self.client.oc_run_or_die(f"create sa {self.sa} -n {self.namespace}")

    def _grant_roles(self) -> None:
        # The steps below are good for CI and headless automation systems since it ties it to service accounts, but for developers it could be better to scope it to their users by following this https://docs.redhat.com/en/documentation/openshift_container_platform/4.18/html/registry/accessing-the-registry#prerequisites
        self.client.oc_run_or_die(f"policy add-role-to-user {OCPSystemRole.BUILDER.value} system:serviceaccount:{self.namespace}:{self.sa} -n {self.namespace}")
        self.client.oc_run_or_die(f"policy add-role-to-group {OCPSystemRole.PULLER.value} {OCPSystemRole.AUTHENTICATED.value} -n {self.namespace}")

    def create_token(self) -> str:
        return self.client.oc_run_or_die(f"create token {self.sa} -n {self.namespace}").out.strip()

    def podman_authenticate(self) -> None:
        """
        Login to the in-cluster registry using Podman on the host with a token.
        """
        SECONDS = 1
        MINUTES = SECONDS * 60
        route = self.get_url()
        token = self.create_token()
        self.trust()
        self.client.oc_run_or_die("wait --for=jsonpath='{.status.readyReplicas}'=1 deployment/image-registry -n openshift-image-registry --timeout=2m")
        logger.info("Waiting on image registry service to be ready at the route through HTTP requests")
        wait_for_http_ready(f"https://{route}/v2/", timeout=6 * MINUTES)
        self.host.run_or_die(f"podman login -u {self.sa} -p {token} {route}")
        logger.info(f"Successfully logged into in-cluster registry at {route}")


def trust_certificates(host_obj: host.Host, certs: dict[str, str]) -> None:
    """
    Trust certificates by writing them to the system trust anchors and running update-ca-trust.

    :param host_obj: The host on which to trust the certs
    :param certs: Dict of {filename: cert_content} to be placed in anchors
    """
    for filename, content in certs.items():
        host_obj.write(f"/etc/pki/ca-trust/source/anchors/{filename}", content)
    host_obj.run_or_die("sudo update-ca-trust extract")


def wait_for_http_ready(url: str, timeout: int = 120, interval: int = 5, expected_codes: tuple[int, ...] = (200, 401, 403)) -> None:
    """
    Wait until the HTTP endpoint is reachable and returns an expected status code.

    Args:
        url (str): The URL to check.
        timeout (int): Max total wait time in seconds.
        interval (int): Time to wait between retries.
        expected_codes (tuple): Acceptable HTTP status codes.

    Raises:
        RuntimeError: If the URL is not ready within the timeout.
    """

    ctx = ssl._create_unverified_context()
    start = time.time()
    logger.info(f"Waiting for HTTP endpoint {url} to be reachable")
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, context=ctx) as response:
                if response.status in expected_codes:
                    logger.debug(f"[READY] {url} responded with status {response.status}")
                    return
        except urllib.error.HTTPError as e:
            if e.code in expected_codes:
                logger.debug(f"[READY] {url} responded with status {e.code}")
                return
            logger.debug(f"[WAITING] {url} returned HTTP {e.code}")
        except Exception as e:
            logger.debug(f"[WAITING] {url} not reachable: {e}")
        time.sleep(interval)

    raise RuntimeError(f"Timed out waiting for {url} to be ready.")
