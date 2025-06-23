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
from typing import Optional
import urllib.request
import urllib.error
import ssl
import timer


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
    def trust(self, target: Optional[host.Host] = None) -> None:
        """Configure trust for the registry's certificate on the target host (or self)."""
        pass

    @abstractmethod
    def get_url(self) -> str:
        """Return the URL or hostname:port of the registry."""
        pass

    def _create_ocp_trust_configmap(self, client: k8sClient.K8sClient, cm_name: str, cert_data: str, cert_key: str) -> None:
        """
        Create a ConfigMap with certificate data and configure image config to trust it.
        Args:
            client: K8s client for running oc commands
            cm_name: Name of the ConfigMap to create
            cert_data: Certificate data (PEM format)
            cert_key: Key name for the certificate in the ConfigMap (e.g., hostname, route)
        """
        lh = host.LocalHost()
        temp_cert_path = "/tmp/ocp-trust-cert.crt"
        lh.write(temp_cert_path, cert_data)
        logger.info(f"Creating ConfigMap {cm_name} with certificate for {cert_key}")

        client.oc(f"delete cm -n openshift-config {shlex.quote(cm_name)}")
        client.oc_run_or_die(f"create cm -n openshift-config {cm_name} --from-file={cert_key}={temp_cert_path}")
        lh.remove(temp_cert_path)

        data = {"spec": {"additionalTrustedCA": {"name": cm_name}}}
        client.oc_run_or_die(f"patch image.config.openshift.io/cluster --patch {shlex.quote(json.dumps(data))} --type=merge")


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

    def trust(self, target: Optional[host.Host] = None) -> None:
        target = target or self.host
        cert_dir = self.certificate_path()

        logger.info(f"trusting files in {cert_dir} and placing them on {target.hostname()}")
        certs = {f"{file}-{self.hostname}": self.host.read_file(os.path.join(cert_dir, file)) for file in os.listdir(cert_dir)}
        trust_certificates(target, certs)

    def ocp_trust(self, client: k8sClient.K8sClient) -> None:
        cm_name = f"local-container-registry-{self.hostname}"
        crt_file = os.path.join(self._registry_base_directory, 'certs/domain.crt')
        crt_data = self.host.read_file(crt_file)
        cert_key = f"{self.hostname}..{self.listen_port}"

        logger.info(f"trusting registry running on {self.hostname} in ocp")
        super()._create_ocp_trust_configmap(client, cm_name, crt_data, cert_key)


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
        self._ensure_project_and_sa()
        self._grant_roles()
        self.podman_authenticate()

    def trust(self, target: Optional[host.Host] = None) -> None:
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
        result = self.client.oc("get route default-route -n openshift-image-registry --template='{{ .spec.host }}'")
        if result.success():
            return result.out.strip()
        else:
            raise RuntimeError("Registry default route not found - ensure registry is deployed with external access enabled")

    def _wait_for_registry_operator_ready(self, timeout: str = "20s") -> None:
        logger.info("Waiting for registry operator to be available")
        for tries in itertools.count():
            if self.client.oc(f"wait deployment/cluster-image-registry-operator -n openshift-image-registry --for=condition=Available=True --timeout={timeout}").success():
                logger.info(f"Registry operator ready after {tries} tries")
                break

    def _wait_for_registry_default_route(self, timeout: str = "10s", max_tries: int = 5) -> None:
        logger.info("Waiting for registry default route")
        for tries in range(max_tries):
            if self.client.oc("get route default-route -n openshift-image-registry --template='{{ .spec.host }}'").success():
                logger.info(f"Route available after {tries + 1} tries")
                return
            if tries < max_tries - 1:  # Don't wait after the last attempt
                logger.debug(f"Route not ready, waiting {timeout} (attempt {tries + 1}/{max_tries})")
                wait_timer = timer.Timer(timeout)
                while not wait_timer.triggered():
                    time.sleep(0.1)  # Small sleep to prevent busy waiting
        raise RuntimeError("Registry default route not available")

    def _create_router_ca_configmap(self) -> str:
        """Create a ConfigMap with the router CA certificate for image registry trust."""
        cm_name = "registry-router-ca"
        route = self.get_url()
        assert route is not None

        # Get the router certificate from the default router secret
        cert_b64 = self.client.oc_run_or_die("get secret -n openshift-ingress router-certs-default -o go-template='{{index .data \"tls.crt\"}}'").out.strip()
        try:
            cert_data = base64.b64decode(cert_b64, validate=True).decode()
        except (binascii.Error, UnicodeDecodeError) as e:
            raise ValueError(f"Invalid certificate data: {e}")

        # Use the reusable _create_ocp_trust_configmap method from base class
        logger.info(f"Configuring image config to trust router certificate for {route}")
        super()._create_ocp_trust_configmap(self.client, cm_name, cert_data, route)

        return cm_name

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

            # Wait for the route to be created before trying to use it
            self._wait_for_registry_default_route()

            # Configure image config to trust router certificates
            logger.info("Configuring image config to trust router certificates")
            cm_name = self._create_router_ca_configmap()
            self.client.oc_run_or_die(f"wait --for=jsonpath='{{.spec.additionalTrustedCA.name}}'={cm_name} image.config.openshift.io/cluster --timeout=5m")

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
        """
        Create a very long-lived token for dev/CI purposes (10 years - effectively permanent).

        Duration rationale:
        - Default 'oc create token' duration is only 1 hour, which is too short for dev/CI
        - We use 87600h (10 years) to avoid token expiration during development cycles
        - This is safe for non-production environments where convenience > security
        - Long-lived tokens prevent authentication failures in CI pipelines
        - 10 years is effectively permanent for any reasonable development lifecycle

        """
        return self.client.oc_run_or_die(f"create token {self.sa} -n {self.namespace} --duration=87600h").out.strip()

    def podman_authenticate(self) -> None:
        """
        Login to the in-cluster registry using Podman on the host with a token.
        """
        route = self.get_url()
        token = self.create_token()
        self.trust()
        self.client.oc_run_or_die("wait --for=jsonpath='{.status.readyReplicas}'=1 deployment/image-registry -n openshift-image-registry --timeout=2m")
        logger.info("Waiting on image registry service to be ready at the route through HTTP requests")
        wait_for_http_ready(f"https://{route}/v2/", timeout="6m")

        # Clear any existing registry credentials to prevent login conflicts
        # This prevents issues where users might have logged in with incorrect URLs like {route}/{namespace}
        logger.info(f"Clearing any existing registry credentials for {route}")
        self.host.run(f"podman logout {route}")
        # Also try to logout from common incorrect formats
        self.host.run(f"podman logout {route}/{self.namespace}")

        # Perform the correct login
        logger.info(f"Logging into registry at {route}")
        self.host.run_or_die(f"podman login -u {self.sa} -p {token} {route}")

        logger.info(f"Successfully logged into in-cluster registry at {route}")
        logger.info(f"To push images, use format: podman push <image> {route}/{self.namespace}/<image-name>:<tag>")
        logger.info(f"Note: namespace '{self.namespace}' is used in image URLs, NOT in login URLs even though it might give a false positive")

    def _podman_logout(self) -> None:
        """Logout from the in-cluster registry using Podman"""
        logger.info("Logging out from in-cluster registry")

        try:
            route = self.get_url()
            # Clear registry credentials to prevent login conflicts
            logger.info(f"Logging out from registry at {route}")
            self.host.run(f"podman logout {route}")
            # Also try to logout from common incorrect formats that might exist
            self.host.run(f"podman logout {route}/{self.namespace}")
            logger.info("Successfully logged out from in-cluster registry")
        except Exception as e:
            logger.warning(f"Failed to logout from registry (may not have been logged in): {e}")

    def _remove_project_and_sa(self) -> None:
        """Remove the project namespace and service account"""
        logger.info(f"Removing project namespace '{self.namespace}' and service account '{self.sa}'")

        # Remove role bindings first
        logger.info("Removing role bindings...")
        self.client.oc(f"policy remove-role-from-user {OCPSystemRole.BUILDER.value} system:serviceaccount:{self.namespace}:{self.sa} -n {self.namespace}")
        self.client.oc(f"policy remove-role-from-group {OCPSystemRole.PULLER.value} {OCPSystemRole.AUTHENTICATED.value} -n {self.namespace}")

        # Remove the entire namespace (this also removes the service account)
        logger.info(f"Deleting namespace '{self.namespace}'...")
        result = self.client.oc(f"delete namespace {self.namespace} --ignore-not-found --timeout=60s")
        if result.success():
            logger.info(f"Namespace '{self.namespace}' deleted successfully")
        else:
            logger.warning(f"Failed to delete namespace '{self.namespace}': {result.out}")

    def _restore_ocp_registry_defaults(self) -> None:
        """Restore the OpenShift registry to default configuration"""
        logger.info("Restoring OpenShift registry to default configuration")

        # Clean up registry storage using comprehensive cleanup
        logger.info("Cleaning up registry storage resources...")

        # Reset registry to OpenShift defaults
        logger.info("Resetting registry management state to Removed (OpenShift default)...")
        self.client.oc_run_or_die("patch configs.imageregistry.operator.openshift.io cluster --type=merge --patch '{\"spec\":{\"managementState\":\"Removed\"}}' ")
        self.client.oc_run_or_die("wait --for=jsonpath='{.spec.managementState}'=Removed configs.imageregistry.operator.openshift.io/cluster --timeout=5m")

        # Remove any storage configuration completely (restore to no storage config)
        logger.info("Removing all storage configuration (restore to OpenShift default)...")
        self.client.oc_run_or_die("patch configs.imageregistry.operator.openshift.io cluster --type=json -p '[{\"op\": \"remove\", \"path\": \"/spec/storage\"}]' ")
        self.client.oc_run_or_die("wait --for=jsonpath='{.spec.storage}'=null configs.imageregistry.operator.openshift.io/cluster --timeout=5m")

        # Disable default route (restore to OpenShift default)
        logger.info("Disabling default route (restore to OpenShift default)...")
        self.client.oc_run_or_die("patch configs.imageregistry.operator.openshift.io cluster --type=merge --patch '{\"spec\":{\"defaultRoute\":false}}' ")
        self.client.oc_run_or_die("wait --for=jsonpath='{.spec.defaultRoute}'=false configs.imageregistry.operator.openshift.io/cluster --timeout=5m")

        # Wait for changes to be applied
        logger.info("Waiting for registry to return to default state...")
        time.sleep(10)

        # Verify the registry is back to defaults
        logger.info("Verifying registry is back to OpenShift defaults...")
        result = self.client.oc("get configs.imageregistry.operator.openshift.io cluster -o jsonpath='{.spec.managementState}'")
        if result.success() and "Removed" in result.out:
            logger.info("Registry management state restored to 'Removed'")
        else:
            logger.error_and_exit("Registry management state not properly reset")

        logger.info("Registry restored to OpenShift defaults")


def trust_certificates(host_obj: host.Host, certs: dict[str, str]) -> None:
    """
    Trust certificates by writing them to the system trust anchors and running update-ca-trust.

    :param host_obj: The host on which to trust the certs
    :param certs: Dict of {filename: cert_content} to be placed in anchors
    """
    for filename, content in certs.items():
        host_obj.write(f"/etc/pki/ca-trust/source/anchors/{filename}", content)
    host_obj.run_or_die("sudo update-ca-trust extract")


def wait_for_http_ready(url: str, timeout: str = "6m", interval: str = "5s", expected_codes: tuple[int, ...] = (200, 401, 403)) -> None:
    """
    Wait until the HTTP endpoint is reachable and returns an expected status code.

    Args:
        url (str): The URL to check.
        timeout (str): Max total wait time (e.g., "6m", "2m30s").
        interval (str): Time to wait between retries (e.g., "5s", "10s").
        expected_codes (tuple): Acceptable HTTP status codes.

    Raises:
        RuntimeError: If the URL is not ready within the timeout.
    """

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    timeout_timer = timer.Timer(timeout)
    logger.info(f"Waiting for HTTP endpoint {url} to be reachable (timeout: {timeout})")

    while not timeout_timer.triggered():
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

        # Don't wait if we're about to timeout
        if not timeout_timer.triggered():
            interval_timer = timer.Timer(interval)
            while not interval_timer.triggered() and not timeout_timer.triggered():
                time.sleep(0.1)  # Small sleep to prevent busy waiting

    raise RuntimeError(f"Timed out waiting for {url} to be ready.")
