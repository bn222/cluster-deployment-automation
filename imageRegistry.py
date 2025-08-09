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
from typing import Callable
from clusterStorage import HostPathStorage
from common import apply_yaml_content, render_template_to_string

CONTAINER_NAME = "local-container-registry"


class OCPSystemRole(str, Enum):
    """Cluster-wide OpenShift system roles used for image registry permissions."""

    BUILDER = "system:image-builder"
    """Allows pushing images to the internal OpenShift image registry."""

    PULLER = "system:image-puller"
    """Allows pulling images from the internal OpenShift image registry."""

    AUTHENTICATED = "system:authenticated"
    """Represents any authenticated user or service account in the cluster."""


class RegistryType(str, Enum):
    """Type of registry to deploy."""

    IN_CLUSTER = "in-cluster"
    """Deploy the registry in the cluster."""

    LOCAL = "local"
    """Deploy the registry on the local host."""

    MICROSHIFT = "microshift"
    """Deploy the registry on a MicroShift cluster."""


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
        storage: HostPathStorage,
        namespace: str = "in-cluster-registry",
        sa: str = "pusher",
        storage_size: str = "8Gi",
    ) -> None:
        super().__init__(host.LocalHost())
        self.kubeconfig = kubeconfig
        self.namespace = namespace
        self.sa = sa
        self.storage_size = storage_size
        self.storage: HostPathStorage = storage
        self.client = k8sClient.K8sClient(self.kubeconfig, self.host)

    def _wait_for_condition(self, condition_fn: Callable[[], bool], description: str, timeout: str = "30s", interval: int = 3) -> None:
        """Generic wait utility for any condition function

        Args:
            condition_fn: Function that returns True when condition is met
            description: Human readable description of what we're waiting for
            timeout: Maximum time to wait (e.g. "5m", "30s")
            interval: Seconds between checks
        """
        logger.info(f"Waiting for {description}...")
        timeout_timer = timer.Timer(timeout)

        while not timeout_timer.triggered():
            try:
                if condition_fn():
                    logger.info(f"{description} - condition met")
                    return
            except Exception as e:
                logger.debug(f"Condition check failed: {e}")

            logger.debug(f"Still waiting for {description}...")
            time.sleep(interval)

        raise RuntimeError(f"Timed out waiting for {description} after {timeout}")

    def deploy(self) -> None:
        self._wait_for_registry_operator_ready()
        self._configure_ocp_registry()
        self._ensure_project_and_sa()
        self._grant_roles()
        self.podman_authenticate()

    def undeploy(self) -> None:
        """Undeploy the in-cluster registry, restoring to OpenShift defaults"""
        logger.info("Undeploying in-cluster registry and restoring to OpenShift defaults")

        self._podman_logout()
        self._remove_project_and_sa()
        self._restore_ocp_registry_defaults()

        logger.info("In-cluster registry undeployment completed successfully")

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

        # Create registry-specific PVC using the existing storage class
        logger.info(f"Creating registry storage with storage class: {self.storage.get_storage_class_name()}")
        self.storage.create_pv_with_node_affinity(pv_name="registry-pv", storage_size=self.storage_size, storage_path=self.storage.storage_path)

        # Create PVC for registry using the provided storage class
        # The PV will be created automatically by the storage class or external storage management
        self._create_registry_pvc()

        # Configure OpenShift router for high-throughput registry access
        self._configure_ocp_router_for_registry()

        # Configure registry with all settings in a single atomic patch including CI-optimized queue settings
        # Queue settings prevent 504 timeouts during high-concurrency CI builds:
        # - read.maxInQueue=50: Allow 50 concurrent read requests to queue (image pulls)
        # - read.maxWaitInQueue=10s: Wait up to 10s for read requests
        # - write.maxInQueue=25: Allow 25 concurrent write requests to queue (image pushes)
        # - write.maxWaitInQueue=30s: Wait up to 30s for write requests (pushes take longer)
        logger.info("Configuring registry with management state, storage, route settings, and CI-optimized request queuing")
        registry_patch = '{"spec":{"managementState":"Managed","storage":{"pvc":{"claim":"registry-storage"}},"defaultRoute":true,"replicas":1,"rolloutStrategy":"Recreate","requests":{"read":{"maxInQueue":50,"maxWaitInQueue":"10s"},"write":{"maxInQueue":25,"maxWaitInQueue":"30s"}}}}'

        self.client.oc_run_or_die(f"patch configs.imageregistry.operator.openshift.io cluster --type=merge --patch '{registry_patch}'")

        # Wait for all configurations to be applied
        self._wait_for_condition(lambda: self.client.oc("get configs.imageregistry.operator.openshift.io cluster -o jsonpath='{.spec.managementState}'").out.strip() == "Managed", "registry management state to be set to Managed")
        self._wait_for_condition(lambda: bool(self.client.oc("get configs.imageregistry.operator.openshift.io cluster -o jsonpath='{.spec.storage.pvc}'").out.strip()), "registry to be configured with PVC storage")
        self._wait_for_condition(lambda: self.client.oc("get configs.imageregistry.operator.openshift.io cluster -o jsonpath='{.spec.rolloutStrategy}'").out.strip() == "Recreate", "registry rollout strategy to be set to Recreate")
        self._wait_for_condition(lambda: self.client.oc("get configs.imageregistry.operator.openshift.io cluster -o jsonpath='{.spec.requests.read.maxInQueue}'").out.strip() == "50", "registry read queue size to be set to 50")
        self._wait_for_condition(lambda: self.client.oc("get configs.imageregistry.operator.openshift.io cluster -o jsonpath='{.spec.requests.write.maxWaitInQueue}'").out.strip() == "30s", "registry write queue timeout to be set to 30s")

        # Wait for PVC binding after registry configuration
        self._ensure_pvc_binding_after_registry_config()

        # Wait for route creation and configure trust (always enabled)
        logger.info("Waiting for registry default route to be created")
        self._wait_for_condition(lambda: self.client.oc("get configs.imageregistry.operator.openshift.io cluster -o jsonpath='{.spec.defaultRoute}'").out.strip() == "true", "defaultRoute spec to be set to true")

        # Wait for the route to be created before trying to use it
        self._wait_for_condition(lambda: self.client.oc("get route default-route -n openshift-image-registry --template='{{ .spec.host }}'").success(), "registry default route to be created")

        # Configure image config to trust router certificates
        logger.info("Configuring image config to trust router certificates")
        cm_name = self._create_router_ca_configmap()
        self._wait_for_condition(lambda: self.client.oc("get image.config.openshift.io/cluster -o jsonpath='{.spec.additionalTrustedCA.name}'").out.strip() == cm_name, f"image config to trust CA configmap {cm_name}")

        # Wait for the registry to be ready
        logger.info("Waiting for registry to be ready")
        self._wait_for_condition(
            lambda: self.client.oc("get configs.imageregistry.operator.openshift.io cluster -o jsonpath='{.status.readyReplicas}'").out.strip() == "1",
            "registry to have 1 ready replica",
            timeout="3m",  # Needs longer timeout for pod scheduling and image pulling
        )

    def _create_registry_pvc(self) -> None:
        """Create PVC for registry using the provided storage class"""
        storage_class = self.storage.get_storage_class_name()
        logger.info(f"Creating registry PVC using storage class: {storage_class}")

        pvc_manifest = f"""
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: registry-storage
  namespace: openshift-image-registry
spec:
  accessModes:
  - ReadWriteMany
  resources:
    requests:
      storage: {self.storage_size}
  storageClassName: {storage_class}
"""

        # Apply the PVC manifest
        lh = host.LocalHost()
        temp_pvc_path = "/tmp/registry-pvc.yaml"
        lh.write(temp_pvc_path, pvc_manifest)

        # Delete existing PVC if it exists
        self.client.oc("delete pvc registry-storage -n openshift-image-registry --ignore-not-found")

        # Create new PVC
        if not apply_yaml_content(self.client, pvc_manifest, description="registry PVC"):
            logger.error_and_exit("Failed to create registry PVC")

        logger.info("Registry PVC created successfully")

    def _ensure_pvc_binding_after_registry_config(self) -> None:
        """Ensure PVC binding occurs after registry is configured to use it"""
        logger.info("Ensuring PVC binding after registry configuration...")

        logger.info("Waiting for registry to be configured with PVC...")
        self._wait_for_condition(lambda: self.client.oc("get configs.imageregistry.operator.openshift.io cluster -o jsonpath='{.spec.storage.pvc.claim}'").out.strip() == "registry-storage", "registry to be configured with registry-storage PVC claim")

        # Check PVC binding status
        pvc_status_result = self.client.oc("get pvc registry-storage -n openshift-image-registry -o jsonpath='{.status.phase}'")
        if pvc_status_result.success():
            pvc_status = pvc_status_result.out.strip()
            logger.info(f"Current PVC status: {pvc_status}")

            if pvc_status == "Bound":
                logger.info("PVC is already bound")
                return
            elif pvc_status == "Pending":
                logger.info("PVC is pending - this is expected for WaitForFirstConsumer binding mode")
                logger.info("The PVC will bind when the registry pod is scheduled")
                return
            else:
                logger.error_and_exit(f"PVC is in unexpected state: {pvc_status}")
        else:
            logger.error_and_exit("Failed to check PVC status")

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
        self._wait_for_condition(
            lambda: self.client.oc("get deployment/image-registry -n openshift-image-registry -o jsonpath='{.status.readyReplicas}'").out.strip() == "1",
            "image-registry deployment to have 1 ready replica",
            timeout="2m",
        )
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

        # Reset registry to OpenShift defaults with single atomic merge patch
        logger.info("Resetting registry to OpenShift defaults (managementState=Removed, remove storage, defaultRoute=false)")

        # Apply single atomic merge patch - all changes in one API transaction
        patch_json = '{"spec":{"managementState":"Removed","defaultRoute":false,"storage":null}}'
        logger.info(f"Applying atomic merge patch: {patch_json}")
        self.client.oc_run_or_die(f"patch configs.imageregistry.operator.openshift.io cluster --type=merge -p '{patch_json}'")

        # Wait for all configurations to be applied
        self._wait_for_condition(lambda: self.client.oc("get configs.imageregistry.operator.openshift.io cluster -o jsonpath='{.spec.managementState}'").out.strip() == "Removed", "registry management state to be set to Removed")
        self._wait_for_condition(lambda: self.client.oc("get configs.imageregistry.operator.openshift.io cluster -o jsonpath='{.spec.defaultRoute}'").out.strip() in ["false", ""], "registry defaultRoute to be disabled (false or unset)")

        # Wait for registry operator to fully remove deployment and terminate pods
        logger.info("Waiting for registry operator to fully remove deployment and terminate pods...")

        # Wait for deployment to be deleted by operator
        self._wait_for_condition(
            lambda: not self.client.oc("get deployment image-registry -n openshift-image-registry").success(), "registry deployment to be removed by operator", timeout="1m"  # Operator needs time to process the managementState change
        )

        # Wait for all registry pods to terminate
        self._wait_for_condition(
            lambda: not self.client.oc("get pods -n openshift-image-registry -l docker-registry=default --no-headers").success() or not self.client.oc("get pods -n openshift-image-registry -l docker-registry=default --no-headers").out.strip(),
            "all registry pods to terminate",
            timeout="1m",  # Pods need time to gracefully terminate
        )

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

        logger.info("Cleaning up registry storage resources...")
        # Use the storage instance for consistent cleanup
        self.storage.cleanup_storage_resources("registry-storage", "openshift-image-registry", "registry-pv")

    def _configure_ocp_router_for_registry(self) -> None:
        """Configure OpenShift router for high-throughput registry access"""
        logger.info("Configuring OpenShift router for high-throughput registry access...")

        # Step 1: Configure router timeouts
        logger.info("Setting router replicas and timeout configuration...")
        router_config_patch = '{"spec":{"replicas":2,"tuningOptions":{"reloadInterval":"5s","clientTimeout":"60s","serverTimeout":"60s","tunnelTimeout":"3600s"}}}'
        self.client.oc_run_or_die(f"patch ingresscontroller/default -n openshift-ingress-operator --type=merge --patch '{router_config_patch}'")
        self._wait_for_condition(
            lambda: len(
                [
                    p
                    for p in self.client.oc(
                        "get pods -n openshift-ingress -l ingresscontroller.operator.openshift.io/deployment-ingresscontroller=default --template='{{range .items}}{{.status.phase}}/{{.metadata.creationTimestamp}} {{end}}'"
                    ).out.split()
                    if p.startswith("Running/")
                ]
            )
            >= 2,
            "router pods to be running with updated resources",
            timeout="3m",
        )

        # Step 2: Update router pod resources
        logger.info("Increasing router pod resources for high-throughput access...")
        self.client.oc_run_or_die("set resources deployment/router-default -n openshift-ingress --requests=cpu=250m,memory=512Mi --limits=cpu=500m,memory=1Gi")

        logger.info("Router configured successfully for CI workloads")


def trust_certificates(host_obj: host.Host, certs: dict[str, str]) -> None:
    """
    Trust certificates by writing them to the system trust anchors and running update-ca-trust.

    :param host_obj: The host on which to trust the certs
    :param certs: Dict of {filename: cert_content} to be placed in anchors
    """
    for filename, content in certs.items():
        host_obj.write(f"/etc/pki/ca-trust/source/anchors/{filename}", content)
    host_obj.run_or_die("update-ca-trust extract")


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


class MicroshiftRegistry(InClusterRegistry):
    def __init__(self, host: host.Host, kubeconfig: str, external_ip: str, storage: HostPathStorage, base_dns_domain: str = "nip.io", storage_size: str = "8Gi") -> None:
        # Initialize as InClusterRegistry but with MicroShift-specific namespace
        super().__init__(kubeconfig=kubeconfig, storage=storage, storage_size=storage_size, namespace="openshift-image-registry", sa="registry-sa")
        self.host = host
        self.manifests_path = os.path.join(os.path.dirname(__file__), "manifests", "infra", "image-registry")
        self.external_ip = external_ip
        self.base_dns_domain = base_dns_domain

    def deploy(self) -> None:
        """Deploy MicroShift registry with LoadBalancer service"""
        logger.info("Deploying MicroShift registry with external access...")

        self._ensure_namespace_exists()
        storage_path = self.storage._ensure_storage_directory()
        self.storage.create_pv_with_node_affinity(pv_name="registry-pv", storage_size=self.storage_size, storage_path=storage_path)
        self._create_registry_pvc()
        self._configure_microshift_registry()
        self._wait_for_registry_ready()
        self.podman_authenticate()

        logger.info("MicroShift registry deployment completed successfully!")
        self._show_registry_info()

    def _ensure_namespace_exists(self) -> None:
        """Ensure the openshift-image-registry namespace exists, creating it if necessary"""
        logger.info("Ensuring openshift-image-registry namespace exists...")

        # Check if namespace already exists
        result = self.client.oc("get namespace openshift-image-registry")
        if result.success():
            logger.info("Namespace openshift-image-registry already exists")
        else:
            # Create the namespace
            logger.info("Creating openshift-image-registry namespace...")
            create_result = self.client.oc("create namespace openshift-image-registry")
            if create_result.success():
                logger.info("Successfully created openshift-image-registry namespace")
            else:
                logger.error_and_exit(f"Failed to create namespace: {create_result.out}")

    def _create_registry_pvc(self) -> None:
        """Create PVC for MicroShift registry using the hostpath storage class"""
        logger.info("Creating registry PVC for MicroShift...")

        # Use the storage instance to create the PVC
        self.storage.create_pvc("registry-storage", "openshift-image-registry", self.storage_size)

        logger.info("Registry PVC created successfully")

    def undeploy(self) -> None:
        """Undeploy MicroShift registry and clean up all resources"""
        logger.info("Undeploying MicroShift registry...")

        # Delete the registry manifests
        self._delete_registry_manifests()

        # Clean up storage resources
        self._cleanup_registry_storage()

        # Clean up namespace
        self._cleanup_namespace()

        logger.info("MicroShift registry undeployment completed successfully!")

    def _cleanup_namespace(self) -> None:
        """Clean up the openshift-image-registry namespace"""
        logger.info("Cleaning up openshift-image-registry namespace...")

        # Delete the namespace
        result = self.client.oc("delete namespace openshift-image-registry --ignore-not-found --timeout=120s")
        if result.success():
            logger.info("Successfully deleted openshift-image-registry namespace")
        else:
            logger.warning(f"Failed to delete namespace: {result.out}")

    def _configure_microshift_registry(self) -> None:
        """Configure MicroShift registry with LoadBalancer service"""

        logger.info("Deploying MicroShift registry config...")
        self.client.oc_run_or_die(f"apply -f {os.path.join(self.manifests_path, 'registry-config.yaml')}")

        logger.info("Deploying MicroShift registry manifests...")
        template_file = os.path.join(self.manifests_path, "registry.yaml.j2")

        rendered_manifest = render_template_to_string(template_file, external_ip=self.external_ip, base_dns_domain=self.base_dns_domain)

        if not apply_yaml_content(self.client, rendered_manifest, description="registry manifest"):
            logger.error_and_exit("Failed to deploy registry manifests")

    def _wait_for_registry_ready(self) -> None:
        """Wait for registry deployment to be ready"""
        logger.info("Waiting for registry deployment to be ready...")

        # Wait for deployment to be available
        self._wait_for_condition(lambda: self.client.oc("get deployment/registry -n openshift-image-registry -o jsonpath='{.status.readyReplicas}'").out.strip() == "1", "registry deployment to have 1 ready replica", timeout="300s")

        logger.info("Registry is ready!")

    def podman_authenticate(self) -> None:
        """
        No need to authenticate, the registry uses anonymous users.
        """
        registry_url = self.get_url()

        # The registry is insecure by default (no TLS in manifest)
        # Use http and expect 401 if auth is required, which it is.
        logger.info(f"Waiting for image registry to be ready at http://{registry_url}/v2/")
        wait_for_http_ready(f"http://{registry_url}/v2/", timeout="3m", expected_codes=(200, 401))

        # Registry is insecure, so use --tls-verify=false

        logger.info(f"Successfully logged into in-cluster registry at {registry_url}")
        logger.info(f"To push images, use format: podman push <image> {registry_url}/<image-name>:<tag>")

    def _show_registry_info(self) -> None:
        """Show registry access information"""
        logger.info("Registry deployment complete!")
        print("")
        print("MicroShift Registry Access Information:")
        print("=" * 40)
        registry_url = self.get_url()

        print(f"NodePort: {self.external_ip or 'localhost'}:30500")
        print("")
        print("Usage Example:")
        print(f"podman tag myapp:latest {registry_url}/{self.namespace}/myapp:v1.0.0")
        print(f"podman push {registry_url}/{self.namespace}/myapp:v1.0.0 --tls-verify=false")
        print("")

    def _delete_registry_manifests(self) -> None:
        """Delete all registry manifests"""
        logger.info("Deleting registry manifests...")

        # Render the template and delete using the same manifest
        template_file = os.path.join(self.manifests_path, "registry.yaml.j2")
        rendered_manifest = render_template_to_string(template_file, external_ip=self.external_ip, base_dns_domain=self.base_dns_domain)

        if not apply_yaml_content(self.client, rendered_manifest, delete=True, description="registry manifest"):
            logger.error_and_exit("Failed to delete registry manifests")

        # Also delete individual resources that might exist (fallback)
        resources_to_delete = ["deployment/registry", "service/registry", "service/registry-loadbalancer", "service/registry-nodeport", "route/default-route"]

        for resource in resources_to_delete:
            logger.debug(f"Deleting {resource} in openshift-image-registry namespace...")
            result = self.client.oc(f"delete {resource} -n openshift-image-registry --ignore-not-found --timeout=30s")
            if result.success():
                logger.debug(f"Successfully deleted {resource}")
            else:
                logger.debug(f"Failed to delete {resource} (may not exist): {result.out}")

    def _cleanup_registry_storage(self) -> None:
        """Clean up registry storage resources"""
        logger.info("Cleaning up registry storage resources...")

        # Use the storage instance for consistent cleanup
        self.storage.cleanup_storage_resources("registry-storage", "openshift-image-registry", "registry-pv")

        logger.info("Registry storage cleanup completed")
