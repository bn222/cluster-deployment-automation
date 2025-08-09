import os
import time
import jinja2
from abc import ABC, abstractmethod
from logger import logger
from k8sClient import K8sClient
from enum import Enum
from typing import Optional
from common import apply_yaml_content


class StorageType(str, Enum):
    """Type of storage to deploy."""

    HOSTPATH = "hostpath"
    """Deploy hostpath storage."""


class ClusterStorage(ABC):
    """Abstract base class for cluster storage implementations"""

    def __init__(self, kubeconfig_path: str):
        self.client = K8sClient(kubeconfig_path)
        self.manifests_path = os.path.join(os.path.dirname(__file__), "manifests", "infra", "storage")

    @abstractmethod
    def deploy_storage(self) -> None:
        """Deploy cluster storage - implementation specific"""
        pass

    @abstractmethod
    def undeploy_storage(self) -> None:
        """Undeploy cluster storage - implementation specific"""
        pass

    @abstractmethod
    def get_storage_class_name(self) -> str:
        """Return the storage class name for this storage type"""
        pass

    def create_pvc(self, pvc_name: str, namespace: str, storage_size: str, access_modes: list[str] = ["ReadWriteMany"]) -> None:
        """Create PVC for the specified storage"""
        logger.info(f"Creating PVC '{pvc_name}' in namespace '{namespace}' with size '{storage_size}'")

        # Check if PVC already exists and is bound
        pvc_check = self.client.oc(f"get pvc {pvc_name} -n {namespace} -o jsonpath='{{.status.phase}}'")
        if pvc_check.success() and pvc_check.out.strip() == "Bound":
            logger.info(f"PVC '{pvc_name}' already exists and is bound")
            return

        # Check if PVC exists but isn't bound
        pvc_exists = self.client.oc(f"get pvc {pvc_name} -n {namespace}")
        if not pvc_exists.success():
            # Create the PVC
            access_modes_yaml = '\n  '.join([f"- {mode}" for mode in access_modes])
            pvc_yaml = f"""
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: {pvc_name}
  namespace: {namespace}
spec:
  accessModes:
  {access_modes_yaml}
  resources:
    requests:
      storage: {storage_size}
  storageClassName: {self.get_storage_class_name()}
"""

            if not apply_yaml_content(self.client, pvc_yaml, description=f"PVC '{pvc_name}'"):
                logger.error_and_exit(f"Failed to create PVC '{pvc_name}'")

            logger.info(f"PVC '{pvc_name}' created successfully")
        else:
            logger.info(f"PVC '{pvc_name}' already exists but is not bound yet")

    def cleanup_pv(self, pv_name: str) -> None:
        """Clean up stuck PV, including removing finalizers if necessary"""
        logger.info(f"Cleaning up PV '{pv_name}'...")

        # Check if PV exists
        pv_check = self.client.oc(f"get pv {pv_name}")
        if not pv_check.success():
            logger.info(f"PV '{pv_name}' does not exist, skipping PV cleanup")
            return

        # Get PV status
        pv_status = "Unknown"
        pv_status_result = self.client.oc(f"get pv {pv_name} -o jsonpath='{{.status.phase}}'")
        if pv_status_result.success():
            pv_status = pv_status_result.out.strip()
            logger.info(f"PV '{pv_name}' current status: {pv_status}")

        # Always perform force cleanup to ensure complete removal
        logger.info(f"PV is in {pv_status} state, performing force cleanup...")

        # Remove finalizers first if they exist
        logger.info("Removing PV finalizers...")
        patch_result = self.client.oc(f'patch pv {pv_name} -p \'{{"metadata": {{"finalizers": null}}}}\' --type=merge')
        if not patch_result.success():
            logger.warning(f"Failed to remove PV finalizers: {patch_result.out}")

        # Force delete the PV
        delete_result = self.client.oc(f"delete pv {pv_name} --ignore-not-found --force --grace-period=0")
        if not delete_result.success():
            logger.error_and_exit(f"Failed to delete existing PV: {delete_result.out}")

        logger.info("PV deletion initiated, waiting for it to be completely removed...")

    def cleanup_storage_resources(self, pvc_name: str, pvc_namespace: str, pv_name: str) -> None:
        """Clean up storage resources in the correct order"""
        logger.info(f"Cleaning up storage resources: PVC '{pvc_name}' in namespace '{pvc_namespace}' and PV '{pv_name}'")

        # Clean up PVC first, then PV
        cleanup_stuck_pvc(self.client, pvc_name, pvc_namespace)
        self.cleanup_pv(pv_name)
        self._verify_cleanup_complete(pvc_name, pvc_namespace, pv_name)

    def _verify_cleanup_complete(self, pvc_name: str, pvc_namespace: str, pv_name: str) -> None:
        """Verify that storage resources have been completely cleaned up"""
        logger.info("Verifying storage resource cleanup completion...")

        # Check PVC cleanup
        pvc_check = self.client.oc(f"get pvc {pvc_name} -n {pvc_namespace}")
        if pvc_check.success():
            logger.warning(f"PVC '{pvc_name}' still exists after cleanup")
        else:
            logger.info(f"PVC '{pvc_name}' successfully removed")

        # Check PV cleanup
        pv_check = self.client.oc(f"get pv {pv_name}")
        if pv_check.success():
            logger.warning(f"PV '{pv_name}' still exists after cleanup")
        else:
            logger.info(f"PV '{pv_name}' successfully removed")

        logger.info("Storage resource cleanup verification completed")


class HostPathStorage(ClusterStorage):
    """HostPath storage implementation for OpenShift clusters with node-specific targeting"""

    def __init__(self, kubeconfig_path: str, target_node_hostname: str, storage_path: str = "/var/lib/hostpath-storage"):
        super().__init__(kubeconfig_path)
        self.manifests_path = os.path.join(os.path.dirname(__file__), "manifests", "infra", "storage")
        self.target_node_hostname = target_node_hostname
        self.storage_path = storage_path

    def deploy_storage(self) -> None:
        """Deploy hostPath storage class only - applications create their own PVs/PVCs"""
        logger.info("Deploying hostPath storage class...")

        self._ensure_storage_directory()

        if self.client.oc("get storageclass local-hostpath").success():
            logger.info("HostPath storage class already exists, skipping deployment")
            return

        storage_manifest = os.path.join(self.manifests_path, "simple-hostpath-storage.yaml")

        with open(storage_manifest, 'r') as f:
            manifest_content = f.read()

        # Split manifest into StorageClass and PV parts - only apply StorageClass
        parts = manifest_content.split('---')
        storage_class_yaml = parts[0].strip()

        # Apply storage class
        if not apply_yaml_content(self.client, storage_class_yaml, description="storage class"):
            logger.error_and_exit("Failed to create hostPath storage class")

        # Verify storage class was created
        result = self.client.oc("get storageclass local-hostpath")
        if result.success():
            logger.info("HostPath storage class created successfully")
        else:
            logger.error_and_exit("Failed to create hostPath storage class")

    def undeploy_storage(self) -> None:
        """Undeploy hostPath storage class and directories only - applications handle their own PVs/PVCs"""
        logger.info("Undeploying hostPath storage class...")

        # Clean up storage class
        logger.info("Deleting hostPath storage class...")
        self.client.oc("delete storageclass local-hostpath --ignore-not-found --timeout=30s")

        # Clean up storage directory DaemonSets
        logger.info("Cleaning up any remaining storage directory DaemonSets...")
        self.client.oc("delete daemonset storage-dir-creator -n kube-system --ignore-not-found --timeout=30s")

        # Wait for cleanup to settle
        logger.info("Waiting for cleanup to settle...")
        time.sleep(5)

        # Additional verification for storage class
        result = self.client.oc("get storageclass local-hostpath")
        if result.success():
            logger.warning("Storage class still exists after cleanup")
        else:
            logger.info("Storage class successfully removed")

        logger.info("HostPath storage cleanup completed")

    def create_pv_with_node_affinity(self, pv_name: str, storage_size: str, storage_path: Optional[str] = None) -> None:
        """Create PV with node affinity targeting the configured node"""
        logger.info(f"Creating PV '{pv_name}' with size '{storage_size}'")

        # Use instance storage path if none provided
        if storage_path is None:
            storage_path = self.storage_path

        # Get node affinity expressions for the target node
        node_affinity = self._get_node_affinity_expressions()

        # Check if PV already exists and delete it if it has different configuration
        # This is necessary because nodeAffinity is immutable on PVs
        existing_pv = self.client.oc(f"get pv {pv_name} -o yaml")
        if existing_pv.success():
            logger.info(f"Existing PV '{pv_name}' found, deleting for reconfiguration...")
            self.cleanup_pv(pv_name)

        # Render PV template
        pv_template_path = os.path.join(self.manifests_path, "persistent-volume.yaml.j2")
        with open(pv_template_path) as f:
            j2_template = jinja2.Template(f.read())

        rendered = j2_template.render(pv_name=pv_name, node_affinity=node_affinity, storage_size=storage_size, storage_path=storage_path)
        logger.debug(f"Creating PV '{pv_name}' with node affinity: {node_affinity}")
        logger.debug(f"Storage size: {storage_size}, Storage path: {storage_path}")
        logger.debug(f"Rendered PV manifest:\n{rendered}")

        # Apply the PV
        if not apply_yaml_content(self.client, rendered, description=f"PV '{pv_name}' with node affinity"):
            logger.error_and_exit(f"Failed to create PV '{pv_name}'")

        logger.info(f"PV '{pv_name}' created successfully")

    def _get_node_affinity_expressions(self) -> list[dict[str, str | list[str]]]:
        """Generate node affinity expressions - requires explicit target node configuration"""

        # Target node hostname must be specified for targeted storage deployment
        if self.target_node_hostname:
            logger.info(f"Targeting specific node: {self.target_node_hostname}")
            return [{"key": "kubernetes.io/hostname", "operator": "In", "values": [self.target_node_hostname]}]
        else:
            logger.error_and_exit("Target node not configured. Please specify a target node hostname for storage deployment.")

    def _ensure_storage_directory(self) -> str:
        """Create storage directories on the target node using DaemonSet"""
        logger.info(f"Ensuring storage directory exists on target node: {self.target_node_hostname}")

        # Create storage directories using DaemonSet
        self._apply_daemonset_with_template()

        logger.info("Storage directory creation initiated successfully")
        return self.storage_path

    def _apply_daemonset_with_template(self) -> None:
        """Apply DaemonSet for storage directory creation using Jinja2 template"""
        logger.info(f"Creating storage directories on target node: {self.target_node_hostname}")

        # Generate node affinity for the DaemonSet
        node_affinity = self._get_node_affinity_expressions()

        # Get OpenShift namespace UID/GID for proper directory ownership
        logger.info("Querying OpenShift namespace UID/GID for directory ownership...")
        uid, gid = self._get_namespace_uid_gid_range()

        # Render DaemonSet template with ownership information
        ds_template_path = os.path.join(self.manifests_path, "storage-dir-creator.yaml.j2")
        with open(ds_template_path) as f:
            j2_template = jinja2.Template(f.read())

        rendered = j2_template.render(node_affinity=node_affinity, storage_path=self.storage_path, storage_uid=uid, storage_gid=gid)
        logger.debug(f"Rendered DaemonSet manifest:\n{rendered}")

        # Apply the DaemonSet
        if not apply_yaml_content(self.client, rendered, description="storage directory creator DaemonSet"):
            logger.error_and_exit("Failed to create storage directory creator DaemonSet")

        logger.info("Storage directory creator DaemonSet applied successfully")
        logger.info(f"Directory will be created with ownership {uid}:{gid}")

        # No need for post-creation ownership setting - DaemonSet handles it

    def get_storage_class_name(self) -> str:
        """Return the storage class name for hostPath storage"""
        return "local-hostpath"

    def _get_namespace_uid_gid_range(self, namespace: str = "openshift-image-registry") -> tuple[int, int]:
        """
        Get the UID and GID range assigned to a namespace by OpenShift.

        OpenShift assigns UID ranges dynamically when namespaces are created,
        and we need to use the actual assigned range for proper storage permissions.

        Returns:
            tuple[int, int]: (uid_start, gid_start) from the namespace annotations
        """
        logger.info(f"Detecting UID/GID range assigned to {namespace} namespace...")

        # Get the UID range from namespace annotations
        uid_result = self.client.oc(f"get namespace {namespace} -o jsonpath='{{.metadata.annotations.openshift\\.io/sa\\.scc\\.uid-range}}'")
        if not uid_result.success():
            logger.error_and_exit(f"Failed to get UID range from {namespace} namespace")

        uid_range = uid_result.out.strip()
        if not uid_range:
            logger.error_and_exit(f"No UID range found in {namespace} namespace annotations")

        # Parse the range (format: "1000320000/10000")
        uid_start_str, _ = uid_range.split('/')
        uid_start = int(uid_start_str)

        # Get the GID range (usually the same as UID range)
        gid_result = self.client.oc(f"get namespace {namespace} -o jsonpath='{{.metadata.annotations.openshift\\.io/sa\\.scc\\.supplemental-groups}}'")
        if gid_result.success() and gid_result.out.strip():
            gid_range = gid_result.out.strip()
            gid_start_str, _ = gid_range.split('/')
            gid_start = int(gid_start_str)
        else:
            # Fallback to same as UID if GID range not found
            gid_start = uid_start

        logger.info(f"Detected UID range: {uid_start}, GID range: {gid_start}")
        return uid_start, gid_start

    def _set_storage_directory_ownership(self, directory_path: str, namespace: str = "openshift-image-registry") -> None:
        """Set proper ownership on storage directory based on OpenShift namespace UID/GID assignment"""
        if not self.target_node_hostname:
            logger.warning("No target node specified, cannot set directory ownership")
            return

        # Get the OpenShift-assigned UID/GID for the namespace
        uid, gid = self._get_namespace_uid_gid_range(namespace)

        logger.info(f"Setting ownership {uid}:{gid} on directory {directory_path} on node {self.target_node_hostname}")

        # Use oc debug to set ownership on the target node
        ownership_cmd = f"chroot /host chown -R {uid}:{gid} {directory_path}"
        debug_result = self.client.oc(f"debug node/{self.target_node_hostname} -- {ownership_cmd}")

        if not debug_result.success():
            logger.error_and_exit(f"Failed to set ownership on {directory_path}: {debug_result.out}")

        logger.info(f"Successfully set ownership {uid}:{gid} on {directory_path}")


def create_cluster_storage(kubeconfig_path: str, storage_type: StorageType = StorageType.HOSTPATH, target_node_hostname: Optional[str] = None, storage_path: str = "/var/lib/hostpath-storage") -> ClusterStorage:
    """Factory function to create the appropriate storage implementation"""

    if storage_type == StorageType.HOSTPATH:
        if not target_node_hostname:
            logger.error_and_exit("Target node hostname is required for HostPath storage. Please specify a target node.")

        logger.info("Creating HostPath storage implementation")
        logger.info(f"Targeting storage at node: {target_node_hostname}, path: {storage_path}")
        return HostPathStorage(kubeconfig_path, target_node_hostname, storage_path)
    else:
        logger.error_and_exit(f"Unsupported storage type: {storage_type}")


def cleanup_stuck_pvc(client: K8sClient, pvc_name: str, namespace: str) -> None:
    """Clean up stuck PVC, including removing finalizers if necessary"""
    logger.info(f"Cleaning up PVC '{pvc_name}' in namespace '{namespace}'...")

    # Check if PVC exists
    pvc_check = client.oc(f"get pvc {pvc_name} -n {namespace}")
    if not pvc_check.success():
        logger.info(f"PVC '{pvc_name}' does not exist in namespace '{namespace}', skipping PVC cleanup")
        return

    # Get PVC status
    pvc_status = "Unknown"
    pvc_status_result = client.oc(f"get pvc {pvc_name} -n {namespace} -o jsonpath='{{.status.phase}}'")
    if pvc_status_result.success():
        pvc_status = pvc_status_result.out.strip()
        logger.info(f"PVC '{pvc_name}' current status: {pvc_status}")

    # Always perform force cleanup to ensure complete removal
    logger.info(f"PVC is in {pvc_status} state, performing force cleanup...")

    # Remove finalizers first if they exist
    logger.info("Removing PVC finalizers...")
    patch_result = client.oc(f'patch pvc {pvc_name} -n {namespace} -p \'{{"metadata": {{"finalizers": null}}}}\' --type=merge')
    if not patch_result.success():
        logger.warning(f"Failed to remove PVC finalizers: {patch_result.out}")

    # Force delete the PVC with extended timeout for complex scenarios
    logger.info("Initiating PVC deletion...")
    delete_result = client.oc(f"delete pvc {pvc_name} -n {namespace} --ignore-not-found --force --grace-period=0 --timeout=1m")
    if not delete_result.success():
        logger.warning(f"Initial PVC deletion attempt failed: {delete_result.out}")
        logger.info("Attempting final cleanup with background deletion...")
        # Try one more time without timeout to let it proceed in background
        client.oc(f"delete pvc {pvc_name} -n {namespace} --ignore-not-found --force --grace-period=0")
        time.sleep(10)  # Give it some time to start the deletion process

    logger.info("PVC deletion initiated, waiting for it to be completely removed...")
