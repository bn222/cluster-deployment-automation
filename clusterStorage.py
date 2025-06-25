import os
import time
import tempfile
import jinja2
from logger import logger
from k8sClient import K8sClient
import timer


class ClusterStorage:
    def __init__(self, kubeconfig_path: str):
        self.client = K8sClient(kubeconfig_path)
        self.manifests_path = os.path.join(os.path.dirname(__file__), "manifests", "infra", "storage")

    def _apply_yaml_content(self, yaml_content: str, description: str = "manifest") -> bool:
        """Apply YAML content using a temporary file and return success status"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml') as f:
            f.write(yaml_content)
            f.flush()
            result = self.client.oc(f"apply -f {f.name}")

        if result.success():
            logger.info(f"{description} applied successfully")
            return True
        else:
            logger.error(f"Failed to apply {description}: {result.out}")
            return False

    def deploy_storage(self) -> None:
        """Deploy cluster storage, currently only hostPath storage is supported"""
        logger.info("Deploying simple hostPath storage")

        self._deploy_simple_storage()

        logger.info("Storage deployment completed successfully")

    def undeploy_storage(self) -> None:
        """Undeploy cluster storage, removing storage class and directories only"""
        logger.info("Undeploying cluster storage")

        self._undeploy_simple_storage()

        logger.info("Storage undeployment completed successfully")

    def _deploy_simple_storage(self) -> None:
        """Deploy simple hostPath storage class only - applications create their own PVs/PVCs"""
        logger.info("Deploying hostPath storage class...")

        self._ensure_storage_directory()

        storage_manifest = os.path.join(self.manifests_path, "simple-hostpath-storage.yaml")

        with open(storage_manifest, 'r') as f:
            manifest_content = f.read()

        # Split manifest into StorageClass and PV parts - only apply StorageClass
        parts = manifest_content.split('---')
        storage_class_yaml = parts[0].strip()

        # Apply storage class
        if not self._apply_yaml_content(storage_class_yaml, "storage class"):
            logger.error_and_exit("Failed to create hostPath storage class")

        # Verify storage class was created
        result = self.client.oc("get storageclass local-hostpath")
        if result.success():
            logger.info("HostPath storage class created successfully")
        else:
            logger.error_and_exit("Failed to create hostPath storage class")

    def _undeploy_simple_storage(self) -> None:
        """Undeploy simple hostPath storage class and directories only - applications handle their own PVs/PVCs"""
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

    def create_pv_with_node_affinity(self, pv_name: str, storage_size: str, storage_path: str = "/var/lib/registry-storage") -> None:
        """Create PV with node affinity based on cluster topology using Jinja2 template"""
        logger.info(f"Creating PV '{pv_name}' with size '{storage_size}'")

        # Determine the appropriate node selector strategy and affinity expressions
        node_selector = self._determine_node_selector_strategy()
        node_affinity = self._get_node_affinity_expressions(node_selector)

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
        if not self._apply_yaml_content(rendered, f"PV '{pv_name}' with node affinity"):
            logger.error_and_exit(f"Failed to create PV '{pv_name}'")

        logger.info(f"PV '{pv_name}' created successfully")

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

            if not self._apply_yaml_content(pvc_yaml, f"PVC '{pvc_name}'"):
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

        # Use oc wait to properly wait for the PV to be deleted
        wait_result = self.client.oc(f"wait --for=delete pv/{pv_name} --timeout=30s")
        if not wait_result.success():
            # If wait fails, verify manually that it's gone
            check_result = self.client.oc(f"get pv {pv_name}")
            if check_result.success():
                logger.error_and_exit(f"PV still exists after deletion attempt: {wait_result.out}")
            else:
                logger.info(f"PV '{pv_name}' successfully removed from cluster")
        else:
            logger.info(f"PV '{pv_name}' successfully removed from cluster")

    def cleanup_storage_resources(self, pvc_name: str, pvc_namespace: str, pv_name: str) -> None:
        """Comprehensive cleanup of PV and PVC, handling stuck resources with finalizers"""
        logger.info(f"Performing comprehensive storage cleanup for PVC '{pvc_name}' in namespace '{pvc_namespace}' and PV '{pv_name}'...")
        cleanup_stuck_pvc(self.client, pvc_name, pvc_namespace)
        self.cleanup_pv(pv_name)
        self._verify_cleanup_complete(pvc_name, pvc_namespace, pv_name)

    def _verify_cleanup_complete(self, pvc_name: str, pvc_namespace: str, pv_name: str) -> None:
        """Verify that both PVC and PV are completely removed"""
        logger.info("Verifying storage cleanup is complete...")

        # Check PVC
        pvc_check = self.client.oc(f"get pvc {pvc_name} -n {pvc_namespace}")
        if pvc_check.success():
            logger.error_and_exit(f"PVC '{pvc_name}' still exists after cleanup - manual intervention required")

        # Check PV
        pv_check = self.client.oc(f"get pv {pv_name}")
        if pv_check.success():
            logger.error_and_exit(f"PV '{pv_name}' still exists after cleanup - manual intervention required")

        logger.info("Storage cleanup verification complete - all resources removed")

    def _get_node_affinity_expressions(self, node_selector: str) -> list[dict[str, str]]:
        """Get node affinity expressions based on cluster topology"""

        if node_selector == "dedicated-workers":
            # Only dedicated worker nodes
            return [{"key": "node-role.kubernetes.io/worker", "operator": "Exists"}, {"key": "node-role.kubernetes.io/master", "operator": "DoesNotExist"}]
        elif node_selector == "worker-masters":
            # Master nodes that also have worker role
            return [{"key": "node-role.kubernetes.io/worker", "operator": "Exists"}]
        else:
            # No specific affinity for schedulable nodes
            return []

    def _ensure_storage_directory(self) -> str:
        """Ensure the storage directory exists on appropriate nodes based on cluster topology"""
        logger.info("Ensuring storage directory exists on appropriate nodes...")

        # Determine the appropriate node selector strategy
        node_selector = self._determine_node_selector_strategy()

        # Deploy DaemonSet using Jinja2 template
        self._apply_daemonset_with_template(node_selector)

        # Wait for DaemonSet completion
        t = timer.Timer("2m")
        logger.info(f"Waiting for storage directory creation to complete (timeout: {t.target_duration()})")
        while not t.triggered():
            result = self.client.oc("get daemonset storage-dir-creator -n kube-system -o jsonpath='{.status.numberReady}'")
            if result.success() and result.out.strip():
                ready_count = int(result.out.strip())
                if ready_count > 0:
                    logger.info(f"Storage directories created on {ready_count} nodes after {t.elapsed()}")
                    break
            time.sleep(10)
        else:
            logger.error_and_exit(f"Storage directory creation timed out after {t.target_duration()}")

        # Clean up the DaemonSet
        self.client.oc("delete daemonset storage-dir-creator -n kube-system --ignore-not-found")

        return node_selector

    def _determine_node_selector_strategy(self) -> str:
        """Determine the appropriate node selector strategy based on cluster topology"""

        # First, try to get dedicated worker nodes (not masters)
        result = self.client.oc("get nodes -l '!node-role.kubernetes.io/control-plane' -o jsonpath='{.items[*].metadata.name}'")

        if result.success() and result.out.strip():
            # We have dedicated worker nodes - use them
            target_nodes = result.out.strip().split()
            logger.info(f"Found dedicated worker nodes: {target_nodes}")
            return "dedicated-workers"
        else:
            # No dedicated workers, check if we have any worker nodes (including masters)
            result = self.client.oc("get nodes -l 'node-role.kubernetes.io/worker' -o jsonpath='{.items[*].metadata.name}'")

            if result.success() and result.out.strip():
                # We have worker nodes (likely masters with worker role) - use them
                target_nodes = result.out.strip().split()
                logger.info(f"No dedicated workers found, using master nodes with worker role: {target_nodes}")
                return "worker-masters"
            else:
                # Fallback to any schedulable nodes
                result = self.client.oc("get nodes -o jsonpath='{.items[?(@.spec.taints[*].effect!=\"NoSchedule\")].metadata.name}'")
                if result.success() and result.out.strip():
                    target_nodes = result.out.strip().split()
                    logger.info(f"No worker nodes found, using schedulable nodes: {target_nodes}")
                    return "schedulable"
                else:
                    logger.warning("No suitable nodes found for storage")
                    return "schedulable"

    def _apply_daemonset_with_template(self, node_selector: str) -> None:
        """Apply DaemonSet using Jinja2 template with appropriate node selector"""

        # Render DaemonSet template
        daemonset_template_path = os.path.join(self.manifests_path, "storage-dir-creator.yaml.j2")
        with open(daemonset_template_path) as f:
            j2_template = jinja2.Template(f.read())

        rendered = j2_template.render(node_selector=node_selector)
        logger.debug(f"Rendered DaemonSet manifest:\n{rendered}")

        # Apply the DaemonSet
        if not self._apply_yaml_content(rendered, f"storage directory DaemonSet with {node_selector} node selection"):
            logger.error_and_exit("Failed to create storage directory DaemonSet")

        logger.info(f"Storage directory creation DaemonSet deployed with {node_selector} node selection")

    def get_storage_class_name(self) -> str:
        """Return the hostPath storage class name for registry use"""
        return "local-hostpath"


def cleanup_stuck_pvc(client: K8sClient, pvc_name: str, namespace: str) -> None:
    """Clean up stuck PVC, including removing finalizers if necessary"""
    logger.info("Cleaning up registry PVC...")

    # Check if PVC exists
    pvc_check = client.oc(f"get pvc {pvc_name} -n {namespace}")
    if not pvc_check.success():
        logger.info("Registry PVC does not exist, skipping PVC cleanup")
        return

    # Get PVC status to check if it's stuck
    pvc_status_result = client.oc(f"get pvc {pvc_name} -n {namespace} -o jsonpath='{{.status.phase}}'")
    if pvc_status_result.success():
        pvc_status = pvc_status_result.out.strip()
        logger.info(f"Registry PVC current status: {pvc_status}")

    # Try normal deletion first
    logger.info("Attempting normal PVC deletion...")
    delete_result = client.oc(f"delete pvc {pvc_name} -n {namespace} --ignore-not-found --timeout=30s")

    if delete_result.success():
        logger.info("PVC deleted successfully with normal deletion")
        return

    # If normal deletion failed, check if PVC is stuck in Terminating state
    logger.warning("Normal PVC deletion failed, checking if PVC is stuck...")
    pvc_check_after = client.oc(f"get pvc {pvc_name} -n {namespace} -o jsonpath='{{.metadata.deletionTimestamp}}'")

    if pvc_check_after.success() and pvc_check_after.out.strip():
        logger.info("PVC is stuck in Terminating state, removing finalizers...")

        # Remove finalizers to force deletion
        finalizer_patch = client.oc(f'patch pvc {pvc_name} -n {namespace} -p \'{{"metadata": {{"finalizers": null}}}}\' --type=merge')
        if finalizer_patch.success():
            logger.info("PVC finalizers removed successfully")
        else:
            logger.warning(f"Failed to remove PVC finalizers: {finalizer_patch.out}")

    # Wait a moment for the PVC to be deleted after finalizer removal
    time.sleep(5)

    # Verify PVC is gone
    final_check = client.oc(f"get pvc {pvc_name} -n {namespace} -o jsonpath='{{.metadata.deletionTimestamp}}'")
    if final_check.success():
        logger.warning("PVC still exists after cleanup attempts")
    else:
        logger.info("Registry PVC successfully removed")
