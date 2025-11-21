from clustersConfig import ClustersConfig
from logger import logger
from concurrent.futures import Future
from typing import Optional
from clustersConfig import ExtraConfigArgs
from clustersConfig import NodeConfig
import host
import time


# Standard kernel RPM packages
KERNEL_RPM_PACKAGES = [
    "kernel",
    "kernel-core",
    "kernel-modules",
    "kernel-modules-core",
    "kernel-modules-extra",
]


def _check_running_kernel(h: host.Host, kernel_version: str) -> bool:
    """Check if the desired kernel version is currently running."""
    ret = h.run("uname -r")
    return kernel_version in ret.out


def _get_kernel_rpm_urls(kernel_repo_url: str, kernel_version: str) -> list[str]:
    """Generate the list of kernel RPM URLs."""
    base_url = kernel_repo_url.rstrip('/')
    return [f"{base_url}/{pkg}-{kernel_version}.rpm" for pkg in KERNEL_RPM_PACKAGES]


def _download_kernel_rpms(kernel_repo_url: str, kernel_version: str) -> None:
    """Download kernel RPMs to localhost."""
    h = host.LocalHost()
    working_dir = "kernel_install_tmp"

    # Clean up any previous installation attempts
    h.run(f"rm -rf {working_dir}")
    h.run(f"mkdir -p {working_dir}")

    rpm_urls = _get_kernel_rpm_urls(working_dir, kernel_version)
    logger.info(f"Downloading {len(rpm_urls)} kernel RPMs")

    for rpm in rpm_urls:
        filename = rpm.split("/")[-1]
        logger.info(f"Downloading {filename}")
        rpm_url = kernel_repo_url.rstrip('/') + '/' + filename
        cmd = f"curl -f -k -L -o {rpm} {rpm_url}"
        ret = h.run(cmd)
        if ret.returncode != 0:
            logger.error_and_exit(f"Failed to download {rpm_url}: {ret.err}")


def _copy_kernel_rpms(h: host.Host, kernel_version: str) -> None:
    """Copy kernel RPMs to the node."""
    working_dir = "kernel_install_tmp"

    # Clean up any previous installation attempts
    h.run(f"rm -rf {working_dir}")
    h.run(f"mkdir -p {working_dir}")

    rpm_urls = _get_kernel_rpm_urls(working_dir, kernel_version)
    logger.info(f"Copying {len(rpm_urls)} kernel RPMs")

    for rpm in rpm_urls:
        filename = rpm.split("/")[-1]
        logger.info(f"Copying {filename}")
        h.copy_to(rpm, rpm)


def _install_kernel_rpms(h: host.Host) -> None:
    """Install kernel RPMs using rpm-ostree."""
    working_dir = "kernel_install_tmp"

    logger.info("Installing kernel RPMs using rpm-ostree")
    cmd = f"sudo rpm-ostree override replace {working_dir}/*.rpm"
    ret = h.run(cmd)

    # Check if installation was successful
    output_lines = ret.out.strip().split("\n")
    if output_lines and 'Run "systemctl reboot" to start a reboot' in output_lines[-1]:
        logger.info("Kernel RPMs installed successfully")
        return

    logger.error_and_exit(f"Failed to install kernel RPMs: {ret.out}\n{ret.err}")


def _install_kernel_and_reboot(node: NodeConfig, kernel_version: str) -> None:
    """Install the custom kernel on a single node."""
    logger.info(f"Installing kernel on node: {node.name} ({node.ip})")

    # Create remote host connection
    ip = node.ip
    if ip is None:
        logger.info(f"Unknown IP for node {node.name}, skipping")
        return

    h = host.RemoteHost(ip)
    h.ssh_connect("core")

    # Check if kernel is already installed
    if _check_running_kernel(h, kernel_version):
        logger.info(f"Kernel {kernel_version} already installed on {node.name}, skipping")
        return

    # Download and install kernel
    _copy_kernel_rpms(h, kernel_version)
    _install_kernel_rpms(h)

    # Reboot the node
    logger.info(f"Rebooting node {node.name} to apply new kernel")
    h.run("sudo systemctl reboot")


def _verify_kernel(node: NodeConfig, kernel_version: str) -> None:
    """Wait for reboor and verify that the node is running the specified kernel."""

    # Wait for node to come back up
    logger.info(f"Waiting for node {node.name} to reconnect after reboot")

    # Retry SSH connection after reboot
    ip = node.ip
    if ip is None:
        # Should never happen, deal with a linter warn
        return

    h = host.RemoteHost(ip)
    max_retries = 30
    for attempt in range(max_retries):
        try:
            h.ssh_connect("core")
            logger.info(f"Node {node.name} is back online")
            break
        except Exception as e:
            if attempt < max_retries - 1:
                logger.info(f"Waiting 5s for node {node.name} to come back up (attempt {attempt + 1}/{max_retries})")
                time.sleep(5)
            else:
                logger.error_and_exit(f"Node {node.name} did not come back up after reboot: {e}")

    # Verify kernel installation
    if not _check_running_kernel(h, kernel_version):
        logger.error_and_exit(f"Failed to install kernel {kernel_version} on node {node.name}")

    logger.info(f"Successfully installed kernel {kernel_version} on node {node.name}")


def ExtraConfigCustomKernel(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    """
    Install a custom kernel version on all cluster nodes.

    This extraConfig module installs a specified kernel version from a given
    repository URL on all nodes (both masters and workers) in the cluster.

    Usage in cluster YAML:
        postconfig:
          - name: "custom_kernel"
            kernel_repo_url: "https://download.devel.redhat.com/brewroot/work/tasks/2286/66882286/"
            kernel_version: "5.14.0-570.idpf.IIC_500.el9_6.x86_64"
    """
    # Wait for all previous operations to complete
    [f.result() for (_, f) in futures.items()]

    # Validate configuration
    if not cfg.kernel_repo_url:
        logger.error_and_exit("kernel_repo_url must be specified for custom_kernel postconfig")

    if not cfg.kernel_version:
        logger.error_and_exit("kernel_version must be specified for custom_kernel postconfig")

    logger.info(f"Installing custom kernel {cfg.kernel_version} on all cluster nodes")
    logger.info(f"Kernel repository URL: {cfg.kernel_repo_url}")

    # Get all nodes (masters + workers)
    all_nodes = cc.masters + cc.workers

    if not all_nodes:
        logger.warning("No nodes found in cluster configuration")
        return

    _download_kernel_rpms(cfg.kernel_repo_url, cfg.kernel_version)

    # Install kernel on each node
    for node in all_nodes:
        _install_kernel_and_reboot(node, cfg.kernel_version)

    # let the nodes reboot
    time.sleep(5)
    for node in all_nodes:
        _verify_kernel(node, cfg.kernel_version)

    logger.info("Custom kernel installation completed on all nodes")
