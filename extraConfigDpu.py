from clustersConfig import ClustersConfig
import host
from k8sClient import K8sClient
from concurrent.futures import Future
import os
import time
from typing import Optional, List
from logger import logger
from clustersConfig import ExtraConfigArgs
import imageRegistry
from common import git_repo_setup
from dpuVendor import init_vendor_plugin
import common
import re
from dpuVendor import detect_dpu

MICROSHIFT_KUBECONFIG = "/root/kubeconfig.microshift"


def go_is_installed(host: host.Host) -> bool:
    ret = host.run("sh -c 'go version'")
    if ret.returncode == 0:
        installed_version = ret.out.strip().split(' ')[2]
        if installed_version.startswith("go1.23"):
            return True
    return False


def ensure_go_installed(host: host.Host) -> None:
    if not go_is_installed(host):
        go_install(host)


def go_install(host: host.Host) -> None:
    ret = host.run_or_die("uname -m")
    architecture = ret.out.strip()
    if architecture == "x86_64":
        go_tarball = "go1.23.6.linux-amd64.tar.gz"
    elif architecture == "aarch64":
        go_tarball = "go1.23.6.linux-arm64.tar.gz"
    else:
        logger.error_and_exit(f"Unsupported architecture: {architecture}")

    host.run_or_die(f"curl -L https://go.dev/dl/{go_tarball} -o /tmp/{go_tarball}")
    host.run_or_die(f"tar -C /usr/local -xzf /tmp/{go_tarball}")
    host.run_or_die("ln -snf /usr/local/go/bin/go /usr/bin/go")
    host.run_or_die("ln -snf /usr/local/go/bin/gofmt /usr/bin/gofmt")
    host.run_or_die("sh -c 'go version'")


class DpuOperator:
    DPU_OPERATOR_REPO = "https://github.com/openshift/dpu-operator.git"

    def __init__(self, repo_path: str) -> None:
        git_repo_setup(repo_path, repo_wipe=False, url=self.DPU_OPERATOR_REPO)
        self.repo_path = repo_path

    def build_push(self, builder_image: str, base_image: str) -> None:
        h = host.LocalHost()
        self._update_all_dockerfiles(builder_image, base_image)
        logger.info(f"Building dpu operator images in {self.repo_path} on {h.hostname()} with timeout of 1h")

        def build_and_push() -> None:
            h.run_or_die(f"make -C {self.repo_path} local-buildx")
            h.run_or_die(f"make -C {self.repo_path} local-pushx")

        common.with_timeout(3600, build_and_push)

    # The images in registry.ci.openshift.org do not always support multiarch.
    # As a result we will pin working images, and use these locally instead.
    def _update_all_dockerfiles(self, builder_image: str, base_image: str) -> None:
        for dockerfile in self.dockerfiles():
            try:
                self._update_dockerfile(dockerfile, builder_image, base_image)
            except Exception as e:
                logger.error_and_exit(f"Failed to update dockerfile {dockerfile} err: {e}")

    def _update_dockerfile(self, dockerfile: str, builder_image: str, base_image: str) -> None:
        with open(dockerfile, 'r') as file:
            content = file.read()

        # Replace builder image
        if builder_image:
            builder_pattern = r"^FROM\s+([^\s]+)\s+AS\s+builder"
            content = re.sub(builder_pattern, f"FROM {builder_image} AS builder", content, flags=re.MULTILINE)
            logger.info(f"Updated Dockerfile '{dockerfile}' with builder image '{repr(builder_image)}'.")

        if base_image:
            base_pattern = r"^FROM\s+([^\s]+)$"
            content = re.sub(base_pattern, f"FROM {base_image}", content, flags=re.MULTILINE)
            logger.info(f"Updated Dockerfile '{dockerfile}' with base image '{repr(base_image)}'.")

        with open(dockerfile, 'w') as file:
            file.write(content)

    def dockerfiles(self) -> List[str]:
        if not os.path.exists(self.repo_path):
            logger.error_and_exit(f"The specified path '{self.repo_path}' does not exist.")
        if not os.path.isdir(self.repo_path):
            logger.error_and_exit(f"The specified path '{self.repo_path}' is not a directory.")

        dockerfiles: List[str] = []
        for file_name in os.listdir(self.repo_path):
            full_path = os.path.join(self.repo_path, file_name)
            if file_name.startswith("Dockerfile") and os.path.isfile(full_path):
                dockerfiles.append(full_path)
        return dockerfiles

    def start(self, client: K8sClient) -> None:
        h = host.LocalHost()
        logger.info(f"Deploying dpu operator from {h.hostname()}")

        h.run("dnf install -y pip")
        h.run_or_die("pip install yq")
        ensure_go_installed(h)
        env = os.environ.copy()
        env["KUBECONFIG"] = client._kc
        h.run(f"make -C {self.repo_path} undeploy", env=env)
        ret = h.run(f"make -C {self.repo_path} local-deploy", env=env)
        if not ret.success():
            logger.error_and_exit(f"Failed to deploy dpu operator: {ret}")
        logger.info("Waiting for all dpu operator pods to become ready")
        time.sleep(30)
        client.oc_run_or_die("wait --for=condition=Ready pod --all -n openshift-dpu-operator --timeout=5m")


def ExtraConfigDpu(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to start DPU operator on IPU")

    dpu_node = cc.masters[0]
    assert dpu_node.ip is not None
    acc = host.Host(dpu_node.ip)
    lh = host.LocalHost()
    acc.ssh_connect("root", "redhat")

    imgReg = imageRegistry.ensure_local_registry_running(lh, delete_all=False)
    imgReg.trust(acc)
    acc.run("systemctl restart crio")
    # Disable firewall to ensure host-side can reach dpu
    acc.run("systemctl stop firewalld")
    acc.run("systemctl disable firewalld")

    vendor_plugin = init_vendor_plugin(acc, detect_dpu(dpu_node))
    # TODO: For Intel, this configures hugepages. Figure out a better way
    vendor_plugin.setup(acc)


def ExtraConfigDpuHost(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to start DPU operator on Host")
    lh = host.LocalHost()
    client = K8sClient(cc.kubeconfig)

    imgReg = imageRegistry.ensure_local_registry_running(lh, delete_all=False)
    imgReg.ocp_trust(client)
    # Need to trust the registry in OCP / Microshift
    logger.info("Ensuring local registry is trusted in OCP")

def main() -> None:
    pass


if __name__ == "__main__":
    main()
