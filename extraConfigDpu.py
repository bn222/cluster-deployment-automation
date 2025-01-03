from clustersConfig import ClustersConfig, NodeConfig
import host
from bmc import BMC
from k8sClient import K8sClient
from concurrent.futures import Future, ThreadPoolExecutor
import os
import time
from typing import Optional, List
from logger import logger
from clustersConfig import ExtraConfigArgs
import imageRegistry
from common import git_repo_setup
from dpuVendor import init_vendor_plugin, IpuPlugin
from imageRegistry import ImageRegistry
import re

DPU_OPERATOR_REPO = "https://github.com/openshift/dpu-operator.git"
MICROSHIFT_KUBECONFIG = "/root/kubeconfig.microshift"
OSE_DOCKERFILE = "https://pkgs.devel.redhat.com/cgit/containers/dpu-operator/tree/Dockerfile?h=rhaos-4.17-rhel-9"

KERNEL_RPMS = [
    "https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/vol/rhel-9/packages/kernel/5.14.0/427.2.1.el9_4/x86_64/kernel-5.14.0-427.2.1.el9_4.x86_64.rpm",
    "https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/vol/rhel-9/packages/kernel/5.14.0/427.2.1.el9_4/x86_64/kernel-core-5.14.0-427.2.1.el9_4.x86_64.rpm",
    "https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/vol/rhel-9/packages/kernel/5.14.0/427.2.1.el9_4/x86_64/kernel-modules-5.14.0-427.2.1.el9_4.x86_64.rpm",
    "https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/vol/rhel-9/packages/kernel/5.14.0/427.2.1.el9_4/x86_64/kernel-modules-core-5.14.0-427.2.1.el9_4.x86_64.rpm",
    "https://download-01.beak-001.prod.iad2.dc.redhat.com/brewroot/vol/rhel-9/packages/kernel/5.14.0/427.2.1.el9_4/x86_64/kernel-modules-extra-5.14.0-427.2.1.el9_4.x86_64.rpm",
]


def ensure_rhel_9_4_kernel_is_installed(h: host.Host) -> None:
    h.ssh_connect("core")
    ret = h.run("uname -r")
    if "el9_4" in ret.out:
        return

    logger.info(f"Installing RHEL 9.4 kernel on {h.hostname()}")

    wd = "working_dir"
    h.run(f"rm -rf {wd}")
    h.run(f"mkdir -p {wd}")
    logger.info(KERNEL_RPMS)

    for e in KERNEL_RPMS:
        fn = e.split("/")[-1]
        cmd = f"curl -k {e} --create-dirs > {wd}/{fn}"
        h.run(cmd)

    cmd = f"sudo rpm-ostree override replace {wd}/*.rpm"
    logger.info(cmd)
    while True:
        ret = h.run(cmd)
        output = ret.out.strip().split("\n")
        if output and output[-1] == 'Run "systemctl reboot" to start a reboot':
            break
        else:
            logger.info(output)
            logger.info("Output was something unexpected")

    h.run("sudo systemctl reboot")
    time.sleep(10)
    h.ssh_connect("core")
    ret = h.run("uname -r")
    if "el9_4" not in ret.out:
        logger.error_and_exit(f"Failed to install rhel 9.4 kernel on host {h.hostname()}")


def _ensure_local_registry_running(rsh: host.Host, delete_all: bool = False) -> ImageRegistry:
    logger.info(f"Ensuring local registry running on {rsh.hostname()}")
    imgReg = imageRegistry.ImageRegistry(rsh)
    imgReg.ensure_running(delete_all=delete_all)
    imgReg.trust(host.LocalHost())
    return imgReg


def go_is_installed(host: host.Host) -> bool:
    ret = host.run("sh -c 'go version'")
    if ret.returncode == 0:
        installed_version = ret.out.strip().split(' ')[2]
        if installed_version.startswith("go1.22"):
            return True
    return False


def ensure_go_installed(host: host.Host) -> None:
    if go_is_installed(host):
        return

    ret = host.run_or_die("uname -m")
    architecture = ret.out.strip()
    if architecture == "x86_64":
        go_tarball = "go1.22.3.linux-amd64.tar.gz"
    elif architecture == "aarch64":
        go_tarball = "go1.22.3.linux-arm64.tar.gz"
    else:
        logger.error_and_exit(f"Unsupported architecture: {architecture}")

    host.run_or_die(f"curl -L https://go.dev/dl/{go_tarball} -o /tmp/{go_tarball}")
    host.run_or_die(f"tar -C /usr/local -xzf /tmp/{go_tarball}")
    host.run_or_die("ln -snf /usr/local/go/bin/go /usr/bin/go")
    host.run_or_die("ln -snf /usr/local/go/bin/gofmt /usr/bin/gofmt")
    host.run_or_die("sh -c 'go version'")


def copy_local_registry_certs(host: host.Host, path: str) -> None:
    directory = "/root/.local-container-registry/certs"
    files = os.listdir(directory)
    for file in files:
        host.copy_to(f"{directory}/{file}", f"{path}/{file}")


def find_dockerfiles(repo: str) -> List[str]:
    if not os.path.exists(repo):
        logger.error_and_exit(f"The specified path '{repo}' does not exist.")
    if not os.path.isdir(repo):
        logger.error_and_exit(f"The specified path '{repo}' is not a directory.")

    dockerfiles: List[str] = []
    for file_name in os.listdir(repo):
        full_path = os.path.join(repo, file_name)
        if file_name.startswith("Dockerfile") and os.path.isfile(full_path):
            dockerfiles.append(full_path)

    return dockerfiles


# The images in registry.ci.openshift.org do not always support multiarch.
# As a result we will pin working images, and use these locally instead.
def update_dpu_operator_dockerfiles(repo: str, builder_image: str, base_image: str) -> None:
    dockerfiles = find_dockerfiles(repo)
    for dockerfile in dockerfiles:
        try:
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

        except Exception as e:
            logger.error_and_exit(f"Failed to update dockerfile {dockerfile} err: {e}")


def dpu_operator_build_push(repo: str, builder_image: str, base_image: str) -> None:
    h = host.LocalHost()
    update_dpu_operator_dockerfiles(repo, builder_image, base_image)
    logger.info(f"Building dpu operator images in {repo} on {h.hostname()}")
    h.run_or_die(f"make -C {repo} local-buildx")
    h.run_or_die(f"make -C {repo} local-pushx")


def dpu_operator_start(client: K8sClient, repo: str) -> None:
    h = host.LocalHost()
    logger.info(f"Deploying dpu operator from {h.hostname()}")

    h.run("dnf install -y pip")
    h.run_or_die("pip install yq")
    ensure_go_installed(h)
    env = os.environ.copy()
    env["KUBECONFIG"] = client._kc
    h.run(f"make -C {repo} undeploy", env=env)
    ret = h.run(f"make -C {repo} local-deploy", env=env)
    if not ret.success():
        logger.error_and_exit("Failed to deploy dpu operator")
    logger.info("Waiting for all dpu operator pods to become ready")
    time.sleep(30)
    client.oc_run_or_die("wait --for=condition=Ready pod --all -n openshift-dpu-operator --timeout=5m")


def wait_for_microshift_restart(client: K8sClient) -> None:
    ret = client.oc("wait --for=condition=Ready pod --all --all-namespaces --timeout=3m")
    retries = 3
    while not ret.success():
        if retries == 0:
            logger.error_and_exit(f"Microshift failed to restart: \n err: {ret.err} {ret.returncode}")
        logger.info(f"Waiting for pods to come up failed with err {ret.err} retrying")
        time.sleep(20)
        ret = client.oc("wait --for=condition=Ready pod --all --all-namespaces --timeout=3m")
        retries -= 1
    logger.info("Microshift restarted")


def ExtraConfigDpu(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to start DPU operator on IPU")

    repo = cfg.resolve_dpu_operator_path()
    dpu_node = cc.masters[0]
    assert dpu_node.ip is not None
    acc = host.Host(dpu_node.ip)
    lh = host.LocalHost()
    acc.ssh_connect("root", "redhat")
    client = K8sClient(MICROSHIFT_KUBECONFIG)

    imgReg = _ensure_local_registry_running(lh, delete_all=False)
    imgReg.trust(acc)
    acc.run("systemctl restart crio")
    # Disable firewall to ensure host-side can reach dpu
    acc.run("systemctl stop firewalld")
    acc.run("systemctl disable firewalld")

    vendor_plugin = init_vendor_plugin(acc, dpu_node.kind or "")
    if isinstance(vendor_plugin, IpuPlugin):
        # TODO: Remove when this container is properly started by the vsp
        # We need to manually start the p4 sdk container currently for the IPU plugin
        vendor_plugin.ensure_p4_pod_running(lh, acc, imgReg)

    git_repo_setup(repo, repo_wipe=False, url=DPU_OPERATOR_REPO)
    if cfg.rebuild_dpu_operators_images:
        # Build vsp
        vendor_plugin = init_vendor_plugin(acc, dpu_node.kind or "")
        dpu_operator_build_push(repo, cfg.builder_image, cfg.base_image)
    else:
        logger.info("Will not rebuild dpu-operator images")
    dpu_operator_start(client, repo)

    # Deploy dpu daemon
    client.oc_run_or_die(f"label no {dpu_node.name} dpu=true")
    logger.info("Waiting for all pods to become ready")
    client.oc_run_or_die("wait --for=condition=Ready pod --all --all-namespaces --timeout=2m")
    client.oc_run_or_die(f"create -f {repo}/examples/dpu.yaml")
    client.wait_ds_running(ds="vsp", namespace="openshift-dpu-operator")
    client.oc_run_or_die("wait --for=condition=Ready pod --all --all-namespaces --timeout=3m")
    logger.info("Finished setting up dpu operator on dpu")


def ExtraConfigDpuHost(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    logger.info("Running post config step to start DPU operator on Host")
    lh = host.LocalHost()
    client = K8sClient(cc.kubeconfig)
    repo = cfg.resolve_dpu_operator_path()

    imgReg = _ensure_local_registry_running(lh, delete_all=False)
    imgReg.ocp_trust(client)
    # Need to trust the registry in OCP / Microshift
    logger.info("Ensuring local registry is trusted in OCP")

    node = cc.workers[0]
    h = host.Host(node.node)
    h.ssh_connect("core")

    git_repo_setup(repo, branch="main", repo_wipe=False, url=DPU_OPERATOR_REPO)
    if cfg.rebuild_dpu_operators_images:
        dpu_operator_build_push(repo, cfg.builder_image, cfg.base_image)
    else:
        logger.info("Will not rebuild dpu-operator images")
    dpu_operator_start(client, repo)

    def helper(h: host.Host, node: NodeConfig) -> Optional[host.Result]:
        # Label the node
        logger.info(f"labeling node {h.hostname()} dpu=true")
        client.oc_run_or_die(f"label no {e.name} dpu=true")
        return None

    executor = ThreadPoolExecutor(max_workers=len(cc.workers))
    f = []
    # Assuming that all workers have a DPU
    for e in cc.workers:
        logger.info(f"Calling helper function for node {e.node}")
        bmc = BMC.from_bmc(e.bmc, e.bmc_user, e.bmc_password)
        h = host.Host(e.node, bmc)
        f.append(executor.submit(helper, h, e))

    for thread in f:
        logger.info(thread.result())

    logger.info("Verified idpf is providing net-devs on DPU worker nodes")

    # Create host nad
    # TODO: Remove when this is automatically created by the dpu operator
    logger.info("Creating dpu NAD")
    client.oc("delete -f manifests/dpu/dpu_nad.yaml")
    client.oc_run_or_die("create -f manifests/dpu/dpu_nad.yaml")
    # Deploy dpu daemon and wait for dpu pods to come up
    logger.info("Creating dpu operator config")
    client.oc_run_or_die(f"create -f {repo}/examples/host.yaml")
    time.sleep(30)
    client.wait_ds_running(ds="vsp", namespace="openshift-dpu-operator")
    client.oc_run_or_die("wait --for=condition=Ready pod --all -n openshift-dpu-operator --timeout=5m")
    logger.info("Finished setting up dpu operator on host")


def main() -> None:
    pass


if __name__ == "__main__":
    main()
