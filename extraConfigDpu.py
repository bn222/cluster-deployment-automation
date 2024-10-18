from clustersConfig import ClustersConfig, NodeConfig
import host
from bmc import BMC
from k8sClient import K8sClient
from concurrent.futures import Future, ThreadPoolExecutor
import os
import time
from typing import Optional
from logger import logger
from clustersConfig import ExtraConfigArgs
import imageRegistry
from common import git_repo_setup
from dpuVendor import init_vendor_plugin, IpuPlugin
from imageRegistry import ImageRegistry

DPU_OPERATOR_REPO = "https://github.com/openshift/dpu-operator.git"
MICROSHIFT_KUBECONFIG = "/root/kubeconfig.microshift"
OSE_DOCKERFILE = "https://pkgs.devel.redhat.com/cgit/containers/dpu-operator/tree/Dockerfile?h=rhaos-4.17-rhel-9"
P4_IMG = "wsfd-advnetlab239.anl.eng.bos2.dc.redhat.com:5000/intel-ipu-p4-sdk:10-9-2024"

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


def dpu_operator_build_push(repo: Optional[str]) -> None:
    h = host.LocalHost()
    logger.info(f"Building dpu operator images in {repo} on {h.hostname()}")
    h.run_or_die(f"make -C {repo} local-buildx")
    h.run_or_die(f"make -C {repo} local-pushx")


def dpu_operator_start(client: K8sClient, repo: Optional[str]) -> None:
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


def wait_vsp_ds_running(client: K8sClient) -> None:
    retries = 10
    for _ in range(retries):
        time.sleep(20)
        desired_result = client.oc_run_or_die("get ds vsp -n openshift-dpu-operator -o jsonpath='{.status.desiredNumberScheduled}'")
        available_result = client.oc_run_or_die("get ds vsp -n openshift-dpu-operator -o jsonpath='{.status.numberAvailable}'")
        logger.info(f"Waiting for VSP ds to scale up. Desired/Available: {desired_result.out}/{available_result.out}")
        if desired_result.out.isdigit() and available_result.out.isdigit():
            desired_pods = int(desired_result.out)
            available_pods = int(available_result.out)
            if available_pods == desired_pods:
                break
    else:
        logger.error_and_exit("Vsp pods failed to reach ready state")


def ensure_p4_pod_running(lh: host.Host, acc: host.Host, imgReg: ImageRegistry) -> None:
    lh.run_or_die(f"podman pull --tls-verify=false {P4_IMG}")
    lh.run_or_die(f"podman tag {P4_IMG} {imgReg.url()}/intel-ipu-p4-sdk:10-9-2024")
    lh.run_or_die(f"podman push {imgReg.url()}/intel-ipu-p4-sdk:10-9-2024")
    uname = acc.run("uname -r").out.strip()
    logger.info("Manually starting P4 container")
    cmd = f"podman run --network host -d --privileged --entrypoint='[\"/bin/sh\", \"-c\", \"sleep 5; sh /entrypoint.sh\"]' -v /lib/modules/{uname}:/lib/modules/{uname} -v data1:/opt/p4 {imgReg.url()}/intel-ipu-p4-sdk:10-9-2024"
    acc.run_or_die(cmd)
    # Occasionally the P4 pod fails to start
    while True:
        time.sleep(10)
        if "intel-ipu-p4-sdk:10-9-2024" in acc.run("podman ps").out:
            break
        logger.info("Failed to start p4 container, retrying")
        acc.run_or_die(cmd)


def ExtraConfigDpu(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to start DPU operator on IPU")

    repo = cfg.dpu_operator_path
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

    # Build and start vsp on DPU
    vendor_plugin = init_vendor_plugin(acc, dpu_node.kind or "")
    if isinstance(vendor_plugin, IpuPlugin):
        # TODO: Remove when this container is properly started by the vsp
        # We need to manually start the p4 sdk container currently for the IPU plugin
        ensure_p4_pod_running(lh, acc, imgReg)

        # Build on the ACC since an aarch based server is needed for the build
        # (the Dockerfile needs to be fixed to allow layered multi-arch build
        # by removing the calls to pip)
        vsp_img = vendor_plugin.build_push(acc, imgReg, cfg.ipu_plugin_sha)

        # As a workaround while waiting for properly multiarch build support, we can create a manifest to ensure both host and dpu can deploy the vsp with the same image.
        # Note that this makes the assumption that the host deployment has already been run and the latest ipu plugin image is already locally available in the registry.
        # Without these assumptions, this will not work as expected
        manifest = f"{vsp_img}-manifest"
        lh.run(f"buildah manifest rm {manifest}")
        lh.run_or_die(f"buildah manifest create {manifest}")
        lh.run_or_die(f"podman pull {vsp_img}-x86_64")
        lh.run_or_die(f"podman pull {vsp_img}-aarch64")
        lh.run_or_die(f"buildah manifest add {manifest} {vsp_img}-x86_64")
        lh.run_or_die(f"buildah manifest add {manifest} {vsp_img}-aarch64")
        lh.run_or_die(f"buildah manifest push --all {manifest} docker://{vsp_img}")

    git_repo_setup(repo, repo_wipe=False, url=DPU_OPERATOR_REPO)
    if cfg.rebuild_dpu_operators_images:
        dpu_operator_build_push(repo)
    else:
        logger.info("Will not rebuild dpu-operator images")
    dpu_operator_start(client, repo)

    # Deploy dpu daemon
    client.oc_run_or_die(f"label no {dpu_node.name} dpu=true")
    logger.info("Waiting for all pods to become ready")
    client.oc_run_or_die("wait --for=condition=Ready pod --all --all-namespaces --timeout=2m")
    client.oc_run_or_die(f"create -f {repo}/examples/dpu.yaml")
    wait_vsp_ds_running(client)
    client.oc_run_or_die("wait --for=condition=Ready pod --all --all-namespaces --timeout=3m")
    logger.info("Finished setting up dpu operator on dpu")


def ExtraConfigDpuHost(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    logger.info("Running post config step to start DPU operator on Host")
    lh = host.LocalHost()
    client = K8sClient(cc.kubeconfig)
    repo = cfg.dpu_operator_path

    imgReg = _ensure_local_registry_running(lh, delete_all=False)
    imgReg.ocp_trust(client)
    # Need to trust the registry in OCP / Microshift
    logger.info("Ensuring local registry is trusted in OCP")

    node = cc.workers[0]
    h = host.Host(node.node)
    h.ssh_connect("core")
    vendor_plugin = init_vendor_plugin(h, node.kind or "")
    if isinstance(vendor_plugin, IpuPlugin):
        vendor_plugin.build_push(lh, imgReg, cfg.ipu_plugin_sha)

    git_repo_setup(repo, branch="main", repo_wipe=False, url=DPU_OPERATOR_REPO)
    if cfg.rebuild_dpu_operators_images:
        dpu_operator_build_push(repo)
    else:
        logger.info("Will not rebuild dpu-operator images")
    dpu_operator_start(client, repo)

    def helper(h: host.Host, node: NodeConfig) -> Optional[host.Result]:
        # Temporary workaround, remove once 4.16 installations are working
        logger.info("Ensuring Rhel 9.4 kernel is installed")
        ensure_rhel_9_4_kernel_is_installed(h)
        # There is a bug with the idpf driver that causes the IPU to fail to be enumerated over PCIe on boot
        # As a result, we will need to trigger cold boots of the node until the device is available
        # TODO: Remove when no longer needed
        retries = 3
        h.ssh_connect("core")
        ret = h.run(f"test -d /sys/class/net/{cfg.dpu_net_interface}")
        while ret.returncode != 0:
            logger.error(f"{h.hostname()} does not have a network device {cfg.dpu_net_interface} cold booting node to try to recover")
            h.cold_boot()
            logger.info("Cold boot triggered, waiting for host to reboot")
            time.sleep(60)
            h.ssh_connect("core")
            retries = retries - 1
            if retries == 0:
                logger.error_and_exit(f"Failed to bring up IPU net device on {h.hostname()}")
            ret = h.run(f"test -d /sys/class/net/{cfg.dpu_net_interface}")

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
    wait_vsp_ds_running(client)
    client.oc_run_or_die("wait --for=condition=Ready pod --all -n openshift-dpu-operator --timeout=5m")
    logger.info("Finished setting up dpu operator on host")


def main() -> None:
    pass


if __name__ == "__main__":
    main()
