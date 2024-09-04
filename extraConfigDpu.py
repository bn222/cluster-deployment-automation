from clustersConfig import ClustersConfig, NodeConfig
import host
from k8sClient import K8sClient
from concurrent.futures import Future, ThreadPoolExecutor
import re
import os
import requests
import time
from typing import Optional, Match
from logger import logger
from clustersConfig import ExtraConfigArgs
import imageRegistry
from common import git_repo_setup
from dpuVendor import init_vendor_plugin, IpuPlugin, MarvellDpuPlugin
from imageRegistry import ImageRegistry

DPU_OPERATOR_REPO = "https://github.com/openshift/dpu-operator.git"
MICROSHIFT_KUBECONFIG = "/root/kubeconfig.microshift"
OSE_DOCKERFILE = "https://pkgs.devel.redhat.com/cgit/containers/dpu-operator/tree/Dockerfile?h=rhaos-4.17-rhel-9"
REPO_DIR = "/root/dpu-operator"

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


def _update_dockerfile(image: str, path: str) -> None:
    with open(path, 'r') as file:
        dockerfile_contents = file.read()

    # Update only the non-builder image
    pattern = re.compile(r'^FROM\s+([^\s]+)(?!.*\bAS\b.*$)', re.MULTILINE)

    def replace_image(match: Match[str]) -> str:
        return f"FROM {image}"

    new_dockerfile_contents = pattern.sub(replace_image, dockerfile_contents)

    with open(path, 'w') as file:
        file.write(new_dockerfile_contents)


def _get_ose_image(dockerfile_url: str) -> str:
    logger.info("Fetching")
    request = requests.get(dockerfile_url, verify=False)
    image = None
    for line in request.text.split("\n"):
        if line.startswith("FROM"):
            image = line.split(" ")[1]
    if image:
        src = "openshift/"
        dst = "registry-proxy.engineering.redhat.com/rh-osbs/openshift-"
        return image.replace(src, dst)
    else:
        logger.error_and_exit(f"Failed to parse base image from {dockerfile_url}")


def update_dockerfiles_with_ose_images(repo: str, dockerfile_url: str = OSE_DOCKERFILE) -> None:
    image = _get_ose_image(dockerfile_url)
    for file in [f"{REPO_DIR}/Dockerfile.rhel", f"{REPO_DIR}/Dockerfile.daemon.rhel"]:
        _update_dockerfile(image, file)


def _ensure_local_registry_running(rsh: host.Host, delete_all: bool = False) -> ImageRegistry:
    logger.info(f"Ensuring local registry running on {rsh.hostname()}")
    imgReg = imageRegistry.ImageRegistry(rsh)
    imgReg.ensure_running(delete_all=delete_all)
    imgReg.trust(host.LocalHost())
    return imgReg


def go_is_installed(host: host.Host) -> bool:
    ret = host.run("go version")
    if ret.returncode == 0:
        installed_version = ret.out.strip().split(' ')[2]
        if installed_version.startswith("go1.22"):
            return True
    return False


def download_go(host: host.Host, go_tarball: str, temp_file: str) -> None:
    url = f"https://go.dev/dl/{go_tarball}"

    response = requests.get(url, stream=True)
    if response.status_code == 200:
        with open(temp_file, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
    else:
        raise Exception(f"Failed to download {url}")


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

    if host.is_localhost():
        temp_file = f"/tmp/{go_tarball}"
        retries = 10
        while True:
            try:
                download_go(host, go_tarball, temp_file)
                break
            except Exception as e:
                logger.info(f"Failed to download {go_tarball}, retrying")
                retries -= 1
                if retries <= 0:
                    raise e
                time.sleep(1)

        host.run("rm -rf /usr/local/go")
        host.run("rm -rf /usr/bin/go")
        host.run_or_die(f"tar -C /usr/local -xzf {temp_file}")
        current_path = os.environ.get('PATH', '')
        go_directory = '/usr/local/go/bin'
        if go_directory not in current_path.split(os.pathsep):
            new_path = current_path + os.pathsep + go_directory
            os.environ['PATH'] = new_path
    else:
        host.run_or_die(f"wget https://go.dev/dl/{go_tarball}")
        host.run("rm -rf /usr/local/go")
        host.run("rm -rf /usr/bin/go")
        host.run_or_die(f"tar -C /usr/local -xzf {go_tarball}")
        host.run_or_die("echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile")
        host.run_or_die("echo 'export PATH=$PATH:/usr/local/go/bin' > /etc/profile.d/go.sh")
        host.run_or_die("chmod +x /etc/profile.d/go.sh")
    ret = host.run("go version")
    if not ret.success():
        logger.error_and_exit("Unable to update PATH for a running process, run 'export PATH=$PATH:/usr/local/go/bin' and try again")


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
    vendor_plugin = init_vendor_plugin(acc, dpu_node.kind or "", acc.run("uname -m").out)
    if isinstance(vendor_plugin, IpuPlugin):
        # TODO: Remove when this container is properly started by the vsp
        # We need to manually start the p4 sdk container currently for the IPU plugin
        img = "quay.io/sdaniele/intel-ipu-p4-sdk:temp_wa_5-28-24"
        uname = acc.run("uname -r").out.strip()
        logger.info("Manually starting P4 container")
        cmd = f"podman run --network host -d --privileged --entrypoint='[\"/bin/sh\", \"-c\", \"sleep 5; sh /entrypoint.sh\"]' -v /lib/modules/{uname}:/lib/modules/{uname} -v data1:/opt/p4 {img}"
        acc.run_or_die(cmd)
        vendor_plugin.import_from_url("http://10.26.16.5/ipu-plugin.tar")
        vendor_plugin.push(imgReg)
        vendor_plugin.start(vendor_plugin.vsp_image_name(imgReg), client)
    elif isinstance(vendor_plugin, MarvellDpuPlugin):
        # TODO: Remove when this container is properly started by the vsp
        # We need to manually start the p4 sdk container currently for the IPU plugin
        img = "quay.io/sdaniele/intel-ipu-p4-sdk:temp_wa_5-28-24"
        uname = acc.run("uname -r").out.strip()
        cmd = f"podman run --network host -d --privileged --entrypoint='[\"/bin/sh\", \"-c\", \"sleep 5; sh /entrypoint.sh\"]' -v /lib/modules/{uname}:/lib/modules/{uname} -v data1:/opt/p4 {img}"
        logger.info("Manually starting P4 container")
        acc.run_or_die(cmd)
    else:
        vendor_plugin.build_and_start(lh, client, imgReg)

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
    time.sleep(30)

    # TODO: remove wa once fixed in future versions of MeV
    # Wait for dpu to restart after vsp triggers reboot
    # Note, this will fail if the acc comes up with a new MAC address on the physical port.
    # As a temporary workaround until this issue is resolved, pre-load the rh_mvp.pkg / configure the iscsi attempt
    # to ensure the MAC remains consistent across reboots
    acc.ssh_connect("root", "redhat")
    if isinstance(vendor_plugin, IpuPlugin):
        uname = acc.run("uname -r").out.strip()
        cmd = f"podman run --network host -d --privileged --entrypoint='[\"/bin/sh\", \"-c\", \"sleep 5; sh /entrypoint.sh\"]' -v /lib/modules/{uname}:/lib/modules/{uname} -v data1:/opt/p4 {img}"
        logger.info("Manually restarting P4 container")
        acc.run_or_die(cmd)
    acc.run_or_die("systemctl restart microshift")
    client.oc_run_or_die("wait --for=condition=Ready pod --all --all-namespaces --timeout=2m")
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
    vendor_plugin = init_vendor_plugin(h, node.kind or "")
    vendor_plugin.build_and_start(lh, client, imgReg)

    git_repo_setup(repo, repo_wipe=False, url=DPU_OPERATOR_REPO)
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
        bmc = host.BMC.from_bmc(e.bmc, e.bmc_user, e.bmc_password)
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
    client.oc_run_or_die("wait --for=condition=Ready pod --all -n openshift-dpu-operator --timeout=5m")
    logger.info("Finished setting up dpu operator on host")


def main() -> None:
    pass


if __name__ == "__main__":
    main()
