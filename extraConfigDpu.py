from clustersConfig import ClustersConfig, NodeConfig
import host
from k8sClient import K8sClient
from concurrent.futures import Future, ThreadPoolExecutor
import jinja2
import re
import os
import requests
import time
from typing import Optional, Match
from logger import logger
from clustersConfig import ExtraConfigArgs
import reglocal
from common import git_repo_setup
from dpuVendor import init_vendor_plugin, IpuPlugin

DPU_OPERATOR_REPO = "https://github.com/openshift/dpu-operator.git"
MICROSHIFT_KUBECONFIG = "/var/lib/microshift/resources/kubeadmin/kubeconfig"
OSE_DOCKERFILE = "https://pkgs.devel.redhat.com/cgit/containers/dpu-operator/tree/Dockerfile?h=rhaos-4.17-rhel-9"
REPO_DIR = "/root/dpu-operator"
SRIOV_NUM_VFS = 8


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


def _ensure_local_registry_running(rsh: host.Host, delete_all: bool = False) -> str:
    logger.info(f"creating local registry on {rsh.hostname()}")
    _, reglocal_hostname, reglocal_listen_port, _ = reglocal.ensure_running(rsh, delete_all=delete_all)
    reglocal.local_trust(rsh)
    registry = f"{reglocal_hostname}:{reglocal_listen_port}"
    return registry


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
        host.run_or_die(f"tar -C /usr/local -xzf {go_tarball}")
        host.run("rm -rf /usr/local/go")
        host.run("rm -rf /usr/bin/go")
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


def build_dpu_operator_images() -> str:
    logger.info("Building dpu operator images")
    lh = host.LocalHost()
    git_repo_setup(REPO_DIR, repo_wipe=True, url=DPU_OPERATOR_REPO, branch="main")
    update_dockerfiles_with_ose_images(REPO_DIR)

    # Start a local registry to store dpu-operator images
    registry = _ensure_local_registry_running(lh, delete_all=True)
    reglocal.local_trust(lh)

    operator_image = f"{registry}/openshift-dpu-operator/cda-dpu-operator:latest"
    daemon_image = f"{registry}/openshift-dpu-operator/cda-dpu-daemon:latest"
    render_local_images_yaml(operator_image=operator_image, daemon_image=daemon_image, outfilename=f"{REPO_DIR}/config/dev/local-images.yaml")

    lh.run_or_die(f"make -C {REPO_DIR} images-buildx")

    return registry


def start_dpu_operator(host: host.Host, client: K8sClient, operator_image: str, daemon_image: str, repo_wipe: bool = False) -> None:
    logger.info(f"Deploying dpu operator containers on {host.hostname()}")
    if repo_wipe:
        host.run(f"rm -rf {REPO_DIR}")
        host.run_or_die(f"git clone {DPU_OPERATOR_REPO}")
        render_local_images_yaml(operator_image=operator_image, daemon_image=daemon_image, outfilename="/tmp/dpu-local-images.yaml", pull_policy="IfNotPresent")
        host.copy_to("/tmp/dpu-local-images.yaml", f"{REPO_DIR}/config/dev/local-images.yaml")

    host.run_or_die("pip install yq")
    ensure_go_installed(host)
    reglocal.local_trust(host)
    host.run_or_die(f"podman pull {operator_image}")
    host.run_or_die(f"podman pull {daemon_image}")
    if host.is_localhost():
        env = os.environ.copy()
        env["KUBECONFIG"] = client._kc
        host.run(f"make -C {REPO_DIR} undeploy", env=env)
        ret = host.run(f"make -C {REPO_DIR} local-deploy", env=env)
        if not ret.success():
            logger.error_and_exit("Failed to deploy dpu operator")
    else:
        host.run(f"cd {REPO_DIR} && export KUBECONFIG={client._kc} && make undeploy")
        host.run_or_die(f"cd {REPO_DIR} && export KUBECONFIG={client._kc} && make local-deploy")
    logger.info("Waiting for all pods to become ready")


def render_local_images_yaml(operator_image: str, daemon_image: str, outfilename: str, pull_policy: str = "Always") -> None:
    with open('./manifests/dpu/local-images.yaml.j2') as f:
        j2_template = jinja2.Template(f.read())
        rendered = j2_template.render(operator_image=operator_image, daemon_image=daemon_image, pull_policy=pull_policy)
        logger.info(rendered)

    with open(outfilename, "w") as outFile:
        outFile.write(rendered)


def ExtraConfigDpu(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to start DPU operator on IPU")

    dpu_node = cc.masters[0]
    assert dpu_node.ip is not None
    acc = host.Host(dpu_node.ip)
    lh = host.LocalHost()
    acc.ssh_connect("root", "redhat")
    client = K8sClient(MICROSHIFT_KUBECONFIG, acc)

    if cfg.rebuild_dpu_operators_images:
        registry = build_dpu_operator_images()
    else:
        registry = _ensure_local_registry_running(lh, delete_all=False)

    operator_image = f"{registry}/openshift-dpu-operator/cda-dpu-operator:latest"
    daemon_image = f"{registry}/openshift-dpu-operator/cda-dpu-daemon:latest"

    # Build and start vsp on DPU
    vendor_plugin = init_vendor_plugin(acc)
    if isinstance(vendor_plugin, IpuPlugin):
        # TODO: Remove when this container is properly started by the vsp
        # We need to manually start the p4 sdk container currently for the IPU plugin
        img = "quay.io/sdaniele/intel-ipu-p4-sdk:temp_wa_5-28-24"
        cmd = f"podman run --network host -d --privileged --entrypoint='[\"/bin/sh\", \"-c\", \"sleep 5; sh /entrypoint.sh\"]' -v /lib/modules/5.14.0-425.el9.aarch64:/lib/modules/5.14.0-425.el9.aarch64 -v data1:/opt/p4 {img}"
        logger.info("Manually starting P4 container")
        acc.run_or_die(cmd)
    vendor_plugin.build_and_start(acc, client, registry)

    start_dpu_operator(acc, client, operator_image, daemon_image, repo_wipe=True)

    # Disable firewall to ensure host-side can reach dpu
    acc.run("systemctl stop firewalld")
    acc.run("systemctl disable firewalld")

    # Deploy dpu daemon
    client.oc_run_or_die(f"label no {dpu_node.name} dpu=true")
    logger.info("Waiting for all pods to become ready")
    client.oc_run_or_die("wait --for=condition=Ready pod --all --all-namespaces --timeout=2m")
    client.oc_run_or_die(f"create -f {REPO_DIR}/examples/dpu.yaml")
    time.sleep(30)

    # TODO: remove wa once fixed in future versions of MeV
    # Wait for dpu to restart after vsp triggers reboot
    # Note, this will fail if the acc comes up with a new MAC address on the physical port.
    # As a temporary workaround until this issue is resolved, pre-load the rh_mvp.pkg / configure the iscsi attempt
    # to ensure the MAC remains consistent across reboots
    acc.ssh_connect("root", "redhat")
    cmd = f"podman run --network host -d --privileged --entrypoint='[\"/bin/sh\", \"-c\", \"sleep 5; sh /entrypoint.sh\"]' -v /lib/modules/5.14.0-425.el9.aarch64:/lib/modules/5.14.0-425.el9.aarch64 -v data1:/opt/p4 {img}"
    logger.info("Manually restarting P4 container")
    acc.run_or_die(cmd)
    acc.run_or_die("systemctl restart microshift")
    client.oc_run_or_die("wait --for=condition=Ready pod --all --all-namespaces --timeout=2m")
    logger.info("Finished setting up dpu operator on dpu")


def ExtraConfigDpuHost(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    logger.info("Running post config step to start DPU operator on Host")

    lh = host.LocalHost()
    client = K8sClient(cc.kubeconfig)

    if cfg.rebuild_dpu_operators_images:
        registry = build_dpu_operator_images()
    else:
        registry = _ensure_local_registry_running(lh, delete_all=False)
    operator_image = f"{registry}/openshift-dpu-operator/cda-dpu-operator:latest"
    daemon_image = f"{registry}/openshift-dpu-operator/cda-dpu-daemon:latest"

    # Need to trust the registry in OCP / Microshift
    reglocal.ocp_trust(client, reglocal.get_local_registry_base_directory(lh), reglocal.get_local_registry_hostname(lh), 5000)

    h = host.Host(cc.workers[0].node)
    vendor_plugin = init_vendor_plugin(h)
    vendor_plugin.build_and_start(lh, client, registry)

    start_dpu_operator(lh, client, operator_image, daemon_image)
    client.oc_run_or_die("wait --for=condition=Ready pod --all -n dpu-operator-system --timeout=2m")

    def helper(h: host.Host, node: NodeConfig) -> Optional[host.Result]:
        logger.info(f"Manually creating vfs for host {h.hostname()}")
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

    logger.info("Completed creation of vfs on DPU worker nodes")

    # Create host nad
    # TODO: Remove when this is automatically created by the dpu operator
    client.oc("delete -f manifests/dpu/dpu_nad.yaml")
    client.oc_run_or_die("create -f manifests/dpu/dpu_nad.yaml")
    # Deploy dpu daemon and wait for dpu pods to come up
    client.oc_run_or_die(f"create -f {REPO_DIR}/examples/dpu.yaml")
    time.sleep(30)
    client.oc_run_or_die("wait --for=condition=Ready pod --all -n dpu-operator-system --timeout=2m")
    logger.info("Finished setting up dpu operator on host")


def main() -> None:
    pass


if __name__ == "__main__":
    main()
