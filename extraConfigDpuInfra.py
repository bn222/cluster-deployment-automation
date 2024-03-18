from concurrent.futures import ThreadPoolExecutor
from clustersConfig import ClustersConfig
import host
import time
from git.repo import Repo
from k8sClient import K8sClient
from concurrent.futures import Future
import os
import sys
import shutil
from common_patches import apply_common_pathches
from typing import Dict
from typing import List
from typing import Optional
from logger import logger
from clustersConfig import ExtraConfigArgs


def install_remotely(ip: str, links: List[str]) -> bool:
    try:
        return install_remotelyh(ip, links)
    except Exception as e:
        logger.info(e)
    return False


def install_remotelyh(ip: str, links: List[str]) -> bool:
    logger.info(f"connecting to {ip}")
    rh = host.RemoteHost(ip)
    # Eventhough a buggy kernel can cause connections to drop,
    # disconnects are handled seamlessly
    rh.ssh_connect("core")

    want = "4.18.0-372.35.1.el8_6.mr3440_221116_1544.aarch64"
    if want in rh.run("uname -a").out:
        logger.info(f"kernel already installed on {ip}, skipping")
        return True
    else:
        logger.info(f"installing kernel on {ip}")

    wd = "working_dir"
    rh.run(f"rm -rf {wd}")
    rh.run(f"mkdir -p {wd}")
    logger.info(links)

    for e in links:
        fn = e.split("/")[-1]
        cmd = f"curl -k {e} --create-dirs > {wd}/{fn}"
        rh.run(cmd)

    logger.info("result: %s", rh.run("sudo rpm-ostree").out)

    cmd = f"sudo rpm-ostree override replace {wd}/*.rpm"
    logger.info(cmd)
    while True:
        ret = rh.run(cmd).out.strip().split("\n")
        if ret and ret[-1] == 'Run "systemctl reboot" to start a reboot':
            break
        else:
            logger.info(ret)
            logger.info("Output was something unexpected")

    rh.run("sudo systemctl reboot")
    time.sleep(10)
    rh.ssh_connect("core")
    return want in rh.run("uname -a").out


def install_custom_kernel(lh: host.Host, client: K8sClient, bf_names: List[str], ips: List[str]) -> None:
    logger.info(f"Installing custom kernel on {ips}")
    links = [
        "https://s3.upshift.redhat.com/DH-PROD-CKI/internal-artifacts/696717272/build%20aarch64/3333360250/artifacts/kernel-core-4.18.0-372.35.1.el8_6.mr3440_221116_1544.aarch64.rpm",
        "https://s3.upshift.redhat.com/DH-PROD-CKI/internal-artifacts/696717272/build%20aarch64/3333360250/artifacts/kernel-4.18.0-372.35.1.el8_6.mr3440_221116_1544.aarch64.rpm",
        "https://s3.upshift.redhat.com/DH-PROD-CKI/internal-artifacts/696717272/build%20aarch64/3333360250/artifacts/kernel-modules-4.18.0-372.35.1.el8_6.mr3440_221116_1544.aarch64.rpm",
        "https://s3.upshift.redhat.com/DH-PROD-CKI/internal-artifacts/696717272/build%20aarch64/3333360250/artifacts/kernel-modules-extra-4.18.0-372.35.1.el8_6.mr3440_221116_1544.aarch64.rpm",
        "http://download.eng.bos.redhat.com/brewroot/vol/rhel-8/packages/linux-firmware/20220210/108.git6342082c.el8_6/noarch/linux-firmware-20220210-108.git6342082c.el8_6.noarch.rpm",
    ]

    executor = ThreadPoolExecutor(max_workers=len(ips))

    for retry in range(10):
        futures = []

        for h in ips:
            futures.append(executor.submit(install_remotely, h, links))

        results = [f.result() for f in futures]
        if not all(results):
            logger.info(f"failed, retried {retry} times uptill now")
            logger.info(results)
        else:
            logger.info("finished installing custom kernels")
            break

    for bf, ip in zip(bf_names, ips):
        if ip is None:
            sys.exit(-1)
        rh = host.RemoteHost(ip)
        rh.ssh_connect("core")

        def cb() -> None:
            host.sync_time(lh, rh)

        client.wait_ready(bf, cb)


def run_dpu_network_operator_git(lh: host.Host, kc: str) -> None:
    repo_dir = "/root/dpu-network-operator"
    # url = "https://github.com/openshift/dpu-network-operator.git"
    # url = "https://github.com/bn222/dpu-network-operator"
    url = "https://github.com/wizhaoredhat/dpu-network-operator.git"

    if os.path.exists(repo_dir):
        logger.info(f"Repo exists at {repo_dir}, deleting it")
        shutil.rmtree(repo_dir)
    logger.info(f"Cloning repo to {repo_dir}")
    Repo.clone_from(url, repo_dir, branch='dpu_ovn_ic_changes')

    cur_dir = os.getcwd()
    os.chdir(repo_dir)
    lh.run("rm -rf bin")
    env = os.environ.copy()
    env["KUBECONFIG"] = kc
    env["IMG"] = "quay.io/wizhao/dpu-network-operator:Nov1_WZ_DPU_DS_Test_1"
    # cleanup first, to make this script idempotent
    logger.info("running make undeploy")
    logger.info(lh.run("make undeploy", env=env))
    logger.info("running make deploy")
    logger.info(lh.run("make deploy", env=env))
    os.chdir(cur_dir)


def restart_ovs_configuration(ips: List[str]) -> None:
    logger.info("Restarting ovs config")

    for ip in ips:
        rh = host.RemoteHost(ip)
        rh.ssh_connect("core")
        rh.run("sudo systemctl restart ovs-configuration")


def ExtraConfigDpuInfra(cc: ClustersConfig, _: ExtraConfigArgs, futures: Dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    kc = "/root/kubeconfig.infracluster"
    client = K8sClient(kc)
    lh = host.LocalHost()
    apply_common_pathches(client)

    bf_names = [x.name for x in cc.workers if x.kind == "bf"]
    ips = [client.get_ip(e) for e in bf_names]

    for bf, ip in zip(bf_names, ips):
        if ip is None:
            sys.exit(-1)
        rh = host.RemoteHost(ip)
        rh.ssh_connect("core")

        def cb() -> None:
            host.sync_time(lh, rh)

        client.wait_ready(bf, cb)

    # workaround, this will reboot the BF
    # install_custom_kernel(lh, client, bf_names, ips)

    lh.run("dnf install -y golang")

    # workaround, subscription based install broken
    run_dpu_network_operator_git(lh, kc)

    logger.info("Waiting for pod to be in running state")
    while True:
        pods = client._client.list_namespaced_pod("openshift-dpu-network-operator").items
        if len(pods) == 1:
            if pods[0].status.phase == "Running":
                break
            logger.info(f"Pod is in {pods[0].status.phase} state")
        elif len(pods) > 1:
            logger.info("unexpected number of pods")
            sys.exit(-1)
        time.sleep(5)

    logger.info("Creating namespace for tenant")
    client.oc("create -f manifests/infra/ns.yaml")

    logger.info("Creating DpuClusterConfig cr")
    client.oc("create -f manifests/infra/dpuclusterconfig.yaml")

    logger.info("Patching mcp setting maxUnavailable to 2")
    client.oc("patch mcp dpu --type=json -p=\\[\\{\"op\":\"replace\",\"path\":\"/spec/maxUnavailable\",\"value\":2\\}\\]")

    logger.info("Labeling nodes")
    for b in bf_names:
        client.oc(f"label node {b} node-role.kubernetes.io/dpu-worker=")

    logger.info("Creating config map")
    logger.info(client.oc("create -f manifests/infra/cm.yaml"))

    for b in bf_names:
        client.oc(f"label node {b} network.operator.openshift.io/dpu=")
    logger.info("Waiting for mcp to be ready")
    client.wait_for_mcp("dpu", "cm.yaml")

    for b in bf_names:
        ip = client.get_ip(b)
        if ip is None:
            logger.error("Failed to get ip for {b}")
            sys.exit(-1)
        rh = host.RemoteHost(ip)
        rh.ssh_connect("core")
        result = rh.run("sudo ovs-vsctl show")
        if "c1pf0hpf" not in result.out:
            logger.info(result.out)
            logger.info("Did not find interface c1pf0hpf in br-ex. Try to restart ovs-configuration on node.")
            sys.exit(-1)


# VF Management port requires a new API. We need a new extra config class to handle the API changes.
def ExtraConfigDpuInfra_NewAPI(cc: ClustersConfig, _: ExtraConfigArgs, futures: Dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    kc = "/root/kubeconfig.infracluster"
    client = K8sClient(kc)
    lh = host.LocalHost()
    apply_common_pathches(client)

    bf_names = [x.name for x in cc.workers if x.kind == "bf"]
    ips = [client.get_ip(e) for e in bf_names]

    for bf, ip in zip(bf_names, ips):
        if ip is None:
            sys.exit(-1)
        rh = host.RemoteHost(ip)
        rh.ssh_connect("core")

        def cb() -> None:
            host.sync_time(lh, rh)

        client.wait_ready(bf, cb)

    # workaround, this will reboot the BF
    # install_custom_kernel(lh, client, bf_names, ips)

    lh.run("dnf install -y golang")

    # workaround, subscription based install broken
    run_dpu_network_operator_git(lh, kc)

    logger.info("Waiting for pod to be in running state")
    while True:
        pods = client._client.list_namespaced_pod("openshift-dpu-network-operator").items
        if len(pods) == 1:
            if pods[0].status.phase == "Running":
                break
            logger.info(f"Pod is in {pods[0].status.phase} state")
        elif len(pods) > 1:
            logger.info("unexpected number of pods")
            sys.exit(-1)
        time.sleep(5)

    logger.info("Creating namespace for tenant")
    client.oc("create -f manifests/infra/ns.yaml")

    logger.info("Creating DpuClusterConfig cr")
    client.oc("create -f manifests/infra/dpuclusterconfig.yaml")

    logger.info("Patching mcp setting maxUnavailable to 2")
    client.oc("patch mcp dpu --type=json -p=\\[\\{\"op\":\"replace\",\"path\":\"/spec/maxUnavailable\",\"value\":2\\}\\]")

    logger.info("Labeling nodes")
    for b in bf_names:
        client.oc(f"label node {b} node-role.kubernetes.io/dpu-worker=")

    # DELTA: No need to create config map to set dpu mode. https://github.com/openshift/cluster-network-operator/pull/1676

    for b in bf_names:
        client.oc(f"label node {b} network.operator.openshift.io/dpu=")
    logger.info("Waiting for mcp to be ready")
    client.wait_for_mcp("dpu", "dpu mcp patch")

    for b in bf_names:
        ip = client.get_ip(b)
        if ip is None:
            logger.error(f"Failed to get ip for node {b}")
            sys.exit(-1)
        rh = host.RemoteHost(ip)
        rh.ssh_connect("core")
        result = rh.run("sudo ovs-vsctl show")
        if "c1pf0hpf" not in result.out:
            logger.info(result.out)
            logger.info("Did not find interface c1pf0hpf in br-ex. Try to restart ovs-configuration on node.")
            sys.exit(-1)


def main() -> None:
    pass


if __name__ == "__main__":
    main()
