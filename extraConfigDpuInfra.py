from concurrent.futures import ThreadPoolExecutor
import host
import time
from git import Repo
from k8sClient import K8sClient
from concurrent.futures import Future
import os
import sys
import shutil
from common_patches import apply_common_pathches
from typing import Dict


def install_remotely(ip, links):
    try:
        return install_remotelyh(ip, links)
    except Exception as e:
        print(e)


def install_remotelyh(ip, links):
    print(f"connecting to {ip}")
    rh = host.RemoteHost(ip)
    # Eventhough a buggy kernel can cause connections to drop,
    # disconnects are handled seamlessly
    rh.ssh_connect("core")

    want = "4.18.0-372.35.1.el8_6.mr3440_221116_1544.aarch64"
    if want in rh.run("uname -a").out:
        print(f"kernel already installed on {ip}, skipping")
        return True
    else:
        print(f"installing kernel on {ip}")

    wd = "working_dir"
    rh.run(f"rm -rf {wd}")
    rh.run(f"mkdir -p {wd}")
    print(links)

    for e in links:
        fn = e.split("/")[-1]
        cmd = f"curl -k {e} --create-dirs > {wd}/{fn}"
        rh.run(cmd)

    print("result:", rh.run("sudo rpm-ostree"))

    cmd = f"sudo rpm-ostree override replace {wd}/*.rpm"
    print(cmd)
    while True:
        ret = rh.run(cmd).out.strip().split("\n")
        if ret and ret[-1] == 'Run "systemctl reboot" to start a reboot':
            break
        else:
            print(ret)
            print("Output was something unexpected")

    rh.run("sudo systemctl reboot")
    time.sleep(10)
    rh.ssh_connect("core")
    return want in rh.run("uname -a").out

def install_custom_kernel(lh, client, bf_names, ips):
    print(f"Installing custom kernel on {ips}")
    links = [
      "https://s3.upshift.redhat.com/DH-PROD-CKI/internal-artifacts/696717272/build%20aarch64/3333360250/artifacts/kernel-core-4.18.0-372.35.1.el8_6.mr3440_221116_1544.aarch64.rpm",
      "https://s3.upshift.redhat.com/DH-PROD-CKI/internal-artifacts/696717272/build%20aarch64/3333360250/artifacts/kernel-4.18.0-372.35.1.el8_6.mr3440_221116_1544.aarch64.rpm",
      "https://s3.upshift.redhat.com/DH-PROD-CKI/internal-artifacts/696717272/build%20aarch64/3333360250/artifacts/kernel-modules-4.18.0-372.35.1.el8_6.mr3440_221116_1544.aarch64.rpm",
      "https://s3.upshift.redhat.com/DH-PROD-CKI/internal-artifacts/696717272/build%20aarch64/3333360250/artifacts/kernel-modules-extra-4.18.0-372.35.1.el8_6.mr3440_221116_1544.aarch64.rpm",
      "http://download.eng.bos.redhat.com/brewroot/vol/rhel-8/packages/linux-firmware/20220210/108.git6342082c.el8_6/noarch/linux-firmware-20220210-108.git6342082c.el8_6.noarch.rpm"
    ]

    executor = ThreadPoolExecutor(max_workers=len(ips))

    for retry in range(10):
        futures = []

        for h in ips:
            futures.append(executor.submit(install_remotely, h, links))

        results = list(f.result() for f in futures)
        if not all(results):
            print(f"failed, retried {retry} times uptill now")
            print(results)
        else:
            print("finished installing custom kernels")
            break

    for bf, ip in zip(bf_names, ips):
        if ip is None:
            sys.exit(-1)
        rh = host.RemoteHost(ip)
        rh.ssh_connect("core")

        def cb():
            host.sync_time(lh, rh)
        client.wait_ready(bf, cb)

def run_dpu_network_operator_git(lh, kc):
    repo_dir = "/root/dpu-network-operator"
    url = "https://github.com/openshift/dpu-network-operator.git"

    if os.path.exists(repo_dir):
        print(f"Repo exists at {repo_dir}, deleting it")
        shutil.rmtree(repo_dir)
    print(f"Cloning repo to {repo_dir}")
    Repo.clone_from(url, repo_dir, branch='master')

    cur_dir = os.getcwd()
    os.chdir(repo_dir)
    lh.run("rm -rf bin")
    env = os.environ.copy()
    env["KUBECONFIG"] = kc
    env["IMG"] = "quay.io/wizhao/dpu-network-operator:4-14-may10"
    # cleanup first, to make this script idempotent
    print("running make undeploy")
    print(lh.run("make undeploy", env))
    print("running make deploy")
    print(lh.run("make deploy", env))
    os.chdir(cur_dir)


def restart_ovs_configuration(ips):
    print("Restarting ovs config")

    for ip in ips:
        rh = host.RemoteHost(ip)
        rh.ssh_connect("core")
        rh.run("sudo systemctl restart ovs-configuration")


class ExtraConfigDpuInfra:
    def __init__(self, cc):
        self._cc = cc

    def run(self, _, futures: Dict[str, Future]) -> None:
        [f.result() for (_, f) in futures.items()]
        kc = "/root/kubeconfig.infracluster"
        client = K8sClient(kc)
        lh = host.LocalHost()
        apply_common_pathches(client)

        bf_names = [x["name"] for x in self._cc["workers"] if x["type"] == "bf"]
        ips = [client.get_ip(e) for e in bf_names]

        for bf, ip in zip(bf_names, ips):
            if ip is None:
                sys.exit(-1)
            rh = host.RemoteHost(ip)
            rh.ssh_connect("core")

            def cb():
                host.sync_time(lh, rh)
            client.wait_ready(bf, cb)

        # workaround, this will reboot the BF
        # install_custom_kernel(lh, client, bf_names, ips)

        lh.run("dnf install -y golang")

        # workaround, subscription based install broken
        run_dpu_network_operator_git(lh, kc)

        print("Waiting for pod to be in running state")
        while True:
            pods = client._client.list_namespaced_pod("openshift-dpu-network-operator").items
            if len(pods) == 1:
                if pods[0].status.phase == "Running":
                    break
                print(f"Pod is in {pods[0].status.phase} state")
            elif len(pods) > 1:
                print("unexpected number of pods")
                sys.exit(-1)
            time.sleep(5)

        print("Creating namespace for tenant")
        client.oc("create -f manifests/infra/tenantcluster-dpu.yaml")

        print("Creating OVNKubeConfig cr")
        client.oc("create -f manifests/infra/ovnkubeconfig.yaml")

        print("Patching mcp setting maxUnavailable to 2")
        client.oc("patch mcp dpu --type=json -p=\[\{\"op\":\"replace\",\"path\":\"/spec/maxUnavailable\",\"value\":2\}\]")

        print("Labeling nodes")
        for b in bf_names:
            client.oc(f"label node {b} node-role.kubernetes.io/dpu-worker=")

        print("Creating config map")
        print(client.oc("create -f manifests/infra/cm.yaml"))

        for b in bf_names:
            client.oc(f"label node {b} network.operator.openshift.io/dpu=")
        print("Waiting for mcp to be ready")
        start = time.time()
        time.sleep(60)
        client.oc("wait mcp dpu --for condition=updated --timeout=50m")
        minutes, seconds = divmod(int(time.time() - start), 60)
        print(f"It took {minutes}m {seconds}s to for mcp dpu to update")

        for b in bf_names:
            ip = client.get_ip(b)
            rh = host.RemoteHost(ip)
            rh.ssh_connect("core")
            result = rh.run("sudo ovs-vsctl show")
            if "c1pf0hpf" not in result.out:
                print(result.out)
                print("Did not find interface c1pf0hpf in br-ex. Try to restart ovs-configuration on node.")
                sys.exit(-1)

# VF Management port requires a new API. We need a new extra config class to handle the API changes.
class ExtraConfigDpuInfra_NewAPI(ExtraConfigDpuInfra):
    def run(self, _, futures: Dict[str, Future]) -> None:
        [f.result() for (_, f) in futures.items()]
        kc = "/root/kubeconfig.infracluster"
        client = K8sClient(kc)
        lh = host.LocalHost()
        apply_common_pathches(client)

        bf_names = [x["name"] for x in self._cc["workers"] if x["type"] == "bf"]
        ips = [client.get_ip(e) for e in bf_names]

        for bf, ip in zip(bf_names, ips):
            if ip is None:
                sys.exit(-1)
            rh = host.RemoteHost(ip)
            rh.ssh_connect("core")

            def cb():
                host.sync_time(lh, rh)
            client.wait_ready(bf, cb)

        # workaround, this will reboot the BF
        # install_custom_kernel(lh, client, bf_names, ips)

        lh.run("dnf install -y golang")

        # workaround, subscription based install broken
        run_dpu_network_operator_git(lh, kc)

        print("Waiting for pod to be in running state")
        while True:
            pods = client._client.list_namespaced_pod("openshift-dpu-network-operator").items
            if len(pods) == 1:
                if pods[0].status.phase == "Running":
                    break
                print(f"Pod is in {pods[0].status.phase} state")
            elif len(pods) > 1:
                print("unexpected number of pods")
                sys.exit(-1)
            time.sleep(5)

        print("Creating namespace for tenant")
        client.oc("create -f manifests/infra/tenantcluster-dpu.yaml")

        print("Creating OVNKubeConfig cr")
        client.oc("create -f manifests/infra/ovnkubeconfig.yaml")

        print("Patching mcp setting maxUnavailable to 2")
        client.oc("patch mcp dpu --type=json -p=\[\{\"op\":\"replace\",\"path\":\"/spec/maxUnavailable\",\"value\":2\}\]")

        print("Labeling nodes")
        for b in bf_names:
            client.oc(f"label node {b} node-role.kubernetes.io/dpu-worker=")

        # DELTA: No need to create config map to set dpu mode. https://github.com/openshift/cluster-network-operator/pull/1676

        for b in bf_names:
            client.oc(f"label node {b} network.operator.openshift.io/dpu=")
        print("Waiting for mcp to be ready")
        start = time.time()
        time.sleep(60)
        client.oc("wait mcp dpu --for condition=updated --timeout=50m")
        minutes, seconds = divmod(int(time.time() - start), 60)
        print(f"It took {minutes}m {seconds}s to for mcp dpu to update")

        for b in bf_names:
            ip = client.get_ip(b)
            rh = host.RemoteHost(ip)
            rh.ssh_connect("core")
            result = rh.run("sudo ovs-vsctl show")
            if "c1pf0hpf" not in result.out:
                print(result.out)
                print("Did not find interface c1pf0hpf in br-ex. Try to restart ovs-configuration on node.")
                sys.exit(-1)

def main():
    pass


if __name__ == "__main__":
    main()
