from concurrent.futures import ThreadPoolExecutor
import host
import time
from git import Repo
from k8sClient import K8sClient
import os
import sys
import shutil

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

def install_custom_kernel(ips):
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


def run_dpu_network_operator_git(lh, kc):
    repo_dir = "/root/dpu-network-operator"
    url = "https://github.com/bn222/dpu-network-operator.git"

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
    env["IMG"] = "quay.io/bnemeth/dpu-network-operator"
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

    def run(self, cfg):
        kc = "/root/kubeconfig.infracluster"
        client = K8sClient(kc)
        lh = host.LocalHost()

        bf_names = [x["name"] for x in self._cc["workers"] if x["type"] == "bf"]
        ips = [client.get_ip(e) for e in bf_names]
        for bf in bf_names:
            client.wait_ready(bf)

        # workaround, this will reboot the BF
        install_custom_kernel(ips)
        for bf in bf_names:
            client.wait_ready(bf)

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

        print("Creating OVNKubeConfig cr")
        client.oc("create -f manifests/infra/ovnkubeconfig.yaml")

        print("Labeling nodes")
        for b in bf_names:
            client.oc(f"label node {b} node-role.kubernetes.io/dpu-worker=")

        print("Creating config map")
        print(client.oc("create -f manifests/infra/cm.yaml"))

        for b in bf_names:
            client.oc(f"label node {b} network.operator.openshift.io/dpu=")
        print("Waiting for mcp to be ready")
        time.sleep(60)
        client.oc("wait mcp dpu --for condition=updated --timeout=50m")

        # https://issues.redhat.com/browse/NHE-325
        good = {b: False for b in bf_names}
        while not all(good.values()):
            time.sleep(60)
            client.oc("wait mcp dpu --for condition=updated --timeout=50m")
            for b in bf_names:
                ip = client.get_ip(b)
                rh = host.RemoteHost(ip)
                rh.ssh_connect("core")
                result = rh.run("sudo ovs-vsctl show")
                good[b] = "enp3s0f0nc1pf0" in result.out
                if not good[b]:
                    print(f"Applying workaround (NHE-325) to {b}")
                    rh.run("sudo systemctl restart ovs-configuration")


def main():
    pass


if __name__ == "__main__":
    main()
