from git import Repo
from k8sClient import K8sClient
import os
import host
import time


def deploy_sriov_network_operator(client: K8sClient):
    lh = host.LocalHost()
    repo_dir = "/root/sriov-network-operator"
    url = "https://github.com/openshift/sriov-network-operator.git"

    if os.path.exists(repo_dir):
        print(f"Repo exists at {repo_dir}, not touching it")
    else:
        print(f"Cloning repo to {repo_dir}")
        Repo.clone_from(url, repo_dir)

    cur_dir = os.getcwd()
    os.chdir(repo_dir)
    env = os.environ.copy()
    env["KUBECONFIG"] = client._kc
    # cleanup first, to make this script idempotent
    print("running make undeploy")
    print(lh.run("make undeploy", env))
    print("running make deploy-setup")
    time.sleep(60)
    print("Waiting for mcp dpu-host to become ready")
    client.oc("wait mcp dpu-host --for condition=updated --timeout=50m")
    print(lh.run("make deploy-setup", env).out)
    os.chdir(cur_dir)


class ExtraConfigDpuTenant:
    def __init__(self, cc):
        self._cc = cc

    def run(self, cfg):
        print("Running post config step")

        tclient = K8sClient("/root/kubeconfig.tenantcluster")
        print("Apply DPU tenant mc")
        tclient.oc("create -f manifests/tenant/dputenantmachineconfig.yaml")
        time.sleep(60)
        print("Waiting for mcp to be updated")
        tclient.oc("wait mcp dpu-host --for condition=updated")
        print("Labeling nodes")
        for e in self._cc["workers"]:
            cmd = f"label node {e['name']} node-role.kubernetes.io/dpu-host="
            print(tclient.oc(cmd))
        print("Deploying sriov network operator")
        deploy_sriov_network_operator(tclient)
        print("Creating sriov pool config")
        tclient.oc("create -f manifests/tenant/sriov-pool-config.yaml")
        tclient.oc("create -f manifests/tenant/SriovNetworkNodePolicy.yaml")
        print("Waiting for mcp to be updated")
        time.sleep(60)
        tclient.oc("wait mcp dpu-host --for condition=updated --timeout=50m")

        print("creating config map to put ovn-k into dpu host mode")
        tclient.oc("create -f manifests/tenant/sriovdpuconfigmap.yaml")
        print("creating mc to disable ovs")
        tclient.oc("create -f manifests/tenant/disable-ovs.yaml")
        print("Waiting for mcp")
        time.sleep(60)
        tclient.oc("wait mcp dpu-host --for condition=updated --timeout=50m")

        print("setting ovn kube node env-override to set management port")
        print(os.getcwd())
        contents = open("manifests/tenant/setenvovnkube.yaml").read()
        for e in cfg["mapping"]:
            a = {}
            a["OVNKUBE_NODE_MGMT_PORT_NETDEV"] = "ens1f0v0"
            contents += f"  {e['worker']}: |\n"
            for (k, v) in a.items():
                contents += f"    {k}={v}\n"
        open("/tmp/1.yaml", "w").write(contents)

        print("Running create")
        print(tclient.oc("create -f /tmp/1.yaml"))

        for e in self._cc["workers"]:
            cmd = f"label node {e['name']} network.operator.openshift.io/dpu-host="
            print(tclient.oc(cmd))
            rh = host.RemoteHost(tclient.get_ip(e['name']))
            rh.ssh_connect("core")
            # workaround for https://issues.redhat.com/browse/NHE-335
            print(rh.run2("sudo ovs-vsctl del-port br-int ovn-k8s-mp0"))

        print("Final infrastructure cluster configuration")
        iclient = K8sClient("/root/kubeconfig.infracluster")

        # https://issues.redhat.com/browse/NHE-334
        for e in iclient.get_nodes():
            ip = iclient.get_ip(e)
            rh = host.RemoteHost(ip)
            rh.ssh_connect("core")
            cmd = f"echo \'{self._cc['api_ip']} api.{self._cc['name']}.redhat.com\' | sudo tee -a /etc/hosts"
            print(rh.run2(cmd))
        print(iclient.oc(f"create secret generic tenant-cluster-1-kubeconf --from-file=config={tclient._kc}"))

        contents = open("manifests/tenant/envoverrides.yaml").read()
        for e in cfg["mapping"]:
            a = {}
            a["TENANT_K8S_NODE"] = e['worker']
            a["DPU_IP"] = iclient.get_ip(e['bf'])
            a["MGMT_IFNAME"] = "eth1"
            contents += f"  {e['bf']}: |\n"
            for (k, v) in a.items():
                contents += f"    {k}={v}\n"
        open("/tmp/envoverrides.yaml", "w").write(contents)

        iclient.oc("create -f /tmp/envoverrides.yaml")
        iclient.oc("patch --type merge -p {\"spec\":{\"kubeConfigFile\":\"tenant-cluster-1-kubeconf\"}} OVNKubeConfig ovnkubeconfig-sample")
        print("Creating network attachement definition")
        tclient.oc("create -f manifests/tenant/nad.yaml")


def main():
    pass


if __name__ == "__main__":
    main()
