from k8sClient import K8sClient
import os
import host
import time
from extraConfigSriov import ExtraConfigSriov
from extraConfigSriov import ExtraConfigSriovOvSHWOL
import sys
import jinja2

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
        ec = ExtraConfigSriov(self._cc)
        ec.run(cfg)
        print("Waiting for mcp dpu-host to become ready")
        tclient.oc("wait mcp dpu-host --for condition=updated --timeout=50m")

        first_worker = self._cc["workers"][0]['name']
        ip = tclient.get_ip(first_worker)
        if ip is None:
            sys.exit(-1)
        rh = host.RemoteHost(ip)
        rh.ssh_connect("core")
        bf = [x for x in rh.run("lspci").out.split("\n") if "BlueField" in x]
        if not bf:
            print(f"Couldn't find BF on {first_worker}")
            sys.exit(-1)
        bf = bf[0].split(" ")[0]

        print(f"BF is at {bf}")

        bf_port = None
        for port in rh.all_ports():
            ret = rh.run(f'ethtool -i {port["ifname"]}')
            if ret.returncode != 0:
                continue

            d = {}
            for e in ret.out.strip().split("\n"):
                key, value = e.split(":", 1)
                d[key] = value
            if d["bus-info"].endswith(bf):
                bf_port = port["ifname"]
        print(bf_port)

        with open("manifests/tenant/SriovNetworkNodePolicy.yaml") as f:
            j2_template = jinja2.Template(f.read())
            rendered = j2_template.render(bf_port=bf_port, bf_addr=bf)

        with open("/tmp/a.yaml", "w") as f:
            f.write(rendered)

        print("Creating sriov pool config")
        tclient.oc("create -f manifests/tenant/sriov-pool-config.yaml")
        tclient.oc("create -f /tmp/a.yaml")
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
            print(rh.run("sudo ovs-vsctl del-port br-int ovn-k8s-mp0"))

        print("Final infrastructure cluster configuration")
        iclient = K8sClient("/root/kubeconfig.infracluster")

        # https://issues.redhat.com/browse/NHE-334
        for e in iclient.get_nodes():
            ip = iclient.get_ip(e)
            rh = host.RemoteHost(ip)
            rh.ssh_connect("core")
            cmd = f"echo \'{self._cc['api_ip']} api.{self._cc['name']}.redhat.com\' | sudo tee -a /etc/hosts"
            print(rh.run(cmd))
        iclient.oc(f"project tenantcluster-dpu")
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
        r = iclient.oc("patch --type merge -p {\"spec\":{\"kubeConfigFile\":\"tenant-cluster-1-kubeconf\"}} OVNKubeConfig ovnkubeconfig-sample -n tenantcluster-dpu")
        print(r)
        print("Creating network attachement definition")
        tclient.oc("create -f manifests/tenant/nad.yaml")

        ec = ExtraConfigSriovOvSHWOL(self._cc)
        ec.ensure_pci_realloc(tclient, "dpu-host")


def main():
    pass


if __name__ == "__main__":
    main()
