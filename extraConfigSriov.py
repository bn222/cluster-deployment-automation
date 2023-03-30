import host
from k8sClient import K8sClient
import os
from git import Repo
import time
from concurrent.futures import Future
from clustersConfig import ClustersConfig
from arguments import parse_args
import shutil
import jinja2
import sys
from typing import Dict


class ExtraConfigSriov:
    def __init__(self, cc):
        self._cc = cc

    def run(self, cfg, futures: Dict[str, Future]) -> None:
        [f.result() for (_, f) in futures.items()]
        client = K8sClient(self._cc["kubeconfig"])
        lh = host.LocalHost()
        repo_dir = "/root/sriov-network-operator"
        url = "https://github.com/bn222/sriov-network-operator"

        if os.path.exists(repo_dir):
            shutil.rmtree(repo_dir)

        print(f"Cloning repo to {repo_dir}")
        Repo.clone_from(url, repo_dir, branch='master')

        cur_dir = os.getcwd()
        os.chdir(repo_dir)
        env = os.environ.copy()
        env["KUBECONFIG"] = client._kc

        if "image" in cfg:
            image = cfg["image"]
            print(f"Image {image} provided to load custom sriov-network-operator")
            env["SRIOV_NETWORK_OPERATOR_IMAGE"] = image

        # cleanup first, to make this script idempotent
        print("running make undeploy")
        print(lh.run("make undeploy", env))

        # Workaround PSA issues. https://issues.redhat.com/browse/OCPBUGS-1005
        client.oc("create namespace openshift-sriov-network-operator")
        client.oc("label ns --overwrite openshift-sriov-network-operator "
                  "pod-security.kubernetes.io/enforce=privileged "
                  "pod-security.kubernetes.io/enforce-version=v1.24 "
                  "security.openshift.io/scc.podSecurityLabelSync=false")

        print("running make deploy-setup")
        print(lh.run("make deploy-setup", env))
        time.sleep(60)
        os.chdir(cur_dir)

class ExtraConfigSriovOvSHWOL:
    def __init__(self, cc):
        self._cc = cc

    def need_pci_realloc(self, client: K8sClient) -> bool:
        for e in self._cc["workers"]:
            ip = client.get_ip(e['name'])
            if ip is None:
                sys.exit(-1)
            rh = host.RemoteHost(ip)
            rh.ssh_connect("core")
            if "switchdev-configuration-before-nm.service" in rh.run("systemctl list-units --state=failed --plain --no-legend").out:
                print(f"switchdev-configuration is failing in {e['name']}, additional machine configuration is required")
                return True
        return False

    def enable_pci_realloc(self, client: K8sClient, mcp_name: str) -> None:
        print("Applying pci-realloc machine config")
        with open('./manifests/nicmode/pci-realloc.yaml.j2') as f:
            j2_template = jinja2.Template(f.read())
        rendered = j2_template.render(MCPName=mcp_name)
        print(rendered)
        with open("/tmp/pci-realloc.yaml", "w") as outFile:
            outFile.write(rendered)
        client.oc("create -f /tmp/pci-realloc.yaml")
        print("Waiting for mcp")
        time.sleep(60)
        client.oc(f"wait mcp {mcp_name} --for condition=updated --timeout=50m")

    def ensure_pci_realloc(self, client: K8sClient, mcp_name: str) -> None:
        if self.need_pci_realloc(client):
            self.enable_pci_realloc(client, mcp_name)

    def render_sriov_node_policy(self, policyname: str, pfnames, numvfs: int, resourcename: str, outfilename: str):
        with open('./manifests/nicmode/sriov-node-policy.yaml.j2') as f:
            j2_template = jinja2.Template(f.read())
            rendered = j2_template.render(policyName=policyname, pfNamesAll=pfnames, numVfs=numvfs, resourceName=resourcename)
            print(rendered)

        with open(outfilename, "w") as outFile:
            outFile.write(rendered)

    def run(self, _, futures: Dict[str, Future]) -> None:
        [f.result() for (_, f) in futures.items()]
        client = K8sClient(self._cc["kubeconfig"])
        client.oc("create -f manifests/nicmode/pool.yaml")

        workloadVFsAll = []
        managementVFsAll = []
        numVfs = 12
        numMgmtVfs = 1
        workloadResourceName = "mlxnics"
        managementResourceName = "mgmtvf"
        for e in self._cc["workers"]:
            name = e["name"]
            print(client.oc(f'label node {name} --overwrite=true feature.node.kubernetes.io/network-sriov.capable=true'))
            print(client.oc(f'label node {name} --overwrite=true network.operator.openshift.io/smart-nic='))
            # Find out what the PF attached to br-ex is (uplink port). We only do HWOL on uplink ports.
            ip = client.get_ip(name)
            if ip is None:
                sys.exit(-1)
            rh = host.RemoteHost(ip)
            rh.ssh_connect("core")
            result = rh.run("cat /var/lib/ovnk/iface_default_hint").out.strip()
            if result:
                print(f"Found PF Name {result} on node {name}")
            else:
                print(f"Cannot find PF Name on node {name} using hint")
                interface_list = rh.run("sudo ovs-vsctl list-ifaces br-ex").out.strip().split("\n")
                result = [x for x in interface_list if "patch" not in x]
                result = result[0]
                if result:
                    print(f"Found PF Name {result} on node {name}")
                else:
                    print(f"Cannot find PF Name on node {name} using ovs-vsctl")
            if result:
                # Reserve VF(s) for management port(s).
                workloadVFs = result + f"#{numMgmtVfs}-{numVfs-1}"
                managementVFs = result + f"#0-{numMgmtVfs-1}"
                if workloadVFs not in workloadVFsAll:
                    workloadVFsAll.append(workloadVFs)
                if managementVFs not in managementVFsAll:
                    managementVFsAll.append(managementVFs)

        # We error out if we can't find any PFs.
        if not workloadVFsAll:
            print(f"PF Name is not found on any nodes.")
            sys.exit(-1)

        workloadPolicyName = "sriov-workload-node-policy"
        workloadPolicyFile = "/tmp/" + workloadPolicyName + ".yaml"
        self.render_sriov_node_policy(workloadPolicyName, workloadVFsAll, numVfs, workloadResourceName, workloadPolicyFile)

        mgmtPolicyName = "sriov-mgmt-node-policy"
        mgmtPolicyFile = "/tmp/" + mgmtPolicyName + ".yaml"
        self.render_sriov_node_policy(mgmtPolicyName, managementVFsAll, numVfs, managementResourceName, mgmtPolicyFile)

        print(client.oc("create -f manifests/nicmode/sriov-pool-config.yaml"))
        print(client.oc("create -f " + workloadPolicyFile))
        print(client.oc("create -f " + mgmtPolicyFile))
        print(client.oc("create -f manifests/nicmode/nad.yaml"))
        time.sleep(60)
        print(client.oc("wait mcp sriov --for condition=updated --timeout=50m"))

        self.ensure_pci_realloc(client, "sriov")

# VF Management port requires a new API. We need a new extra config class to handle the API changes.
class ExtraConfigSriovOvSHWOL_NewAPI(ExtraConfigSriovOvSHWOL):
    def run(self, _, futures: Dict[str, Future]) -> None:
        [f.result() for (_, f) in futures.items()]
        client = K8sClient(self._cc["kubeconfig"])
        client.oc("create -f manifests/nicmode/pool.yaml")

        workloadVFsAll = []
        managementVFsAll = []
        numVfs = 12
        numMgmtVfs = 1
        workloadResourceName = "mlxnics"
        managementResourceName = "mgmtvf"
        for e in self._cc["workers"]:
            name = e["name"]
            print(client.oc(f'label node {name} --overwrite=true feature.node.kubernetes.io/network-sriov.capable=true'))
            print(client.oc(f'label node {name} --overwrite=true network.operator.openshift.io/smart-nic='))
            # Find out what the PF attached to br-ex is (uplink port). We only do HWOL on uplink ports.
            ip = client.get_ip(name)
            if ip is None:
                sys.exit(-1)
            rh = host.RemoteHost(ip)
            rh.ssh_connect("core")
            result = rh.run("cat /var/lib/ovnk/iface_default_hint").out.strip()
            if result:
                print(f"Found PF Name {result} on node {name}")
            else:
                print(f"Cannot find PF Name on node {name} using hint")
                interface_list = rh.run("sudo ovs-vsctl list-ifaces br-ex").out.strip().split("\n")
                result = [x for x in interface_list if "patch" not in x]
                result = result[0]
                if result:
                    print(f"Found PF Name {result} on node {name}")
                else:
                    print(f"Cannot find PF Name on node {name} using ovs-vsctl")
            if result:
                # Reserve VF(s) for management port(s).
                workloadVFs = result + f"#{numMgmtVfs}-{numVfs-1}"
                managementVFs = result + f"#0-{numMgmtVfs-1}"
                if workloadVFs not in workloadVFsAll:
                    workloadVFsAll.append(workloadVFs)
                if managementVFs not in managementVFsAll:
                    managementVFsAll.append(managementVFs)

        # We error out if we can't find any PFs.
        if not workloadVFsAll:
            print(f"PF Name is not found on any nodes.")
            sys.exit(-1)

        workloadPolicyName = "sriov-workload-node-policy"
        workloadPolicyFile = "/tmp/" + workloadPolicyName + ".yaml"
        self.render_sriov_node_policy(workloadPolicyName, workloadVFsAll, numVfs, workloadResourceName, workloadPolicyFile)

        mgmtPolicyName = "sriov-mgmt-node-policy"
        mgmtPolicyFile = "/tmp/" + mgmtPolicyName + ".yaml"
        self.render_sriov_node_policy(mgmtPolicyName, managementVFsAll, numVfs, managementResourceName, mgmtPolicyFile)

        print(client.oc("create -f manifests/nicmode/sriov-pool-config.yaml"))
        print(client.oc("create -f " + workloadPolicyFile))
        print(client.oc("create -f " + mgmtPolicyFile))
        print(client.oc("create -f manifests/nicmode/nad.yaml"))
        time.sleep(60)
        print(client.oc("wait mcp sriov --for condition=updated --timeout=50m"))

        mgmtPortResourceName = "openshift.io/" + managementResourceName
        print(f"Creating Config Map for Hardware Offload with resource name {mgmtPortResourceName}")
        with open('./manifests/nicmode/hardware-offload-config.yaml.j2') as f:
            j2_template = jinja2.Template(f.read())
            rendered = j2_template.render(mgmtPortResourceName=mgmtPortResourceName)
            print(rendered)

        with open("/tmp/hardware-offload-config.yaml", "w") as outFile:
            outFile.write(rendered)

        print(client.oc("create -f /tmp/hardware-offload-config.yaml"))

        self.ensure_pci_realloc(client, "sriov")

def main():
    pass


if __name__ == "__main__":
    main()
