import host
from k8sClient import K8sClient
import os
from git import Repo
import time
from clustersConfig import ClustersConfig
from arguments import parse_args
import shutil
import jinja2
import sys


class ExtraConfigSriov:
    def __init__(self, cc):
        self._cc = cc

    def run(self, _):
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

    def run(self, _) -> None:
        client = K8sClient(self._cc["kubeconfig"])
        client.oc("create -f manifests/nicmode/pool.yaml")

        pfNamesAll = []
        for e in self._cc["workers"]:
            name = e["name"]
            print(client.oc(f'label node {name} --overwrite=true feature.node.kubernetes.io/network-sriov.capable=true'))
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
            if result and result not in pfNamesAll:
                pfNamesAll.append(result)

        # Just in case we don't get any PFs
        if not pfNamesAll:
            fallback = "ens1f0"
            pfNamesAll.append(fallback)
            print(f"PF Name is not found on any nodes... adding {fallback} as fallback.")

        with open('./manifests/nicmode/sriov-node-policy.yaml.j2') as f:
            j2_template = jinja2.Template(f.read())
            rendered = j2_template.render(pfNamesAll=pfNamesAll)
            print(rendered)
            with open("/tmp/sriov-node-policy.yaml", "w") as outFile:
                outFile.write(rendered)

        print(client.oc("create -f manifests/nicmode/sriov-pool-config.yaml"))
        print(client.oc("create -f /tmp/sriov-node-policy.yaml"))
        print(client.oc("create -f manifests/nicmode/nad.yaml"))
        time.sleep(60)
        print(client.oc("wait mcp sriov --for condition=updated --timeout=50m"))

        self.ensure_pci_realloc(client, "sriov")


def main():
    args = parse_args()
    cc = ClustersConfig(args.config)
    ec = ExtraConfigSriov(cc)
    ec.run(None)


if __name__ == "__main__":
    main()
