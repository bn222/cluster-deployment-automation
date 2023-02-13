import host
from k8sClient import K8sClient
import os
from git import Repo
import time
from clustersConfig import ClustersConfig
from arguments import parse_args
import shutil
import jinja2


class ExtraConfigSriov:
    def __init__(self, cc):
        self._cc = cc

    def run(self, _):
        client = K8sClient(self._cc["kubeconfig"])
        lh = host.LocalHost()
        repo_dir = "/root/sriov-network-operator"
        url = "https://github.com/openshift/sriov-network-operator.git"

        if os.path.exists(repo_dir):
            shutil.rmtree(repo_dir)

        print(f"Cloning repo to {repo_dir}")
        Repo.clone_from(url, repo_dir)

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

    def enable_offload(self):
        client = K8sClient(self._cc["kubeconfig"])
        client.oc("create -f manifests/nicmode/pool.yaml")

        pfNamesAll = []
        for e in self._cc["workers"]:
            name = e["name"]
            print(client.oc(f'label node {name} --overwrite=true feature.node.kubernetes.io/network-sriov.capable=true'))
            # Find out what the PF attached to br-ex is (uplink port). We only do HWOL on uplink ports.
            ip = client.get_ip(name)
            rh = host.RemoteHost(ip)
            rh.ssh_connect("core")
            result = rh.run("cat /var/lib/ovnk/iface_default_hint").out
            print(f"Found PF Name {result} on node {name}")
            if result not in pfNamesAll:
                pfNamesAll.append(result)

        # Just in case we don't get any PFs
        if not pfNamesAll:
            pfNamesAll.append("ens1f0")

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

def main():
    args = parse_args()
    cc = ClustersConfig(args.config)
    ec = ExtraConfigSriov(cc)
    ec.run(None)


if __name__ == "__main__":
    main()
