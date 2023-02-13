import host
from k8sClient import K8sClient
import os
from git import Repo
import time
from clustersConfig import ClustersConfig
from arguments import parse_args
import shutil


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
        print("running make deploy-setup")
        print(lh.run("make deploy-setup", env))
        time.sleep(60)
        os.chdir(cur_dir)

    def enable_offload(self):
        client = K8sClient(self._cc["kubeconfig"])
        client.oc("create -f manifests/nicmode/pool.yaml")

        for e in self._cc["workers"]:
            name = e["name"]
            print(client.oc(f'label node {name} --overwrite=true feature.node.kubernetes.io/network-sriov.capable=true'))

        print(client.oc("create -f manifests/nicmode/sriov-pool-config.yaml"))
        print(client.oc("create -f manifests/nicmode/sriov-node-policy.yaml"))
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
