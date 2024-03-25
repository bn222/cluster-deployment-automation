from clustersConfig import ClustersConfig
import host
from k8sClient import K8sClient
import os
from git.repo import Repo
import time
from concurrent.futures import Future
import shutil
import jinja2
import sys
from typing import Optional
from logger import logger
from clustersConfig import ExtraConfigArgs


def ExtraConfigSriov(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    client = K8sClient(cc.kubeconfig)
    lh = host.LocalHost()
    repo_dir = "/root/sriov-network-operator"
    url = "https://github.com/openshift/sriov-network-operator.git"

    if os.path.exists(repo_dir):
        shutil.rmtree(repo_dir)

    logger.info(f"Cloning repo to {repo_dir}")
    Repo.clone_from(url, repo_dir, branch='master')

    cur_dir = os.getcwd()
    os.chdir(repo_dir)
    env = {
        "KUBECONFIG": client._kc,
    }

    if cfg.image is not None:
        image = cfg.image
        logger.info(f"Image {image} provided to load custom sriov-network-operator")
        env["SRIOV_NETWORK_OPERATOR_IMAGE"] = image

    # cleanup first, to make this script idempotent
    logger.info("running make undeploy")
    logger.info(lh.run("make undeploy", env=env))
    client.oc("delete namespace openshift-sriov-network-operator --ignore-not-found")

    # Workaround PSA issues. https://issues.redhat.com/browse/OCPBUGS-1005
    client.oc("create namespace openshift-sriov-network-operator")
    client.oc("label ns --overwrite openshift-sriov-network-operator " "pod-security.kubernetes.io/enforce=privileged " "pod-security.kubernetes.io/enforce-version=v1.24 " "security.openshift.io/scc.podSecurityLabelSync=false")

    logger.info("running make deploy-setup")
    logger.info(lh.run("make deploy-setup", env=env))

    # Future proof for when sriov moves to new switchdev implementation: https://github.com/k8snetworkplumbingwg/sriov-network-operator/blob/master/doc/design/switchdev-refactoring.md
    time.sleep(60)
    os.chdir(cur_dir)
    client.oc("apply -f manifests/nicmode/sriov-operator-config.yaml")


def ExtraConfigSriovSubscription(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    client = K8sClient(cc.kubeconfig)
    lh = host.LocalHost()

    env = {
        "KUBECONFIG": client._kc,
    }

    # cleanup first, to make this script idempotent
    logger.info("running make undeploy")
    logger.info(lh.run("make undeploy", env=env))
    client.oc("delete namespace openshift-sriov-network-operator --ignore-not-found")

    # Following https://docs.openshift.com/container-platform/4.15/networking/hardware_networks/installing-sriov-operator.html
    client.oc("create -f manifests/nicmode/sriov-namespace-config.yaml")
    client.oc("create -f manifests/nicmode/sriov-operator-group.yaml")
    client.oc("create -f manifests/nicmode/sriov-subscription.yaml")

    client.oc("apply -f manifests/nicmode/sriov-operator-config.yaml")

    _check_sriov_installed(client)


def need_pci_realloc(cc: ClustersConfig, client: K8sClient) -> bool:
    for e in cc.workers:
        ip = client.get_ip(e.name)
        if ip is None:
            sys.exit(-1)
        rh = host.RemoteHost(ip)
        rh.ssh_connect("core")
        if "switchdev-configuration-before-nm.service" in rh.run("systemctl list-units --state=failed --plain --no-legend").out:
            logger.info(f"switchdev-configuration is failing in {e.name}, additional machine configuration is required")
            return True
    return False


def enable_pci_realloc(client: K8sClient, mcp_name: str) -> None:
    logger.info("Applying pci-realloc machine config")
    with open('./manifests/nicmode/pci-realloc.yaml.j2') as f:
        j2_template = jinja2.Template(f.read())
    rendered = j2_template.render(MCPName=mcp_name)
    logger.info(rendered)
    with open("/tmp/pci-realloc.yaml", "w") as outFile:
        outFile.write(rendered)
    client.oc("create -f /tmp/pci-realloc.yaml")
    logger.info("Waiting for mcp")
    client.wait_for_mcp(mcp_name, "pci-realloc.yaml")


def ensure_pci_realloc(cc: ClustersConfig, client: K8sClient, mcp_name: str) -> None:
    if need_pci_realloc(cc, client):
        enable_pci_realloc(client, mcp_name)


def render_sriov_node_policy(policyname: str, pfnames: list[str], numvfs: int, resourcename: str, outfilename: str) -> None:
    with open('./manifests/nicmode/sriov-node-policy.yaml.j2') as f:
        j2_template = jinja2.Template(f.read())
        rendered = j2_template.render(policyName=policyname, pfNamesAll=pfnames, numVfs=numvfs, resourceName=resourcename)
        logger.info(rendered)

    with open(outfilename, "w") as outFile:
        outFile.write(rendered)


def try_get_ovs_pf(rh: host.Host, name: str) -> str:
    rh.ssh_connect("core")
    try:
        result = rh.read_file("/var/lib/ovnk/iface_default_hint").strip()
        if result:
            logger.info(f"Found PF Name {result} on node {name}")
            return result
    except Exception:
        logger.info(f"Cannot find PF Name on node {name} using hint")

    retries = 5
    for attempt in range(1, retries + 1):
        interface_list = rh.run("sudo ovs-vsctl list-ifaces br-ex").out.strip().split("\n")
        selection = [x for x in interface_list if "patch" not in x]
        if selection:
            logger.info(f"Found PF {selection} on node {name} on attempt {attempt}")
            return selection[0]
        time.sleep(20)

    logger.error(f"Failed to find PF name on node {name} using ovs-vsctl")
    sys.exit(-1)


def _ExtraConfigSriovOvSHWOL_common(cc: ClustersConfig, futures: dict[str, Future[Optional[host.Result]]], *, new_api: bool) -> None:
    [f.result() for (_, f) in futures.items()]
    client = K8sClient(cc.kubeconfig)
    client.oc("create -f manifests/nicmode/pool.yaml")

    workloadVFsAll = []
    managementVFsAll = []
    numVfs = 12
    numMgmtVfs = 1
    workloadResourceName = "mlxnics"
    managementResourceName = "mgmtvf"
    for e in cc.workers:
        name = e.name
        logger.info(client.oc(f'label node {name} --overwrite=true feature.node.kubernetes.io/network-sriov.capable=true'))
        logger.info(client.oc(f'label node {name} --overwrite=true network.operator.openshift.io/smart-nic='))
        # Find out what the PF attached to br-ex is (uplink port). We only do HWOL on uplink ports.
        ip = client.get_ip(name)
        if ip is None:
            sys.exit(-1)
        rh = host.RemoteHost(ip)
        result = try_get_ovs_pf(rh, name)

        # Reserve VF(s) for management port(s).
        workloadVFs = f"{result}#{numMgmtVfs}-{numVfs - 1}"
        managementVFs = f"{result}#0-{numMgmtVfs - 1}"
        if workloadVFs not in workloadVFsAll:
            workloadVFsAll.append(workloadVFs)
        if managementVFs not in managementVFsAll:
            managementVFsAll.append(managementVFs)

    # We error out if we can't find any PFs.
    if not workloadVFsAll:
        logger.info("PF Name is not found on any nodes.")
        sys.exit(-1)

    workloadPolicyName = "sriov-workload-node-policy"
    workloadPolicyFile = "/tmp/" + workloadPolicyName + ".yaml"
    render_sriov_node_policy(workloadPolicyName, workloadVFsAll, numVfs, workloadResourceName, workloadPolicyFile)

    mgmtPolicyName = "sriov-mgmt-node-policy"
    mgmtPolicyFile = "/tmp/" + mgmtPolicyName + ".yaml"
    render_sriov_node_policy(mgmtPolicyName, managementVFsAll, numVfs, managementResourceName, mgmtPolicyFile)

    logger.info(client.oc("create -f manifests/nicmode/sriov-pool-config.yaml"))
    client.wait_for_mcp("sriov", "sriov-pool-config.yaml")
    logger.info(client.oc("create -f " + workloadPolicyFile))
    client.wait_for_mcp("sriov", "sriov-workload-node-policy.yaml")
    logger.info(client.oc("create -f " + mgmtPolicyFile))
    client.wait_for_mcp("sriov", "sriov-mgmt-node-policy.yaml")
    logger.info(client.oc("create -f manifests/nicmode/nad.yaml"))
    client.wait_for_mcp("sriov", "nad.yaml")

    if new_api:
        mgmtPortResourceName = "openshift.io/" + managementResourceName
        logger.info(f"Creating Config Map for Hardware Offload with resource name {mgmtPortResourceName}")
        with open('./manifests/nicmode/hardware-offload-config.yaml.j2') as f:
            j2_template = jinja2.Template(f.read())
            rendered = j2_template.render(mgmtPortResourceName=mgmtPortResourceName)
            logger.info(rendered)

        with open("/tmp/hardware-offload-config.yaml", "w") as outFile:
            outFile.write(rendered)

        logger.info(client.oc("create -f /tmp/hardware-offload-config.yaml"))

    ensure_pci_realloc(cc, client, "sriov")


def ExtraConfigSriovOvSHWOL(cc: ClustersConfig, _: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    _ExtraConfigSriovOvSHWOL_common(cc, futures, new_api=False)


# VF Management port requires a new API. We need a new extra config class to handle the API changes.
def ExtraConfigSriovOvSHWOL_NewAPI(cc: ClustersConfig, _: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    _ExtraConfigSriovOvSHWOL_common(cc, futures, new_api=True)


def _check_sriov_installed(client: K8sClient) -> None:
    for _ in range(10):
        result = client.oc("get csv -n openshift-sriov-network-operator -o custom-columns=PHASE:.status.phase")
        if "Succeeded" in result.out:
            logger.info("SR-IOV Network Operator installed successfully.")
            break
        else:
            time.sleep(30)
    else:
        logger.error("SR-IOV Network Operator installation failed or timed out.")
        sys.exit(1)

    logger.info("SR-IOV Network Operator installed successfully.")


def main() -> None:
    pass


if __name__ == "__main__":
    main()
