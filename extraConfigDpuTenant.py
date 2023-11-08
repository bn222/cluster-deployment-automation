from dataclasses import dataclass
from clustersConfig import ClustersConfig
from k8sClient import K8sClient
import host
from common_patches import apply_common_pathches
from concurrent.futures import Future
from extraConfigDpuInfra import run_dpu_network_operator_git
import extraConfigSriov
from typing import Dict
from typing import List
from typing import Union
import sys
import jinja2
import json
import os
import re
from logger import logger
from clustersConfig import ExtraConfigArgs


def ExtraConfigDpuTenantMC(cc: ClustersConfig, _: ExtraConfigArgs, futures: Dict[str, Future[None]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step")
    tclient = K8sClient("/root/kubeconfig.tenantcluster")
    create_nm_operator(tclient)
    apply_common_pathches(tclient)
    logger.info("Apply DPU tenant mc")
    tclient.oc("create -f manifests/tenant/dputenantmachineconfig.yaml")

    logger.info("Waiting for mcp to be updated")
    tclient.wait_for_mcp("dpu-host", "dputenantmachineconfig.yaml")

    logger.info("Patching mcp setting maxUnavailable to 2")
    tclient.oc("patch mcp dpu-host --type=json -p=\[\{\"op\":\"replace\",\"path\":\"/spec/maxUnavailable\",\"value\":2\}\]")

    logger.info("Labeling nodes")
    for e in cc.workers:
        cmd = f"label node {e.name} node-role.kubernetes.io/dpu-host="
        logger.info(tclient.oc(cmd))
    logger.info("Need to deploy sriov network operator")


def render_sriov_node_policy(policyname: str, bf_port: str, bf_addr: str, numvfs: int, resourcename: str, outfilename: str) -> None:
    with open("./manifests/tenant/SriovNetworkNodePolicy.yaml.j2") as f:
        j2_template = jinja2.Template(f.read())
        rendered = j2_template.render(policyName=policyname, bf_port=bf_port, bf_addr=bf_addr, numVfs=numvfs, resourceName=resourcename)
        logger.info(rendered)

    with open(outfilename, "w") as outFile:
        outFile.write(rendered)


def render_envoverrides_cm(client: K8sClient, mapping: List[Dict[str, str]], ns: str) -> str:
    contents = open("manifests/tenant/envoverrides.yaml").read()
    contents += f"{ns}\n"
    contents += "data:\n"
    for e in mapping:
        a: Dict[str, str] = {}
        a["TENANT_K8S_NODE"] = e["worker"]
        # Can be removed since API is replaced https://github.com/openshift/dpu-network-operator/pull/67
        dpu_ip = client.get_ip(e["bf"])
        if isinstance(dpu_ip, str):
            a["DPU_IP"] = dpu_ip
        else:
            logger.error(f"Failed to retrieve ip for {e['bf']}")
            sys.exit(1)
        a["MGMT_IFNAME"] = "c1pf0vf0"
        contents += f"  {e['bf']}: |\n"
        for (k, v) in a.items():
            contents += f"    {k}={v}\n"

    open(f"/tmp/envoverrides-{ns}.yaml", "w").write(contents)
    return f"/tmp/envoverrides-{ns}.yaml"


def ExtraConfigDpuTenant(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: Dict[str, Future[None]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step")

    if cfg.mapping is None:
        logger.error("BF to Worker mapping not provided for tenant deployment")
        sys.exit(1)
    tclient = K8sClient("/root/kubeconfig.tenantcluster")
    logger.info("Waiting for mcp dpu-host to become ready")
    tclient.wait_for_mcp("dpu-host")

    # Since the kubeconfig we pass into secrets will have the role "system:admin", this is not allowed
    # from the local node running operator pods point of view. A possible fix is to somehow download
    # the kubeconfig from the tenant host nodes and use that as the secret. For now, let's disable the
    # webhook
    logger.info("creating config map to disable ovn-k node_admission webhook on tenant cluster")
    tclient.oc("create configmap -n openshift-network-operator network-node-identity --from-literal=enabled=false")

    first_worker = cc.workers[0].name
    ip = tclient.get_ip(first_worker)
    if ip is None:
        sys.exit(-1)
    rh = host.RemoteHost(ip)
    rh.ssh_connect("core")
    all_bf = [x for x in rh.run("lspci").out.split("\n") if "BlueField" in x]
    if not all_bf:
        logger.info(f"Couldn't find BF on {first_worker}")
        sys.exit(-1)
    bf = all_bf[0].split(" ")[0]

    logger.info(f"BF is at {bf}")

    bf_port = None
    for port in rh.all_ports():
        ret = rh.run(f'ethtool -i {port["ifname"]}')
        if ret.returncode != 0:
            continue

        d = {}
        for part in ret.out.strip().split("\n"):
            key, value = part.split(":", 1)
            d[key] = value
        if d["bus-info"].endswith(bf):
            bf_port = port["ifname"]
    logger.info(bf_port)
    if bf_port is None:
        logger.info("Couldn't find bf port")
        sys.exit(-1)

    numVfs = 16
    numMgmtVfs = 1
    workloadPolicyName = "policy-mlnx-bf"
    workloadResourceName = "mlnx_bf"
    workloadBfPort = f"{bf_port}#{numMgmtVfs}-{numVfs-1}"
    workloadPolicyFile = "/tmp/" + workloadPolicyName + ".yaml"
    mgmtPolicyName = "mgmt-policy-mlnx-bf"
    mgmtResourceName = "mgmtvf"
    mgmtBfPort = f"{bf_port}#0-{numMgmtVfs-1}"
    mgmtPolicyFile = "/tmp/" + mgmtPolicyName + ".yaml"

    render_sriov_node_policy(workloadPolicyName, workloadBfPort, bf, numVfs, workloadResourceName, workloadPolicyFile)
    render_sriov_node_policy(mgmtPolicyName, mgmtBfPort, bf, numVfs, mgmtResourceName, mgmtPolicyFile)

    logger.info("Creating sriov pool config")
    tclient.oc("create -f manifests/tenant/sriov-pool-config.yaml")
    tclient.oc("create -f " + workloadPolicyFile)
    tclient.oc("create -f " + mgmtPolicyFile)
    logger.info("Waiting for mcp to be updated")
    tclient.wait_for_mcp("dpu-host", "sriov pool")

    logger.info("creating config map to put ovn-k into dpu host mode")
    tclient.oc("create -f manifests/tenant/sriovdpuconfigmap.yaml")

    logger.info("setting ovn kube node env-override to set management port")
    logger.info(os.getcwd())
    contents = open("manifests/tenant/setenvovnkube.yaml").read()

    for bfmap in cfg.mapping:
        a: Dict[str, str] = {}
        mp = re.sub('np\d$', '', bf_port)
        a["OVNKUBE_NODE_MGMT_PORT_NETDEV"] = f"{mp}v0"
        contents += f"  {bfmap['worker']}: |\n"
        for (k, v) in a.items():
            contents += f"    {k}={v}\n"
    open("/tmp/1.yaml", "w").write(contents)

    logger.info("Running create")
    logger.info(tclient.oc("create -f /tmp/1.yaml"))

    for nc in cc.workers:
        cmd = f"label node {nc.name} network.operator.openshift.io/dpu-host="
        logger.info(tclient.oc(cmd))
        ip = tclient.get_ip(nc.name)
        if ip is None:
            logger.error(f"Failed to get ip for node {nc.name}")
            sys.exit(-1)
        rh = host.RemoteHost(ip)
        rh.ssh_connect("core")
        # workaround for https://issues.redhat.com/browse/NHE-335
        logger.info(rh.run("sudo ovs-vsctl del-port br-int ovn-k8s-mp0"))

    logger.info("creating mc to disable ovs")
    # At this point we error out, because the patch ports on the DPU OvS side does not get created
    # patch ports are created on the OVN side. TODO: FIXME For now try this to make OVN-K on DPU happy:
    for e in cc.workers:
        cmd = f"annotate --overwrite node/{e.name} k8s.ovn.org/node-mgmt-port={{\"PfId\":0,\"FuncId\":0}}"
        logger.info(cmd)
        logger.info(tclient.oc(cmd))

    tclient.oc("create -f manifests/tenant/disable-ovs.yaml")
    logger.info("Waiting for mcp")
    tclient.wait_for_mcp("dpu-host", "dpu host mode")

    logger.info("Final infrastructure cluster configuration")
    iclient = K8sClient("/root/kubeconfig.infracluster")

    # https://issues.redhat.com/browse/NHE-334
    iclient.oc(f"project two-cluster-design")
    logger.info(iclient.oc(f"create secret generic tenant-cluster-1-kubeconf --from-file=config={tclient._kc}"))

    tc_namespace = "two-cluster-design"
    dpu_namespace = "openshift-dpu-network-operator"
    file = render_envoverrides_cm(iclient, cfg.mapping, tc_namespace)
    logger.info(iclient.oc(f"create -f {file}"))
    file = render_envoverrides_cm(iclient, cfg.mapping, dpu_namespace)
    logger.info(iclient.oc(f"create -f {file}"))

    # Restart DPU network operator to apply env-overrides cm
    restart_dpu_network_operator(iclient)

    patch = json.dumps({"spec": {"kubeConfigFile": "tenant-cluster-1-kubeconf"}})
    r = iclient.oc(f"patch --type merge -p '{patch}' DpuClusterConfig dpuclusterconfig-sample -n two-cluster-design")
    logger.info(patch)
    logger.info(r)
    logger.info("Creating network attachement definition")
    tclient.oc("create -f manifests/tenant/nad.yaml")
    tclient.approve_csr()
    iclient.approve_csr()

    extraConfigSriov.ensure_pci_realloc(cc, tclient, "dpu-host")


def ExtraConfigDpuTenant_NewAPI(cc: ClustersConfig, _: ExtraConfigArgs, futures: Dict[str, Future[None]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step")
    tclient = K8sClient("/root/kubeconfig.tenantcluster")
    logger.info("Waiting for mcp dpu-host to become ready")
    tclient.wait_for_mcp("dpu-host")

    lh = host.LocalHost()
    run_dpu_network_operator_git(lh, "/root/kubeconfig.tenantcluster")

    logger.info("Creating namespace for tenant")
    tclient.oc("create -f manifests/infra/ns.yaml")
    logger.info("Creating DpuClusterConfig cr")
    tclient.oc("create -f manifests/tenant/dpuclusterconfig.yaml")

    first_worker = cc.workers[0].name
    ip = tclient.get_ip(first_worker)
    if ip is None:
        sys.exit(-1)
    rh = host.RemoteHost(ip)
    rh.ssh_connect("core")
    all_bf = [x for x in rh.run("lspci").out.split("\n") if "BlueField" in x]
    if not all_bf:
        logger.info(f"Couldn't find BF on {first_worker}")
        sys.exit(-1)
    bf = all_bf[0].split(" ")[0]

    logger.info(f"BF is at {bf}")

    bf_port = None
    for port in rh.all_ports():
        ret = rh.run(f'ethtool -i {port["ifname"]}')
        if ret.returncode != 0:
            continue

        d = {}
        for part in ret.out.strip().split("\n"):
            key, value = part.split(":", 1)
            d[key] = value
        if d["bus-info"].endswith(bf):
            bf_port = port["ifname"]
    logger.info(bf_port)
    if bf_port is None:
        logger.info("Couldn't find bf port")
        sys.exit(-1)

    numVfs = 16
    numMgmtVfs = 1
    workloadPolicyName = "policy-mlnx-bf"
    workloadResourceName = "mlnx_bf"
    workloadBfPort = f"{bf_port}#{numMgmtVfs}-{numVfs-1}"
    workloadPolicyFile = "/tmp/" + workloadPolicyName + ".yaml"
    mgmtPolicyName = "mgmt-policy-mlnx-bf"
    mgmtResourceName = "mgmtvf"
    mgmtBfPort = f"{bf_port}#0-{numMgmtVfs-1}"
    mgmtPolicyFile = "/tmp/" + mgmtPolicyName + ".yaml"

    render_sriov_node_policy(workloadPolicyName, workloadBfPort, bf, numVfs, workloadResourceName, workloadPolicyFile)
    render_sriov_node_policy(mgmtPolicyName, mgmtBfPort, bf, numVfs, mgmtResourceName, mgmtPolicyFile)

    logger.info("Creating sriov pool config")
    tclient.oc("create -f manifests/tenant/sriov-pool-config.yaml")
    tclient.oc("create -f " + workloadPolicyFile)
    tclient.oc("create -f " + mgmtPolicyFile)
    logger.info("Waiting for mcp to be updated")
    tclient.wait_for_mcp("dpu-host", "sriov pool")

    # DELTA START: We don't create sriovdpuconfigmap.yaml to set dpu-host mode. https://github.com/openshift/cluster-network-operator/pull/1676
    mgmtPortResourceName = "openshift.io/" + mgmtResourceName
    logger.info(f"Creating Config Map for mgmt port resource name {mgmtPortResourceName}")
    with open('./manifests/tenant/hardware-offload-config.yaml.j2') as f:
        j2_template = jinja2.Template(f.read())
        rendered = j2_template.render(mgmtPortResourceName=mgmtPortResourceName)
        logger.info(rendered)

    with open("/tmp/hardware-offload-config.yaml", "w") as outFile:
        outFile.write(rendered)

    logger.info(tclient.oc("create -f /tmp/hardware-offload-config.yaml"))
    # DELTA END

    # DELTA: We don't create env-override to set management port. https://github.com/ovn-org/ovn-kubernetes/pull/3467

    for e in cc.workers:
        cmd = f"label node {e.name} network.operator.openshift.io/dpu-host="
        logger.info(tclient.oc(cmd))
        ip = tclient.get_ip(e.name)
        if ip is None:
            logger.error(f"Failed to get ip for node {e.name}")
            sys.exit(-1)
        rh = host.RemoteHost(ip)
        rh.ssh_connect("core")
        # DELTA: "ovn-k8s-mp0" port is deleted by OVN-K. https://github.com/ovn-org/ovn-kubernetes/pull/3571
        result = rh.run("sudo ovs-vsctl show")
        if "ovn-k8s-mp0" in result.out:
            logger.info(result.out)
            logger.info("Unexpected ovn-k8s-mp0 interface found in br-int.")
            # FIXME: The above patch did not seem to entirely work. We will need to investigate further
            # For now we will delete the port.
            logger.info(rh.run("sudo ovs-vsctl del-port br-int ovn-k8s-mp0"))

    logger.info("creating mc to disable ovs")
    tclient.oc("create -f manifests/tenant/disable-ovs.yaml")
    logger.info("Waiting for mcp")
    tclient.wait_for_mcp("dpu-host", "disable-ovs.yaml")

    logger.info("Final infrastructure cluster configuration")
    iclient = K8sClient("/root/kubeconfig.infracluster")

    # https://issues.redhat.com/browse/NHE-334
    logger.info(iclient.oc(f"create secret generic tenant-cluster-1-kubeconf --from-file=config={tclient._kc} --namespace=two-cluster-design"))

    patch = json.dumps({"spec": {"kubeConfigFile": "tenant-cluster-1-kubeconf"}})
    r = iclient.oc(f"patch --type merge -p '{patch}' DpuClusterConfig dpuclusterconfig-sample -n two-cluster-design")
    logger.info(r)
    logger.info("Creating network attachement definition")
    tclient.oc("create -f manifests/tenant/nad.yaml")

    extraConfigSriov.ensure_pci_realloc(cc, tclient, "dpu-host")


def create_nm_operator(client: K8sClient) -> None:
    logger.info("Apply NMO subscription")
    client.oc("create -f manifests/tenant/nmo-subscription.yaml")


def restart_dpu_network_operator(iclient: K8sClient) -> None:
    lh = host.LocalHost()
    logger.info("Restarting dpu-network-operator")
    run_dpu_network_operator_git(lh, "/root/kubeconfig.infracluster")
    iclient.oc("wait deploy/dpu-network-operator-controller-manager --for condition=available -n openshift-dpu-network-operator")
    logger.info("Creating DpuClusterConfig cr")
    iclient.oc("create -f manifests/infra/dpuclusterconfig.yaml")


def main() -> None:
    pass


if __name__ == "__main__":
    main()
