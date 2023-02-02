import host
import coreosBuilder
from concurrent.futures import ThreadPoolExecutor
import common
from k8sClient import K8sClient
from extraConfigSriov import ExtraConfigSriov
import time

"""
The "ExtraConfigBFB" is used to put the BF2 in a known good state. This is achieved by
1) Having a CoreOS Fedora image ready and mounted on NFS. This is needed for loading
a known good state on each of the workers.
2) Then SSH-ing into the load CoreOS Fedora image, we can run a pod with all the BF2
tools available. https://github.com/bn222/bluefield-2-tools
3) The scripts will try to update the firmware of the BF2. Then defaults are applied,
just in case there are lingering configurations.
4) Then the worker node is cold booted. This will also cold boot the BF2.
5) Again the CoreOS Fedora image is used again. However this time we want the BF2
to be in a good state.
6) This is done by loading the DOCA Ubuntu BFB image officially supported by NVIDIA.
7) This is done via rshim to load the image.
"""
class ExtraConfigBFB:
    def __init__(self, cc):
        self._cc = cc

    def run(self, _):
        coreosBuilder.ensure_fcos_exists()
        print("Loading BF-2 with BFB image on all workers")
        lh = host.LocalHost()
        nfs_server = common.extract_ip(lh.run("ip -json a").out, "eno3")
        iso_url = f"{nfs_server}:/root/iso/fedora-coreos.iso"

        def helper(e):
            h = host.RemoteHostWithBF2(e["node"], e["bmc_user"], e["bmc_password"])
            h.boot_iso_redfish(iso_url)
            h.ssh_connect("core")
            h.prep_container()
            print("updating firmware")
            h.bf_firmware_upgrade()
            print("setting firmware config to defaults")
            h.bf_firmware_defaults()
            h.cold_boot()
            h.boot_iso_redfish(iso_url)
            h.ssh_connect("core")
            h.prep_container()
            print("loading bfb image")
            h.bf_load_bfb()

        executor = ThreadPoolExecutor(max_workers=len(self._cc["workers"]))
        futures = []
        # Assuming that all workers have BF that need to reset to bfb image in
        # dpu mode
        for e in self._cc["workers"]:
            f = executor.submit(helper, e)
            futures.append(f)
        [f.result() for f in futures]


class ExtraConfigSwitchNicMode:
    def __init__(self, cc):
        self._cc = cc

    def run(self, _):
        client = K8sClient(self._cc["kubeconfig"])

        ec = ExtraConfigSriov(self._cc)
        ec.run(None)

        client.oc("create -f manifests/nicmode/pool.yaml")

        # label nodes
        for e in self._cc["workers"]:
            name = e["name"]
            print(client.oc(f"label node {name} machineconfiguration.openshift.io/role=sriov"))
            print(client.oc(f"label node {name} node-role.kubernetes.io/sriov="))

        client.oc("delete -f manifests/nicmode/switch.yaml")
        client.oc("create -f manifests/nicmode/switch.yaml")
        time.sleep(60)
        print(client.oc("wait mcp sriov --for condition=updated --timeout=50m"))
