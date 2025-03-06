import jinja2
import re
import host
from logger import logger
from abc import ABC, abstractmethod
from imageRegistry import ImageRegistry
import ipu
import marvell
import clustersConfig


def detect_dpu(node: clustersConfig.NodeConfig) -> str:
    logger.info("Detecting DPU")
    assert node.kind == "dpu"
    assert node.bmc is not None
    ipu_bmc = ipu.IPUBMC(node.bmc)
    if ipu_bmc.is_ipu():
        return "ipu"
    elif marvell.is_marvell(node.bmc):
        return "marvell"
    else:
        logger.error_and_exit("Unknown DPU")


class VendorPlugin(ABC):
    @abstractmethod
    def build_push_start(self, acc: host.Host, imgReg: ImageRegistry) -> None:
        raise NotImplementedError("Must implement build_and_start() for VSP")

    @staticmethod
    def render_dpu_vsp_ds(vsp_ds_manifest: str, ipu_plugin_image: str, outfilename: str) -> None:
        with open(vsp_ds_manifest) as f:
            j2_template = jinja2.Template(f.read())
            rendered = j2_template.render(ipu_plugin_image=ipu_plugin_image)
            logger.info(rendered)

        with open(outfilename, "w") as outFile:
            outFile.write(rendered)


class IpuPlugin(VendorPlugin):
    P4_IMG = "wsfd-advnetlab217.anl.eng.bos2.dc.redhat.com:5000/intel-ipu-sdk:single-port-aarch64"

    def __init__(self) -> None:
        pass

    def build_push_start(self, acc: host.Host, imgReg: ImageRegistry) -> None:
        # Only need to retag and manage images and config hugepages.
        # The actual vsp init is done by the dpu-daemon
        # and vsp-p4 init is done by vsp
        lh = host.LocalHost()
        lh.run_or_die(f"podman pull --tls-verify=false {self.P4_IMG}")
        local_img = f"{imgReg.url()}/intel-vsp-p4:dev"
        lh.run_or_die(f"podman tag {self.P4_IMG} {local_img}")
        lh.run_or_die(f"podman push {local_img}")
        # WA https://issues.redhat.com/browse/IIC-421
        acc.run_or_die("mkdir -p /opt/p4/p4-cp-nws/var/run/openvswitch")
        self.configure_p4_hugepages(acc)

    def configure_p4_hugepages(self, rh: host.Host) -> None:
        logger.info("Configuring hugepages for p4 pod")
        # The p4 container typically sets this up. If we are running the container as a daemonset in microshift, we need to
        # ensure this resource is available prior to the pod starting to ensure dpdk is successful
        rh.run("mkdir -p /dev/hugepages")
        rh.run("mount -t hugetlbfs -o pagesize=2M none /dev/hugepages || true")
        rh.run("echo 512 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages")
        # Restart microshift to make sure the resource is available
        rh.run_or_die("systemctl restart microshift")


class MarvellDpuPlugin(VendorPlugin):
    def __init__(self) -> None:
        pass

    def build_push_start(self, acc: host.Host, imgReg: ImageRegistry) -> None:
        # TODO: https://github.com/openshift/dpu-operator/pull/82
        logger.warning("Setting up Marvell DPU not yet implemented")


def init_vendor_plugin(h: host.Host, dpu_kind: str) -> VendorPlugin:
    # TODO: Vendor hardware will be handled inside the operator. The user will not explicitely configure the system
    # based on what hardware he is running on. From the perspective of the user, he's dealing with abstract DPUs.
    # This function will therefore be removed completely
    if dpu_kind == "marvell":
        logger.info(f"Detected Marvell DPU on {h.hostname()}")
        return MarvellDpuPlugin()
    elif dpu_kind == "ipu":
        logger.info(f"Detected Intel IPU hardware on {h.hostname()}")
        return IpuPlugin()
    else:
        logger.error_and_exit(f"Unexcpeted dpu kind {dpu_kind}")


def extractContainerImage(dockerfile: str) -> str:
    match = re.search(r'FROM\s+([^\s]+)(?:\s+as\s+\w+)?', dockerfile, re.IGNORECASE)
    if match:
        first_image = match.group(1)
        return first_image
    else:
        logger.error_and_exit("Failed to find a Docker image in provided output")
