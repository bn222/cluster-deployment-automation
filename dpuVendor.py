import re
import host
from logger import logger
from abc import ABC, abstractmethod
import ipu
import marvell
import clustersConfig


def detect_dpu(node: clustersConfig.NodeConfig) -> str:
    logger.info("Detecting DPU")
    assert node.kind == "dpu"
    assert node.bmc is not None
    assert node.bmc_host is not None

    ipu_bmc = ipu.IPUBMC(node.bmc, node.bmc_host)
    ipu_bmc.ensure_started()
    if ipu_bmc.is_ipu():
        return "ipu"
    elif marvell.is_marvell(node.bmc):
        return "marvell"
    else:
        logger.error_and_exit("Unknown DPU")


class VendorPlugin(ABC):
    @abstractmethod
    def setup(self, dpu: host.Host) -> None:
        raise NotImplementedError("Must implement setup() for VSP")


class IpuPlugin(VendorPlugin):
    P4_URL = "wsfd-advnetlab-amp04.anl.eng.bos2.dc.redhat.com/intel-ipu-acc-components-2.0.0.11126.tar.gz"

    def __init__(self) -> None:
        pass

    def setup(self, dpu: host.Host) -> None:
        self.download_p4_tar(dpu)
        self.configure_p4_hugepages(dpu)

    def download_p4_tar(self, rh: host.Host) -> None:
        logger.info("Downloading p4.tar.gz")
        rh.run_or_die(f"curl -L {self.P4_URL} -o /tmp/p4.tar.gz")
        rh.run("rm -rf /opt/p4")
        rh.run_or_die("tar -U -C /opt/ -xzf /tmp/p4.tar.gz")
        rh.run("mv /opt/intel-ipu-acc-components-2.0.0.11126 /opt/p4")
        rh.run("mv /opt/p4/p4-cp /opt/p4/p4-cp-nws")
        rh.run("mv /opt/p4/p4-sde /opt/p4/p4sde")

    def configure_p4_hugepages(self, rh: host.Host) -> None:
        logger.info("Configuring hugepages for p4 pod")
        # The p4 container typically sets this up. If we are running the container as a daemonset in microshift, we need to
        # ensure this resource is available prior to the pod starting to ensure dpdk is successful
        hugepages_service = """[Unit]
Description=Setup Hugepages
Before=microshift.service
Wants=microshift.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/mkdir -p /dev/hugepages
ExecStart=/bin/mount -t hugetlbfs -o pagesize=2M none /dev/hugepages
ExecStart=/bin/sh -c 'echo 512 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages'

[Install]
WantedBy=multi-user.target"""

        rh.write("/etc/systemd/system/hugepages-setup.service", hugepages_service)
        rh.run_or_die("sudo systemctl daemon-reload")
        rh.run_or_die("sudo systemctl enable hugepages-setup.service")
        rh.run_or_die("sudo systemctl start hugepages-setup.service")

        # Restart microshift to make sure the resource is available
        rh.run_or_die("systemctl restart microshift")


class MarvellDpuPlugin(VendorPlugin):
    def __init__(self) -> None:
        pass

    def setup(self, dpu: host.Host) -> None:
        logger.warning("Nothing to set up on Marvell DPU")


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
