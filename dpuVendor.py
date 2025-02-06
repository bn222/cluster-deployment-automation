import jinja2
import re
import host
from k8sClient import K8sClient
from logger import logger
from abc import ABC, abstractmethod
from imageRegistry import ImageRegistry


class VendorPlugin(ABC):
    @abstractmethod
    def build_push_start(self, acc: host.Host, imgReg: ImageRegistry, client: K8sClient) -> None:
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
    P4_IMG = "wsfd-advnetlab217.anl.eng.bos2.dc.redhat.com:5000/intel-ipu-sdk:kubecon-aarch64"

    def __init__(self) -> None:
        self._p4_manifest = "./manifests/dpu/dpu_p4_ds.yaml.j2"

    def build_push_start(self, acc: host.Host, imgReg: ImageRegistry, client: K8sClient) -> None:
        lh = host.LocalHost()
        lh.run_or_die(f"podman pull --tls-verify=false {self.P4_IMG}")
        local_img = f"{imgReg.url()}/intel-ipu-p4-sdk:kubecon-aarch64"
        lh.run_or_die(f"podman tag {self.P4_IMG} {local_img}")
        lh.run_or_die(f"podman push {local_img}")

        # If p4 pod already exists from previous run, kill this first.
        acc.run(f"podman ps --filter ancestor={local_img} --format '{{{{.ID}}}}' | xargs -r podman kill")

        self.start_p4_pod(acc, local_img, client)

    def start_p4_pod(self, acc: host.Host, image: str, client: K8sClient) -> None:
        self.configure_p4_hugepages(acc)

        logger.info("Manually starting P4 pod")
        with open(self._p4_manifest) as f:
            j2_template = jinja2.Template(f.read())
            rendered = j2_template.render(ipu_vsp_p4=image)
            tmp_file = "/tmp/dpu_p4_ds.yaml"
            with open(tmp_file, "w") as f:
                f.write(rendered)

        client.oc(f"delete -f {tmp_file}")
        client.oc_run_or_die(f"create -f {tmp_file}")

        # The vsp looks for the service provided by the p4 pod on localhost, make sure to create a service in OCP to expose it
        client.oc("delete -f manifests/dpu/p4_service.yaml")
        client.oc_run_or_die("create -f manifests/dpu/p4_service.yaml")
        client.wait_ds_running(ds="vsp-p4", namespace="default")

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

    def build_push_start(self, acc: host.Host, imgReg: ImageRegistry, client: K8sClient) -> None:
        # TODO: https://github.com/openshift/dpu-operator/pull/82
        logger.warning("Setting up Marvell DPU not yet implemented")


def init_vendor_plugin(h: host.Host, node_kind: str) -> VendorPlugin:
    # TODO: Vendor hardware will be handled inside the operator. The user will not explicitely configure the system
    # based on what hardware he is running on. From the perspective of the user, he's dealing with abstract DPUs.
    # This function will therefore be removed completely
    if node_kind == "marvell-dpu":
        logger.info(f"Detected Marvell DPU on {h.hostname()}")
        return MarvellDpuPlugin()
    else:
        logger.info(f"Detected Intel IPU hardware on {h.hostname()}")
        return IpuPlugin()


def extractContainerImage(dockerfile: str) -> str:
    match = re.search(r'FROM\s+([^\s]+)(?:\s+as\s+\w+)?', dockerfile, re.IGNORECASE)
    if match:
        first_image = match.group(1)
        return first_image
    else:
        logger.error_and_exit("Failed to find a Docker image in provided output")
