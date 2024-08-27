import jinja2
import os
import re
import host
from k8sClient import K8sClient
from logger import logger
from abc import ABC, abstractmethod


class VendorPlugin(ABC):
    @abstractmethod
    def build_and_start(self, h: host.Host, client: K8sClient, registry: str) -> None:
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
    def __init__(self) -> None:
        self._repo = "https://github.com/intel/ipu-opi-plugins.git"
        self._vsp_ds_manifest = "./manifests/dpu/dpu_vsp_ds.yaml.j2"

    def build_and_start(self, h: host.Host, client: K8sClient, registry: str) -> None:
        logger.info("Building ipu-opi-plugin")
        h.run("rm -rf /root/ipu-opi-plugins")
        h.run_or_die(f"git clone {self._repo} /root/ipu-opi-plugins")
        ret = h.run_or_die("cat /root/ipu-opi-plugins/ipu-plugin/images/Dockerfile")
        golang_img = extractContainerImage(ret.out)
        h.run_or_die(f"podman pull docker.io/library/{golang_img}")
        if h.is_localhost():
            cur_dir = os.getcwd()
            os.chdir("/root/ipu-opi-plugins/ipu-plugin")
            env = os.environ.copy()
            env["IMGTOOL"] = "podman"
            ret = h.run("make -C /root/ipu-opi-plugins/ipu-plugin image", env=env)
            if not ret.success():
                logger.error_and_exit("Failed to build vsp images")
            os.chdir(cur_dir)
        else:
            h.run_or_die("cd /root/ipu-opi-plugins/ipu-plugin && export IMGTOOL=podman && make image")
        vsp_image = f"{registry}/ipu-plugin:dpu"
        h.run_or_die(f"podman tag intel-ipuplugin:latest {vsp_image}")

        self.render_dpu_vsp_ds(self._vsp_ds_manifest, vsp_image, "/tmp/vsp-ds.yaml")
        if h.is_localhost():
            h.run_or_die(f"podman push {vsp_image}")
        else:
            h.copy_to("/tmp/vsp-ds.yaml", "/tmp/vsp-ds.yaml")
        client.oc("delete -f /tmp/vsp-ds.yaml")
        client.oc_run_or_die("create -f /tmp/vsp-ds.yaml")


class MarvellDpuPlugin(VendorPlugin):
    def __init__(self) -> None:
        pass

    def build_and_start(self, h: host.Host, client: K8sClient, registry: str) -> None:
        # TODO: https://github.com/openshift/dpu-operator/pull/82
        logger.warning("Setting up Marvell DPU not yet implemented")


def init_vendor_plugin(h: host.Host, node_kind: str) -> VendorPlugin:
    # TODO: Autodetect the vendor hardware and return the proper implementation.
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
