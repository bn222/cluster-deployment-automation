import jinja2
import re
import host
from k8sClient import K8sClient
from logger import logger
from abc import ABC, abstractmethod
from imageRegistry import ImageRegistry


class VendorPlugin(ABC):
    @abstractmethod
    def build_push_start(self, h: host.Host, client: K8sClient, imgReg: ImageRegistry, sha: str, repo: str) -> None:
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
        self._vsp_ds_manifest = "./manifests/dpu/dpu_p4_ds.yaml.j2"

    @property
    def vsp_ds_manifest(self) -> str:
        return self._vsp_ds_manifest

    def get_name_suffix(self, h: host.Host) -> str:
        return h.run("uname -m").out

    def import_from_url(self, url: str) -> None:
        lh = host.LocalHost()
        result = lh.run(f"podman load -q -i {url}")
        tag = result.out.strip().split("\n")[-1].split(":")[-1]
        lh.run_or_die(f"podman tag {tag} intel-ipuplugin:latest")

    def push(self, img_reg: ImageRegistry) -> None:
        lh = host.LocalHost()
        lh.run(f"podman push intel-ipuplugin:latest {self.vsp_image_name(img_reg)}")

    def vsp_image_name(self, img_reg: ImageRegistry) -> str:
        return f"{img_reg.url()}/intel_vsp:dev"

    def build_push_start(self, h: host.Host, client: K8sClient, imgReg: ImageRegistry, sha: str, repo: str) -> None:
        return self.start(self.build_push(h, imgReg, sha, repo), client)

    def build_push(self, h: host.Host, imgReg: ImageRegistry, sha: str, repo: str) -> str:
        logger.info("Building ipu-opi-plugin")
        h.run("rm -rf /root/ipu-opi-plugins")
        h.run_or_die(f"git clone {repo} /root/ipu-opi-plugins")

        logger.info(f"Will build ipu-opi-plugin from commit {sha}")
        h.run_or_die(f"git -C /root/ipu-opi-plugins checkout {sha}")

        fn = "/root/ipu-opi-plugins/ipu-plugin/images/Dockerfile"
        golang_img = extractContainerImage(h.read_file(fn))
        h.run_or_die(f"podman pull docker.io/library/{golang_img}")
        if h.is_localhost():
            env = os.environ.copy()
            env["IMGTOOL"] = "podman"
            env["P4_NAME"] = "fxp-net_linux-networking"
            env["P4_DIR"] = "fxp-net_linux-networking"
            ret = h.run("make -C /root/ipu-opi-plugins/ipu-plugin image", env=env)
        else:
            lh = host.LocalHost()
            h.write("/run/user/0/containers/auth.json", lh.read_file("/run/user/0/containers/auth.json"))
            ret = h.run("IMGTOOL=podman make -C /root/ipu-opi-plugins/ipu-plugin image")

        if not ret.success():
            logger.error_and_exit("Failed to build vsp images")
        vsp_image = self.vsp_image_name(imgReg)
        h.run_or_die(f"podman tag intel-ipuplugin:latest {vsp_image}")
        h.run_or_die(f"podman push {vsp_image}")
        # WA to ensure multiarch vsp image manifest is available
        # push images with both the name expected by the dpu operator (so we can proceed with deploying host side)
        # and the name expected by the manifest that we will build during the IPU deployment step
        h.run_or_die(f"podman tag {vsp_image} {vsp_image}-{self.get_name_suffix(h)}")
        h.run_or_die(f"podman push {vsp_image}-{self.get_name_suffix(h)}")
        return vsp_image

    def start(self, vsp_image: str, client: K8sClient) -> None:
        self.render_dpu_vsp_ds_helper(vsp_image, "/tmp/vsp-ds.yaml")
        client.oc("delete -f /tmp/vsp-ds.yaml")
        client.oc_run_or_die("create -f /tmp/vsp-ds.yaml")

    def render_dpu_vsp_ds_helper(self, ipu_plugin_image: str, outfilename: str) -> None:
        with open(self.vsp_ds_manifest) as f:
            j2_template = jinja2.Template(f.read())
            rendered = j2_template.render(ipu_plugin_image=ipu_plugin_image)
            logger.info(rendered)
        lh = host.LocalHost()
        lh.write(outfilename, rendered)


class MarvellDpuPlugin(VendorPlugin):
    def __init__(self) -> None:
        pass

    def build_push_start(self, h: host.Host, client: K8sClient, imgReg: ImageRegistry, sha: str, repo: str) -> None:
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
