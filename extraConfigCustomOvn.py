from clustersConfig import ClustersConfig
from clustersConfig import NodeConfig
from concurrent.futures import Future
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from logger import logger
from clustersConfig import ExtraConfigArgs
import host
import json
import sys

ORIGINAL_IMAGE = "ovnk-image:original"
CUSTOM_IMAGE = "ovnk-custom-image:dev"
OVN_REPO = "https://github.com/ovn-org/ovn.git"
OVN_BRANCH = "main"
# OVN build dependencies that can be removed to simplify build on UBI.
REMOVE_DEPS = "graphviz groff sphinx-build unbound checkpolicy selinux-policy-devel"
EXECUTOR_SIZE = 20
IMAGE_PATH = "/tmp/image.tar"


def ExtraConfigCustomOvn(cc: ClustersConfig, _cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to build custom OVN from source")

    if not cc.masters:
        die("There isn't any master node available in the config.")

    node = host.RemoteHost(cc.masters[0].ip)
    node.ssh_connect("core")

    tag_ovnk_image(node)
    build_image(node)
    save_image(node)

    executor = ThreadPoolExecutor(max_workers=EXECUTOR_SIZE)

    all = cc.masters[1:] + cc.workers
    futures = {c.name: executor.submit(load_image, c) for c in all}
    for name, future in futures.items():
        result = future.result()
        if not result.success():
            die(f"Failed to load image on \"{name}\": {result}")


def tag_ovnk_image(node: host.Host):
    result = node.run_or_die("sudo crictl ps --name ovn-controller -o json")
    images = json.loads(result.out)
    containers = images.get("containers")

    if not containers:
        die(f"Couldn't find ovn-controller image in \"{images}\"")

    image = containers[0]["image"]["image"]
    logger.info(f"Found ovn-k base image: {image}")

    if node.run(f"sudo podman image exists {ORIGINAL_IMAGE}").success():
        logger.info(f"Found original image with tag \"{ORIGINAL_IMAGE}\"")
    else:
        node.run_or_die(f"sudo podman tag {image} {ORIGINAL_IMAGE}")
        logger.info(f"Tagging the original image as \"{ORIGINAL_IMAGE}\"")


def build_image(node: host.Host):
    logger.info("Building custom OVN image")
    node.copy_to("manifests/ovn/Dockerfile", "/tmp/Dockerfile")
    node.run_or_die(
        f"sudo podman build -t {CUSTOM_IMAGE} "
        f"--build-arg OVNK_IMAGE={ORIGINAL_IMAGE} "
        f"--build-arg OVN_REPO={OVN_REPO} "
        f"--build-arg OVN_BRANCH={OVN_BRANCH} "
        f"--build-arg OVN_REMOVE_DEPS=\"{REMOVE_DEPS}\" "
        "-f /tmp/Dockerfile . "
        ">/tmp/ovn-custom-image.log 2>&1"
    )


def save_image(node: host.Host):
    logger.info("Saving custom OVN image")
    node.run_or_die(f"sudo podman save -o {IMAGE_PATH} --format oci-archive {CUSTOM_IMAGE}")
    node.copy_from(IMAGE_PATH, IMAGE_PATH)


def load_image(config: NodeConfig) -> host.Result:
    logger.info(f"Loading custom OVN image on \"{config.name}\"")

    node = host.RemoteHost(config.ip)
    node.ssh_connect("core")

    # Running commandline SCP here because of the performance. SFTP was able to transfer with 20Mbps at most,
    # SCP over commandline is able to transfer with >800Mbps.
    local_node = host.LocalHost()
    result = local_node.run(f"scp {IMAGE_PATH} core@{config.ip}:{IMAGE_PATH}")
    if not result.success():
        return result

    return node.run(f"sudo podman load -i {IMAGE_PATH}")


def die(msg: str):
    logger.error(msg)
    sys.exit(-1)


def main() -> None:
    pass


if __name__ == "__main__":
    main()
