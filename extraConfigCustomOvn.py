from clustersConfig import ClustersConfig
from clustersConfig import NodeConfig
from concurrent.futures import Future
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Tuple
from logger import logger
from clustersConfig import ExtraConfigArgs
import host
import json
import sys

ORIGINAL_IMAGE = "ovnk-image:original"
CUSTOM_IMAGE = "ovnk-custom-image:dev"
DEFAULT_OVN_REPO = "https://github.com/ovn-org/ovn.git"
DEFAULT_OVN_REF = "main"
# OVN build dependencies that can be removed to simplify build on UBI.
REMOVE_DEPS = "graphviz groff sphinx-build unbound checkpolicy selinux-policy-devel tcpdump"
EXECUTOR_SIZE = 20
IMAGE_PATH = "/tmp/image.tar"
VERSION_KEY = "VERSION_ID="
UBI_IMAGE = "registry.access.redhat.com/ubi{}/ubi:{}"


def ExtraConfigCustomOvn(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to build custom OVN from source")

    if not cc.masters:
        die("There isn't any master node available in the config.")

    assert cc.masters[0].ip is not None
    node = host.RemoteHost(cc.masters[0].ip)
    node.ssh_connect("core")

    tag_ovnk_image(node)
    major, version = detect_ubi_version(node)
    ubi_image = UBI_IMAGE.format(major, version)
    logger.info(f"Using {ubi_image} as base image.")

    build_image(node, cfg, ubi_image)
    save_image(node)

    executor = ThreadPoolExecutor(max_workers=EXECUTOR_SIZE)

    all = cc.masters[1:] + cc.workers
    futures = {c.name: executor.submit(load_image, c) for c in all}
    for name, future in futures.items():
        result = future.result()
        if result is not None and not result.success():
            die(f"Failed to load image on \"{name}\": {result}")


def tag_ovnk_image(node: host.Host) -> None:
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


def detect_ubi_version(node: host.Host) -> Tuple[str, str]:
    result = node.run_or_die("sudo crictl exec --name ovn-controller cat /etc/os-release")
    for line in result.out.splitlines():
        if line.startswith(VERSION_KEY):
            version = line.removeprefix(VERSION_KEY).strip("\"")
            major, _, _ = version.partition(".")
            return major, version

    die(f"Couldn't find proper os-release: {result.out}")

    # The return is there to satisfy the linter, it's unreachable normally.
    return "", ""


def build_image(node: host.Host, cfg: ExtraConfigArgs, ubi_image: str) -> None:
    logger.info("Building custom OVN image")
    node.copy_to("manifests/ovn/Dockerfile", "/tmp/Dockerfile")
    node.run_or_die(
        f"sudo podman build -t {CUSTOM_IMAGE} "
        f"--build-arg OVNK_BUILDER_IMAGE={ubi_image} "
        f"--build-arg OVNK_IMAGE={ORIGINAL_IMAGE} "
        f"--build-arg OVN_REPO={cfg.ovn_repo or DEFAULT_OVN_REPO} "
        f"--build-arg OVN_REF={cfg.ovn_ref or DEFAULT_OVN_REF} "
        f"--build-arg OVN_REMOVE_DEPS=\"{REMOVE_DEPS}\" "
        "-f /tmp/Dockerfile . "
        ">/tmp/ovn-custom-image.log 2>&1"
    )


def save_image(node: host.Host) -> None:
    logger.info("Saving custom OVN image")
    node.run_or_die(f"sudo podman save -o {IMAGE_PATH} --format oci-archive {CUSTOM_IMAGE}")
    node.copy_from(IMAGE_PATH, IMAGE_PATH)


def load_image(config: NodeConfig) -> host.Result:
    logger.info(f"Loading custom OVN image on \"{config.name}\"")

    assert config.ip is not None
    node = host.RemoteHost(config.ip)
    node.ssh_connect("core")

    # Running commandline SCP here because of the performance. SFTP was able to transfer with 20Mbps at most,
    # SCP over commandline is able to transfer with >800Mbps.
    local_node = host.LocalHost()
    result = local_node.run(f"scp {IMAGE_PATH} core@{config.ip}:{IMAGE_PATH}")
    if not result.success():
        return result

    return node.run(f"sudo podman load -i {IMAGE_PATH}")


def die(msg: str) -> None:
    logger.error(msg)
    sys.exit(-1)


def main() -> None:
    pass


if __name__ == "__main__":
    main()
