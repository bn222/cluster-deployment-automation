import common
import host
from logger import logger
import sys
from jinja2 import Template
import os
from typing import Optional, Callable


# uses jinja to generate a kickstart file
def generate_kickstart_image_mode(secrets_path: str, final_kickstart: str, rhc_org_id: str, rhc_act_key: str) -> None:
    with open(secrets_path, 'r') as f_in:
        file_contents = f_in.read()

    ssh_pub, _, _ = next(common.iterate_ssh_keys(), (None, None, None))
    if ssh_pub is not None:
        with open(ssh_pub, 'r') as ssh_in:
            ssh_contents = ssh_in.read()
    else:
        logger.error("No ssh keys found in generate_kickstart")
        sys.exit(-1)

    template_file = "kickstart-image-mode.ks.j2"
    with open(template_file, 'r') as f:
        lines = f.read()

    with open(final_kickstart, 'w') as f_out:
        template = Template(lines)
        f_out.write(template.render(pull_secret=file_contents, ssh_key=ssh_contents, rhc_org_id=rhc_org_id, rhc_act_key=rhc_act_key))
    if not os.path.exists(final_kickstart):
        logger.error_and_exit(f"Expected generated kickstart not found at: {final_kickstart}")
    logger.debug(f"Kickstart generated at {final_kickstart}")


def build_image_mode_container(h: host.Host, push: bool, image_name: str, secrets_path: str, dir: Optional[str] = None) -> None:
    logger.info("Starting to build image mode container...")
    if not dir:
        dir = "rhel-image-mode-4-dpu"
    err, out, returncode = h.run("sudo podman build --security-opt label=type:unconfined_t " f"--authfile {secrets_path} --platform linux/arm64 -t {image_name} {dir}")
    if returncode:
        logger.error_and_exit(f"Failed to build image mode container with error: {err}")
    logger.info(f"out: {out}")
    logger.info(f"err: {err}")

    if push:
        h.run(f"sudo podman push -t {image_name}")
    logger.info("Successfully built Image Mode container")


def ensure_image_is_built(h: host.Host, image_name: str, build_action: Callable[[], None]) -> None:
    """
    Checks if a Podman image exists. If not, it executes the provided build_action.

    Args:
        h: The host object to run commands on.
        image_name: The full name (including registry/tag) of the image to check.
        build_action: A callable (function or lambda) that performs the image build
                      if the image does not exist. This function should handle
                      its own logging for the build process itself.
    """
    if h.run(f"sudo podman image exists {image_name}").success():
        logger.info(f"Image '{image_name}' already exists. Skipping build.")
    else:
        logger.info(f"Building '{image_name}'...")
        build_action()  # Execute the provided build logic
        logger.info(f"Successfully ensured image '{image_name}' is available.")
