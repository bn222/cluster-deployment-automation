import common
import host
from logger import logger
import sys
from jinja2 import Template
import os
from typing import Optional, Callable, cast
import tempfile
import shutil
from concurrent.futures import Future
from clustersConfig import ClustersConfig
from clustersConfig import ExtraConfigArgs


def ExtraConfigIsoBuilder(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]

    lh = host.LocalHost()
    logger.info("Running config step to build DPU iso")

    #    All fields that bootc_iso_builder expects as non-None and we that don't have a default should be in this list.
    required_params = [
        (cfg.organization_id, "organization_id"),
        (cfg.activation_key, "activation_key"),
    ]

    missing_fields = []
    for value, name in required_params:
        if value is None:
            assert value is None
            missing_fields.append(name)

    if missing_fields:
        logger.error_and_exit(f"Error: Missing required configuration for DPU ISO build: " f"{', '.join(missing_fields)}. " f"Please ensure these are specified in your configuration.")

    final_iso_name: str = cfg.final_iso_name or cc.install_iso or "RHEL-9.6.0-20250416.8-aarch64-dvd1-w-kickstart.iso"

    #    This is safe because the 'if missing_fields' block would have exited if any were None.
    organization_id: str = cast(str, cfg.organization_id)
    activation_key: str = cast(str, cfg.activation_key)

    image_mode_url: str = cfg.image_mode_url
    iso_builder_url: str = cfg.iso_builder_url

    iso_kargs: Optional[str] = cfg.iso_kargs

    bootc_iso_builder(
        lh,
        final_iso_name,
        cc.secrets_path,
        organization_id,
        activation_key,
        image_mode_url,
        iso_builder_url,
        kargs=iso_kargs,
    )


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


def build_iso_builder_image_action(h: host.Host, iso_builder_image_name: str) -> None:
    """
    Action to build the ISO builder image. This will be passed to ensure_image_is_built.
    Handles its own temporary directory and git cloning.
    """
    with tempfile.TemporaryDirectory() as tmpdir_path:
        git_repo = os.path.join(tmpdir_path, "iso-builder")
        common.git_repo_setup(git_repo, repo_wipe=True, url="https://github.com/SamD2021/ipu-rhel-iso-builder.git")
        err, out, returncode = h.run(f"sudo podman build --security-opt label=type:unconfined_t " f"--platform linux/arm64 -t {iso_builder_image_name} {git_repo}")
        if returncode:
            logger.error_and_exit(f"Failed to build ISO builder image '{iso_builder_image_name}' with error: {err}")
        logger.debug(f"ISO builder build output (stdout): {out}")
        logger.debug(f"ISO builder build errors (stderr): {err}")


def bootc_iso_builder(
    h: host.Host,
    name_of_final_iso: str,
    secrets_path: str,
    organization_id: str,
    activation_key: str,
    bootc_image_url: str,
    image_builder_url: str,
    rhel_version: str = "9.6",
    input_iso: Optional[str] = None,
    kickstart: Optional[str] = None,
    kargs: Optional[str] = None,
) -> None:
    """
    Uses temp directories to optionally build the Bootc iso builder and runs it as a cross arch container to build an arm64 image mode iso ready for DPU's
    """
    # Ensure the main bootc image is built
    ensure_image_is_built(h=h, image_name=bootc_image_url, build_action=lambda: build_image_mode_container(h, False, bootc_image_url, secrets_path))

    ensure_image_is_built(h=h, image_name=image_builder_url, build_action=lambda: build_iso_builder_image_action(h, image_builder_url))

    with tempfile.TemporaryDirectory() as tmpdir:
        workdir = os.path.join(tmpdir, "workdir")
        os.makedirs(workdir, exist_ok=True)
        if kickstart is None:
            logger.info("No kickstart given, generating it...")
            final_kickstart = os.path.join(workdir, "kickstart.ks")
            generate_kickstart_image_mode(secrets_path, final_kickstart, organization_id, activation_key)
            kickstart = "kickstart.ks"

        # Set default kernel arguments if not provided
        default_kargs = "ip=192.168.0.2:::255.255.255.0::enp0s1f0:off " "netroot=iscsi:192.168.0.1::::iqn.e2000:acc acpi=force"
        final_kargs = kargs or default_kargs

        # Begin base command args
        args = [
            "sudo podman run --rm --privileged",
            "--security-opt label=type:unconfined_t",
            "--arch aarch64",
            f"-v {secrets_path}:/run/containers/0/auth.json:ro",
            "-v /var/lib/containers:/var/lib/containers",
            "-v /run/containers/storage:/run/containers/storage",
            "-v /dev:/dev",
            f"-v {workdir}:/workdir",
            image_builder_url,
            f"-u {bootc_image_url}",
            f"-v {rhel_version}",
            f"-a {final_kargs}",
            "-o output.iso",
        ]

        # Only add if non-empty
        if input_iso:
            args.append(f"-i {input_iso}")
        if kickstart:
            args.append(f"-k {kickstart}")

        full_command = " ".join(args)
        logger.info(f"Running Bootc ISO Builder:\n{full_command}")
        result = h.run(full_command)
        if result.returncode:
            logger.error(f"Running bootc ISO Builder failed with: {result.err}")
            sys.exit(1)
        logger.debug(f"Running bootc ISO Builder stdout: {result.out}")
        logger.debug(f"Running bootc ISO Builder stderr: {result.err}")

        output_path = os.path.join(workdir, "output.iso")
        if not os.path.exists(output_path):
            logger.error_and_exit(f"Expected output ISO {output_path} not found!")
        shutil.copy(output_path, name_of_final_iso)
        logger.info(f"ISO successfully written to {name_of_final_iso}")
