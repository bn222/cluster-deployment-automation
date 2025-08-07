from typing import Optional, Callable
import os
import tempfile
import shutil
from jinja2 import Template
import common
import host
from logger import logger


class BootcIsoBuilder:
    def __init__(
        self,
        host: host.Host,
        name_of_final_iso: str,
        secrets_path: str,
        organization_id: str,
        activation_key: str,
        bootc_image_url: str,
        image_builder_url: str,
        dpu_flavor: str = "agnostic",
        rhel_version: str = "9",
        input_iso: Optional[str] = None,
        kickstart: Optional[str] = None,
        kernel_args: Optional[str] = "",
        remove_args: Optional[str] = None,
        grub_replacements: Optional[list[str]] = None,
        auth_file_path: Optional[str] = None,  # Allow custom auth file path
        bootc_dir: str = "rhel-image-mode-4-dpu",
        bootc_build_local: bool = True,
    ):
        self.h = host
        self.name_of_final_iso = name_of_final_iso
        self.secrets_path = secrets_path
        self.organization_id = organization_id
        self.activation_key = activation_key
        self.bootc_image_url = bootc_image_url
        self.image_builder_url = image_builder_url
        self.dpu_flavor = dpu_flavor
        self.rhel_version = rhel_version
        self.input_iso = input_iso
        self.kickstart = kickstart
        self.kernel_args = kernel_args
        self.remove_args = remove_args
        self.grub_replacements = grub_replacements or []
        # Use custom auth file path if provided, otherwise fallback to secrets_path for backwards compatibility
        self.auth_file_path = auth_file_path or secrets_path
        self.bootc_dir = bootc_dir
        self.bootc_build_local = bootc_build_local

    def _add_transport_prefix(self, image: str) -> str:
        if image.startswith("containers-storage:") or image.startswith("docker://"):
            return image

        is_local = image.startswith("localhost/")
        return ("containers-storage:" if is_local else "docker://") + image

    def _image_exists(self, image_name: str) -> bool:
        return self.h.run(f"sudo podman image exists '{image_name}'").success()

    def ensure_image_is_built(self, image_name: str, build_action: Callable[[], None]) -> None:
        """
        Ensures the image is available:
        - Local images (localhost/, containers-storage:, dir://): build locally, no push
        - Docker registry images (docker://): build locally and push to registry
        - Other remote images: try to pull from registry
        """
        is_local = image_name.startswith("containers-storage:") or image_name.startswith("dir://") or image_name.startswith("localhost/")
        is_docker_registry = image_name.startswith("docker://")

        if is_local:
            logger.info(f"Building local image '{image_name}' (no push)")
            build_action()
            return

        if is_docker_registry and self.bootc_build_local:
            # Strip docker:// prefix for podman commands
            registry_name = image_name.replace("docker://", "")

            logger.info(f"Building image locally and pushing to '{registry_name}'")
            build_action()

            # Push to the docker registry
            logger.info(f"Pushing image to {registry_name}")
            push_result = self.h.run(f"sudo podman push --authfile {self.auth_file_path} {registry_name}")
            if not push_result.success():
                logger.error_and_exit(f"Failed to push image to '{registry_name}': {push_result.err}")

            logger.info(f"Successfully pushed image to {registry_name}")
            return

        # For other remote images, try to pull
        logger.info(f"Pulling remote image: {image_name}")
        if not self.h.run(f"sudo podman pull --authfile {self.auth_file_path} {image_name}").success():
            logger.error_and_exit(f"Failed to pull remote image '{image_name}', push the container to {image_name} to build the iso here, or change transport to localhost to build a default image")

        if not self.h.run(f"sudo podman image exists {image_name}").success():
            logger.error_and_exit(f"Image '{image_name}' could not be pulled or built.")

    def build_image_mode_container(self, image_name: str) -> None:
        label = "Image Mode container"
        logger.info(f"Building {label} image from local source...")
        # Strip docker:// prefix for podman commands
        image_name = image_name.replace("docker://", "")
        if not os.path.exists(self.bootc_dir):
            logger.error_and_exit(f"Expected local directory at {self.bootc_dir}, but it does not exist.")

        entitlement_cert = next((os.path.join(r, f) for r, _, fs in os.walk("/etc/pki/entitlement/") for f in fs if f.endswith(".pem") and not f.endswith("-key.pem")), None)
        entitlement_key = next((os.path.join(r, f) for r, _, fs in os.walk("/etc/pki/entitlement/") for f in fs if f.endswith("-key.pem")), None)
        repo_file = "/etc/yum.repos.d/redhat.repo"
        rhsm_ca = "/etc/rhsm/ca/redhat-uep.pem"

        if not all([entitlement_cert, entitlement_key]) or not os.path.exists(repo_file) or not os.path.exists(rhsm_ca):
            logger.error_and_exit("Missing required entitlement or repo files.")

        args = [
            "sudo podman build",
            "--security-opt label=type:unconfined_t",
            f"--authfile {self.auth_file_path}",
            f"--build-arg DPU_FLAVOR={self.dpu_flavor}",
            "--arch aarch64",
            f"--secret=id=redhat-repo,src={repo_file}",
            f"--secret=id=entitlement-cert,src={entitlement_cert}",
            f"--secret=id=entitlement-key,src={entitlement_key}",
            f"--secret=id=rhsm-ca,src={rhsm_ca}",
            f"-t {image_name}",
            self.bootc_dir,
        ]
        command = " ".join(args)

        err, out, returncode = self.h.run(command)
        if returncode:
            logger.error_and_exit(f"Failed to build {label} image with error: {err}")

        logger.debug(f"{label} build output (stdout): {out}")
        logger.debug(f"{label} build errors (stderr): {err}")
        logger.info(f"Successfully built {label} image")

    def build_iso_builder_image(self, image_name: str, dir: str = "iso-surgeon") -> None:
        label = "ISO Surgeon"
        logger.info(f"Building {label} image from local source...")
        if not os.path.exists(dir):
            logger.error_and_exit(f"Expected local directory at {dir}, but it does not exist.")

        err, out, returncode = self.h.run(f"sudo podman build --security-opt label=type:unconfined_t " f"--authfile {self.auth_file_path} --platform linux/arm64 -t {image_name} {dir}")
        if returncode:
            logger.error_and_exit(f"Failed to build {label} image with error: {err}")

        logger.debug(f"{label} build output (stdout): {out}")
        logger.debug(f"{label} build errors (stderr): {err}")
        logger.info(f"Successfully built {label} image")

    def generate_kickstart_image_mode(self, final_kickstart: str) -> None:
        with open(self.secrets_path, "r") as f_in:
            file_contents = f_in.read()
        with open(self.auth_file_path, "r") as f_in:
            ostree_auth_json = f_in.read()

        ssh_pub, _, _ = next(common.iterate_ssh_keys(), (None, None, None))
        if ssh_pub is not None:
            with open(ssh_pub, "r") as ssh_in:
                ssh_contents = ssh_in.read()
        else:
            logger.error("No ssh keys found in generate_kickstart")
            raise SystemExit(-1)

        template_file = "kickstart-image-mode.ks.j2"
        with open(template_file, "r") as f:
            lines = f.read()
        image_name = self.bootc_image_url
        is_local = image_name.startswith("containers-storage:") or image_name.startswith("dir://") or image_name.startswith("localhost/")
        image_ref = self.bootc_image_url.replace("docker://", "")

        with open(final_kickstart, "w") as f_out:
            template = Template(lines)
            f_out.write(
                template.render(
                    pull_secret=file_contents,
                    ssh_key=ssh_contents,
                    rhc_org_id=self.organization_id,
                    rhc_act_key=self.activation_key,
                    kargs=self.kernel_args,
                    is_remote=not is_local,
                    ostree_auth_json=ostree_auth_json,
                    image_ref=image_ref,
                    dpu_flavor=self.dpu_flavor,
                )
            )
        if not os.path.exists(final_kickstart):
            logger.error_and_exit(f"Expected generated kickstart not found at: {final_kickstart}")
        logger.debug(f"Kickstart generated at {final_kickstart}")

    def build(self) -> None:
        # 1. Build the OS Container that we want to build the ISO from
        self.ensure_image_is_built(
            self.bootc_image_url,
            lambda: self.build_image_mode_container(self.bootc_image_url),
        )
        # 2. Build the ISO Builder (iso-surgeon) Container we will build the ISO with
        self.ensure_image_is_built(
            self.image_builder_url,
            lambda: self.build_iso_builder_image(self.image_builder_url),
        )

        # Create a temporary environment to keep things clean
        with tempfile.TemporaryDirectory() as tmpdir:
            # Ensure workdir is available within the temp dir
            workdir = os.path.join(tmpdir, "workdir")
            os.makedirs(workdir, exist_ok=True)

            # Check if the kickstart
            if self.kickstart is None:
                logger.info("No kickstart given, generating it...")
                final_kickstart = os.path.join(workdir, "kickstart.ks")
                self.generate_kickstart_image_mode(final_kickstart)
                self.kickstart = "kickstart.ks"

            args = [
                "sudo podman run --rm --privileged",
                "--security-opt label=type:unconfined_t",
                "--arch aarch64",
                f"-v {self.auth_file_path}:/run/containers/0/auth.json:ro",
                "-v /var/lib/containers:/var/lib/containers",
                "-v /run/containers/storage:/run/containers/storage",
                "-v /dev:/dev",
                f"-v {workdir}:/workdir",
                self.image_builder_url,
                f"-u {self._add_transport_prefix(self.bootc_image_url)}",
                f"-v {self.rhel_version}",
            ]

            if self.kernel_args:
                args.append(f"-a '{self.kernel_args}'")
            if self.remove_args:
                args.append(f"-r '{self.remove_args}'")
            if self.grub_replacements:
                for replacement in self.grub_replacements:
                    args.append(f"-R '{replacement}'")
            if self.input_iso:
                args.append(f"-i {self.input_iso}")
            if self.kickstart:
                args.append(f"-k {self.kickstart}")

            args.append("-o output.iso")

            full_command = " ".join(args)
            logger.info(f"Running Bootc ISO Builder:\n{full_command}")
            result = self.h.run(full_command)
            if result.returncode:
                logger.error(f"Running bootc ISO Builder failed with: {result.err}")
                raise SystemExit(1)
            logger.debug(f"Running bootc ISO Builder stdout: {result.out}")
            logger.debug(f"Running bootc ISO Builder stderr: {result.err}")

            output_path = os.path.join(workdir, "output.iso")
            if not os.path.exists(output_path):
                logger.error_and_exit(f"Expected output ISO {output_path} not found!")
            shutil.copy(output_path, self.name_of_final_iso)
            logger.info(f"ISO successfully written to {self.name_of_final_iso}")
