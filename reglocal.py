import shlex
import os
import dataclasses
from logger import logger
import host
from imageRegistry import ImageRegistry


@dataclasses.dataclass(frozen=True)
class GitBuildLocalContainerInfo:
    name: str
    envvar: str
    containerfile: str
    registry: str
    project: str
    full_tag: str = dataclasses.field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "full_tag", f"{self.registry}/{self.project}/{self.name}:latest")


def git_build_local(rsh: host.Host, repo_dir: str, registry: str, project: str, container_infos: list[GitBuildLocalContainerInfo]) -> dict[str, str]:
    for ci in container_infos:
        if os.environ.get("CDA_LOCAL_IMAGE_REBUILD") == "0" and rsh.run(shlex.join(["podman", "images", "-q", ci.full_tag])).out:
            logger.info(f"build container: {ci.full_tag} already exists. Skip")
            continue
        cmd = f"podman build -t {shlex.quote(ci.full_tag)} -f {shlex.quote(ci.containerfile)}"
        logger.info(f"build container: {cmd}")
        # FIXME: os.chdir() cannot be used in a multithreded application
        cur_dir = os.getcwd()
        os.chdir(repo_dir)
        ret = rsh.run(cmd)
        os.chdir(cur_dir)
        if not ret.success():
            logger.warning(f"Command failed: {ret}")
            logger.info("Maybe you lack authentication? Issue a `podman login registry.ci.openshift.org` first or create \"$XDG_RUNTIME_DIR/containers/auth.json\". See https://oauth-openshift.apps.ci.l2s4.p1.openshiftapps.com/oauth/token/request")
            logger.error_and_exit(f"{cmd} failed with returncode {ret.returncode}: output: {ret.out}")

    imgReg = ImageRegistry(rsh)
    for ci in container_infos:
        rsh.run_or_die(
            shlex.join(
                [
                    "podman",
                    "push",
                    "--cert-dir",
                    os.path.join(imgReg.certificate_path()),
                    ci.full_tag,
                ]
            )
        )

    return {ci.envvar: ci.full_tag for ci in container_infos}
