import json
import shlex
import os
import dataclasses
from logger import logger
import host
import k8sClient

CONTAINER_NAME = "local-container-registry"


def get_local_registry_base_directory(rsh: host.Host) -> str:
    return rsh.home_dir(".local-container-registry")


def get_local_registry_hostname(rsh: host.Host) -> str:
    ret = rsh.run("hostname -f")
    h = ret.out.strip()
    if not ret.success() or not h:
        raise RuntimeError("Failure to get hostname")
    return h


def get_certificate_path(rsh: host.Host) -> str:
    return os.path.join(get_local_registry_base_directory(rsh), "certs")


def start_image_registry(rsh: host.Host, client: k8sClient.K8sClient) -> str:
    reglocal_dir_name, reglocal_hostname, reglocal_listen_port, reglocal_id = ensure_running(rsh)

    ocp_trust(client, reglocal_dir_name, reglocal_hostname, reglocal_listen_port)

    registry = f"{reglocal_hostname}:{reglocal_listen_port}"

    return registry


def ensure_running(rsh: host.Host, *, delete_all: bool = False, listen_port: int = 5000) -> tuple[str, str, int, str]:
    dir_name = get_local_registry_base_directory(rsh)
    hostname = get_local_registry_hostname(rsh)

    ret = rsh.run(shlex.join(["podman", "inspect", CONTAINER_NAME, "--format", "{{.Id}}"]))

    if ret.success() and rsh.run(shlex.join(['test', '-d', dir_name])).success():
        if not delete_all:
            return dir_name, hostname, listen_port, ret.out.strip()
        _delete_all(rsh, dir_name)

    dir_name_certs = os.path.join(dir_name, "certs")
    dir_name_data = os.path.join(dir_name, "data")
    dir_name_auth = os.path.join(dir_name, "auth")

    rsh.run(shlex.join(["mkdir", "-p", dir_name]))
    rsh.run(shlex.join(["mkdir", "-p", dir_name_certs]))
    rsh.run(shlex.join(["mkdir", "-p", dir_name_data]))
    rsh.run(shlex.join(["mkdir", "-p", dir_name_auth]))

    rsh.run_or_die(
        shlex.join(
            [
                "openssl",
                "req",
                "-newkey",
                "rsa:4096",
                "-nodes",
                "-sha256",
                "-keyout",
                os.path.join(dir_name_certs, "domain.key"),
                "-x509",
                "-days",
                "365",
                "-out",
                os.path.join(dir_name_certs, "domain.crt"),
                "-subj",
                f"/CN={hostname}",
                "-addext",
                f"subjectAltName = DNS:{hostname}",
            ]
        )
    )

    # We need both domain.crt and domain.cert for `podman push --cert-dir` to work.
    rsh.run(shlex.join(["ln", "-snf", "domain.crt", os.path.join(dir_name_certs, "domain.cert")]))

    ret = rsh.run_or_die(
        shlex.join(
            [
                "podman",
                "run",
                "--name",
                CONTAINER_NAME,
                "-p",
                f"{listen_port}:5000",
                "-v",
                f"{dir_name_data}:/var/lib/registry:z",
                "-v",
                f"{dir_name_auth}:/auth:z",
                "-v",
                f"{dir_name_certs}:/certs:z",
                "-e",
                "REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt",
                "-e",
                "REGISTRY_HTTP_TLS_KEY=/certs/domain.key",
                "-e",
                "REGISTRY_COMPATIBILITY_SCHEMA1_ENABLED=true",
                f"--annotation=LOCAL_CONTAINER_REGISTRY_HOSTNAME={hostname}",
                "-d",
                "docker.io/library/registry:latest",
            ]
        )
    )

    return dir_name, hostname, listen_port, ret.out.strip()


def _delete_all(rsh: host.Host, dir_name: str) -> None:
    rsh.run(shlex.join(["podman", "rm", "-f", CONTAINER_NAME]))
    rsh.run(shlex.join(["rm", "-rf", dir_name]))


def delete_all(rsh: host.Host) -> None:
    _delete_all(rsh, get_local_registry_base_directory(rsh))


def local_trust(rsh: host.Host) -> None:
    cert_dir = get_certificate_path(rsh)
    files = os.listdir(cert_dir)
    for file in files:
        rsh.copy_to(f"{cert_dir}/{file}", f"/etc/pki/ca-trust/source/anchors/{file}")
    rsh.run_or_die("update-ca-trust")


def ocp_trust(client: k8sClient.K8sClient, dir_name: str, hostname: str, listen_port: int) -> None:
    cm_name = f"local-container-registry-{hostname}"

    crt_file = os.path.join(dir_name, 'certs/domain.crt')
    if not os.path.isfile(crt_file):
        # This function can only operate locally, like K8sClient. The file must
        # exist.
        raise RuntimeError(f"Certificate file {crt_file} does not exist!")

    client.oc(f"delete configmap -n openshift-config {shlex.quote(cm_name)}")
    client.oc(
        shlex.join(
            [
                "create",
                "configmap",
                "-n",
                "openshift-config",
                cm_name,
                f"--from-file={hostname}..{listen_port}={crt_file}",
            ]
        ),
    )

    data = {"spec": {"additionalTrustedCA": {"name": cm_name}}}
    client.oc(f"patch image.config.openshift.io/cluster --patch {shlex.quote(json.dumps(data))} --type=merge")


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

    for ci in container_infos:
        rsh.run_or_die(
            shlex.join(
                [
                    "podman",
                    "push",
                    "--cert-dir",
                    os.path.join(get_certificate_path(rsh)),
                    ci.full_tag,
                ]
            )
        )

    return {ci.envvar: ci.full_tag for ci in container_infos}
