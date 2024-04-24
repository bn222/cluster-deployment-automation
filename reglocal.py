import json
import shlex
import os

from typing import Optional

import host
import k8sClient

CONTAINER_NAME = "local-container-registry"


def _dir_name(rsh: host.Host) -> str:
    return rsh.home_dir(".local-container-registry")


def _hostname(rsh: host.Host) -> str:
    ret = rsh.run("hostname -f")
    h = ret.out.strip()
    if not ret.success() or not h:
        raise RuntimeError("Failure to get hostname")
    return h


def ensure_running(rsh: Optional[host.Host] = None, *, delete_all: bool = False, listen_port: int = 5000) -> tuple[str, str, int, str]:
    if rsh is None:
        rsh = host.LocalHost()

    dir_name = _dir_name(rsh)
    hostname = _hostname(rsh)

    ret = rsh.run(["podman", "inspect", CONTAINER_NAME, "--format", "{{.Id}}"])

    if ret.success() and rsh.run(['test', '-d', dir_name]).success():
        if not delete_all:
            return dir_name, hostname, listen_port, ret.out.strip()
        _delete_all(rsh, dir_name)

    dir_name_certs = os.path.join(dir_name, "certs")
    dir_name_data = os.path.join(dir_name, "data")
    dir_name_auth = os.path.join(dir_name, "auth")

    rsh.run(["mkdir", "-p", dir_name])
    rsh.run(["mkdir", "-p", dir_name_certs])
    rsh.run(["mkdir", "-p", dir_name_data])
    rsh.run(["mkdir", "-p", dir_name_auth])

    rsh.run(
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
        ],
        die_on_error=True,
    )

    # We need both domain.crt and domain.cert for `podman push --cert-dir` to work.
    rsh.run(["ln", "-snf", "domain.crt", os.path.join(dir_name_certs, "domain.cert")])

    ret = rsh.run(
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
        ],
        die_on_error=True,
    )

    return dir_name, hostname, listen_port, ret.out.strip()


def _delete_all(rsh: host.Host, dir_name: str) -> None:
    rsh.run(["podman", "rm", "-f", CONTAINER_NAME])
    rsh.run(["rm", "-rf", dir_name])


def delete_all(rsh: Optional[host.Host] = None) -> None:
    if rsh is None:
        rsh = host.LocalHost()
    _delete_all(rsh, _dir_name(rsh))


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
