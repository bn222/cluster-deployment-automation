import json
import shlex
import os
import host
import k8sClient
import tempfile
from logger import logger


CONTAINER_NAME = "local-container-registry"


class ImageRegistry:
    def __init__(self, rsh: host.Host, listen_port: int = 5000) -> None:
        self.rsh = rsh

        ret = self.rsh.run("hostname -f")
        h = ret.out.strip()
        if not ret.success() or not h:
            raise RuntimeError("Failure to get hostname")
        self.hostname = h
        self.listen_port = listen_port
        self._registry_base_directory = self.rsh.home_dir(".local-container-registry")

    def certificate_path(self) -> str:
        return os.path.join(self._registry_base_directory, "certs")

    def start_image_registry(self, client: k8sClient.K8sClient) -> str:
        self.ensure_running()
        self.ocp_trust(client)
        return self.url()

    def url(self) -> str:
        return f"{self.hostname}:{self.listen_port}"

    def ensure_running(self, *, delete_all: bool = False) -> tuple[str, int]:
        dir_name = self._registry_base_directory

        ret = self.rsh.run(shlex.join(["podman", "inspect", CONTAINER_NAME, "--format", "{{.Id}}"]))

        if ret.success() and self.rsh.run(shlex.join(['test', '-d', dir_name])).success():
            if not delete_all:
                return dir_name, self.listen_port
            self._delete_all()

        dir_name_certs = os.path.join(dir_name, "certs")
        dir_name_data = os.path.join(dir_name, "data")
        dir_name_auth = os.path.join(dir_name, "auth")

        self.rsh.run(shlex.join(["mkdir", "-p", dir_name]))
        self.rsh.run(shlex.join(["mkdir", "-p", dir_name_certs]))
        self.rsh.run(shlex.join(["mkdir", "-p", dir_name_data]))
        self.rsh.run(shlex.join(["mkdir", "-p", dir_name_auth]))

        self.rsh.run_or_die(
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
                    f"/CN={self.hostname}",
                    "-addext",
                    f"subjectAltName = DNS:{self.hostname}",
                ]
            )
        )

        # We need both domain.crt and domain.cert for `podman push --cert-dir` to work.
        self.rsh.run(shlex.join(["ln", "-snf", "domain.crt", os.path.join(dir_name_certs, "domain.cert")]))

        ret = self.rsh.run_or_die(
            shlex.join(
                [
                    "podman",
                    "run",
                    "--name",
                    CONTAINER_NAME,
                    "-p",
                    f"{self.listen_port}:5000",
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
                    f"--annotation=LOCAL_CONTAINER_REGISTRY_HOSTNAME={self.hostname}",
                    "-d",
                    "docker.io/library/registry:latest",
                ]
            )
        )

        return dir_name, self.listen_port

    def _delete_all(self) -> None:
        self.rsh.run(shlex.join(["podman", "rm", "-f", CONTAINER_NAME]))
        self.rsh.run(shlex.join(["rm", "-rf", self._registry_base_directory]))

    def delete_all(self) -> None:
        self._delete_all()

    def trust(self, other: host.Host) -> None:
        cert_dir = self.certificate_path()
        files = os.listdir(cert_dir)
        logger.info(f"trusting files in {cert_dir} and placing them on {other.hostname()}")
        for file in files:
            self.rsh.copy_from(f"{cert_dir}/{file}", f"/tmp/{file}")
            other.copy_to(f"/tmp/{file}", f"/etc/pki/ca-trust/source/anchors/{file}-{self.rsh.hostname()}")
        other.run_or_die("update-ca-trust")

    def self_trust(self) -> None:
        self.trust(self.rsh)

    def ocp_trust(self, client: k8sClient.K8sClient) -> None:
        cm_name = f"local-container-registry-{self.hostname}"

        crt_file = os.path.join(self._registry_base_directory, 'certs/domain.crt')
        crt_file = self.rsh.read_file(crt_file)
        lh = host.LocalHost()
        lh.write("/tmp/crt", crt_file)
        logger.info(f"trusting registry running on {self.rsh.hostname()} in ocp with file {crt_file}")
        client.oc(f"delete cm -n openshift-config {shlex.quote(cm_name)}")
        client.oc(f"create cm -n openshift-config {cm_name} --from-file={self.hostname}..{self.listen_port}=/tmp/crt")
        lh.remove("/tmp/crt")

        data = {"spec": {"additionalTrustedCA": {"name": cm_name}}}

        client.oc(f"patch image.config.openshift.io/cluster --patch {shlex.quote(json.dumps(data))} --type=merge")
