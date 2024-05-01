import os
import shutil
import json
import time
import sys
import re
import filecmp
from typing import Optional
from typing import Union
from typing import Sequence
import yaml
import requests
from requests import get as get_url
from logger import logger
import host


def load_url_or_file(url_or_file: str) -> str:
    if url_or_file.startswith("http"):
        return get_url(url_or_file).text
    return open(url_or_file).read()


"""
Assisted service is an utility to deploy clusters. The Git repository is
available here: https://github.com/openshift/assisted-service

We deploy the assisted service on the host with Podman. This is documented here:
https://github.com/openshift/assisted-service/tree/master/deploy/podman

There are 2 yaml files that are important: "configmap.yml" and "pod-persistent.yml".

To set up the assisted service pod correctly, the "IMAGE_SERVICE_BASE_URL" and
"SERVICE_BASE_URL" must point to the local host where we want to deploy from.

Additionally some images are provided manually and some hardware limitations are
overwritten. In the config map we append certain multi-arch releases such that
we can deploy on both ARM and x86.

The assisted installer pod would expose a web interface at "http://<host ip>:8080/clusters"
that can be used to create and monitor clusters. However, since we are deploying in a
non-standard way, the web-ui can't be used.
"""


class AssistedInstallerService:
    # Freeze SAAS version to avoid unexpected breakages.
    # The values are taken from:
    # https://gitlab.cee.redhat.com/service/app-interface/-/blob/ee5f631ce539537085b5ef043bbd9593fa74f860/data/services/assisted-installer/cicd/target/production/assisted-service.yaml#L44-47
    #
    # NOTE: aicli is compatible only with v2.29.0+ but the AI API doesn't come
    # up unless we use the installer and agent versions from v2.27.0.
    SAAS_VERSION = "v2.29.0"
    INSTALLER_IMAGE = "registry.redhat.io/rhai-tech-preview/assisted-installer-rhel8:v1.0.0-306"
    CONTROLLER_IMAGE = "registry.redhat.io/rhai-tech-preview/assisted-installer-reporter-rhel8:v1.0.0-383"
    AGENT_DOCKER_IMAGE = "registry.redhat.io/rhai-tech-preview/assisted-installer-agent-rhel8:v1.0.0-295"

    def __init__(self, version: str, ip: str, proxy: Optional[str] = None, noproxy: Optional[str] = None, branch: str = "master"):
        self._version = version
        self._ip = ip
        self._proxy = proxy
        self._noproxy = noproxy
        base_url = f"https://raw.githubusercontent.com/openshift/assisted-service/{branch}"
        pod_config_url = f"{base_url}/deploy/podman/configmap.yml"
        pod_file = f"{base_url}/deploy/podman/pod-persistent.yml"
        self.podConfig = load_url_or_file(pod_config_url)
        self.podFile = load_url_or_file(pod_file)
        self.workdir = os.path.join(os.getcwd(), "build")

    def _configure(self) -> None:
        os.makedirs(self.workdir, exist_ok=True)
        with open(self._config_map_path(), 'w') as out_configmap:
            yaml.dump(self._customized_configmap(), out_configmap, sort_keys=False)

        with open(self._pod_persistent_path(), 'w') as out_pod:
            yaml.dump(self._customized_pod_persistent(), out_pod, default_flow_style=False)

    def _config_map_path(self) -> str:
        return f'{self.workdir}/configmap.yml'

    def _pod_persistent_path(self) -> str:
        return f'{self.workdir}/pod-persistent.yml'

    def _last_run_cm(self) -> str:
        return f'{self.workdir}/configmap-last.yml'

    def _last_run_pod(self) -> str:
        return f'{self.workdir}/pod-persistent-last.yml'

    def _customized_configmap(self) -> dict[str, str]:
        y = yaml.safe_load(self.podConfig)
        if not isinstance(y, dict):
            logger.error(f"Failed to load yaml: {self.podConfig}")
            sys.exit(-1)
        y["data"]["IMAGE_SERVICE_BASE_URL"] = f"http://{self._ip}:8888"
        y["data"]["SERVICE_BASE_URL"] = f"http://{self._ip}:8090"
        y["data"]["INSTALLER_IMAGE"] = AssistedInstallerService.INSTALLER_IMAGE
        y["data"]["CONTROLLER_IMAGE"] = AssistedInstallerService.CONTROLLER_IMAGE
        y["data"]["AGENT_DOCKER_IMAGE"] = AssistedInstallerService.AGENT_DOCKER_IMAGE

        j = json.loads(y["data"]["HW_VALIDATOR_REQUIREMENTS"])
        j[0]["master"]["disk_size_gb"] = 8
        j[0]["worker"]["disk_size_gb"] = 8
        j[0]["sno"]["disk_size_gb"] = 8
        y["data"]["HW_VALIDATOR_REQUIREMENTS"] = json.dumps(j)
        # Don't reuse json.loads(y["data"]["RELEASE_IMAGES"]). It seems
        # that AI doesn't allow to use similar versions (like both -ec.3
        # and nightly) in the same config. For that reason, pass in the
        # version, and instantiate AI _only_ with one version, i.e. the
        # version we will be using.
        version_contents = self.prep_version(self._version)
        y["data"]["RELEASE_IMAGES"] = json.dumps([version_contents])
        if self._proxy:
            y["data"]["http_proxy"] = self._proxy
            y["data"]["https_proxy"] = self._proxy
        if self._noproxy:
            y["data"]["no_proxy"] = self._noproxy
        return y

    def _customized_pod_persistent(self) -> dict[str, str]:
        y = yaml.safe_load(self.podFile)
        if not isinstance(y, dict):
            logger.error(f"Failed to load yaml: {self.podFile}")
            sys.exit(-1)

        containers = y['spec']['containers']
        for container in containers:
            image = container.get('image', '')
            if image.startswith('quay.io/edge-infrastructure/assisted'):
                container['image'] = image.replace(':latest', f':{AssistedInstallerService.SAAS_VERSION}')

        return y

    def prep_version(self, version: str) -> dict[str, Union[str, Sequence[str]]]:
        if re.search(r'4\.12\.0-nightly', version):
            # Note how 4.12.0 has the -multi suffix because AI requires that
            # for 4.12. CDA hides this and simply expect 4.12.0 from the user
            # since that follows the same versioning scheme
            ret = {
                'openshift_version': '4.12-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_nightly_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.12\.[0-9]+', version):
            ret = {
                'openshift_version': f'{version}',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_normal_pullspec(version.rstrip("-multi")),
                'version': version,
            }
        elif re.search(r'4\.13\.0-ec.[0-9]+', version):
            ret = {
                'openshift_version': '4.13-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_normal_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.13\.0-nightly', version):
            ret = {
                'openshift_version': '4.13-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_nightly_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.13\.[0-9]+', version):
            ret = {
                'openshift_version': '4.13-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_normal_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.14\.0-ec.[0-9]+', version):
            # workaround: if openshift_version == 4.14-multi, and
            # version == "4.14.0" nightly, it errors out. Instead
            # pretend that we are installing 4.13, but use the 4.14
            # pullspec
            wa_version = version.replace("4.14", "4.13")
            ret = {
                'openshift_version': '4.13-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_normal_pullspec(version),
                'version': wa_version,
            }
        elif re.search(r'4\.14\.0-nightly', version):
            wa_version = "4.13.0-nighty"

            ret = {
                'openshift_version': '4.13-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_nightly_pullspec(version),
                'version': wa_version,
            }
        elif re.search(r'4\.15\.0-nightly', version):
            wa_version = "4.15.0-nighty"

            ret = {
                'openshift_version': '4.15-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_nightly_pullspec(version),
                'version': wa_version,
            }
        elif re.search(r'4\.16\.0-nightly', version):
            wa_version = "4.16.0-nighty"

            ret = {
                'openshift_version': '4.16-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_nightly_pullspec(version),
                'version': wa_version,
            }
        else:
            logger.error(f"Unknown version {version}")
            sys.exit(-1)
        ret["cpu_architecture"] = "multi"
        if "ec" in version or "nightly" in version:
            ret["support_level"] = "beta"
        ret["cpu_architectures"] = ['x86_64', 'arm64', 'ppc64le', 's390x']
        return ret

    def get_nightly_pullspec(self, version: str) -> str:
        version = version.rstrip("-nightly")
        url = f'https://multi.ocp.releases.ci.openshift.org/api/v1/releasestream/{version}-0.nightly-multi/latest'
        response = requests.get(url)
        j = json.loads(response.content)
        if not isinstance(j, dict):
            decoded = response.content.decode('utf-8')
            logger.error(f"Failed to get json from '{decoded}'")
            sys.exit(-1)
        pull_spec = j["pullSpec"]
        if not isinstance(pull_spec, str):
            logger.error(f"Unexpected pull spec {pull_spec}")
            sys.exit(-1)
        return pull_spec

    def get_normal_pullspec(self, version: str) -> str:
        return f"quay.io/openshift-release-dev/ocp-release:{version}-multi"

    def find_pod(self, name: str) -> Optional[dict[str, str]]:
        lh = host.LocalHost()
        result = lh.run("podman pod ps --format json")
        if result.err:
            logger.error(f"Error {result.err}")
            sys.exit(1)

        j = json.loads(result.out)
        if not isinstance(j, list):
            logger.error(f"Failed to load json from {result.out}")
            sys.exit(-1)

        for x in j:
            if not isinstance(x, dict):
                logger.error(f"Failed to load json from {x}")
                sys.exit(-1)
            if x["Name"] == name:
                return x
        return None

    def pod_running(self) -> bool:
        return bool(self.find_pod("assisted-installer"))

    def last_cm_is_same(self) -> bool:
        return os.path.exists(self._last_run_cm()) and filecmp.cmp(self._config_map_path(), self._last_run_cm())

    def last_pod_is_same(self) -> bool:
        return os.path.exists(self._last_run_pod()) and filecmp.cmp(self._pod_persistent_path(), self._last_run_pod())

    def stop_needed(self, force: bool) -> bool:
        name = "assisted-installer"
        ai_pod = self.find_pod(name)
        if not ai_pod:
            logger.info(f"{name} not yet running")
            return False

        if force:
            logger.info(f"{name} already running but force requested")
            return True
        if ai_pod["Status"] != "Running":
            logger.info(f'{name} already exists but status is {ai_pod["Status"]}')
            return True

        if self.last_cm_is_same() and self.last_pod_is_same():
            logger.info(f"{name} already running with the same configmap and pod config")
            return False
        logger.info(f"{name} already running with a different configmap")
        return True

    def _ensure_pod_started(self, force: bool) -> None:
        if self.stop_needed(force):
            self.stop()

        if not self.pod_running():
            logger.info("Starting assisted-installer.")
            shutil.copy(self._config_map_path(), self._last_run_cm())
            shutil.copy(self._pod_persistent_path(), self._last_run_pod())
            self._play_kube(self._last_run_cm(), self._last_run_pod())

    def _play_kube(self, cm: str, pod: str) -> host.Result:
        lh = host.LocalHost()
        r = lh.run_or_die(f"podman play kube --configmap {cm} {pod}")
        return r

    def _ensure_libvirt_running(self) -> None:
        lh = host.LocalHost()
        if all(x["ifname"] != "virbr0" for x in lh.all_ports()):
            logger.info("Can't find virbr0. Trying to restart libvirt.")
            cmd = "systemctl start libvirtd"
            lh.run(cmd)
            cmd = "virsh net-start default"
            lh.run(cmd)

            # Not sure whether or why this is needed. But we've seen failures w/o this.
            # Need to find out if/how we can remove this to speed up.
            time.sleep(5)

        if all(x["ifname"] != "virbr0" for x in lh.all_ports()):
            logger.error("Can't find virbr0. Make sure that libvirtd is running.")
            sys.exit(-1)

    def wait_for_api(self) -> None:
        self._ensure_libvirt_running()

        url = f"http://{self._ip}:8090/api/assisted-install/v2/clusters"
        response, count = 0, 0
        logger.info(f"Waiting for API to be ready at {url}...")
        while response != 200:
            try:
                response = get_url(url).status_code
            except Exception:
                pass
            if count == 10:
                logger.info("Error: API is down")
                sys.exit(1)
            count += 1
            time.sleep(2)

    def stop(self) -> None:
        if not self.pod_running():
            return

        name = 'assisted-installer'
        logger.info(f"Tearing down {name}.")

        pod_yml = self._pod_persistent_path()
        if os.path.exists(self._last_run_pod()):
            pod_yml = self._last_run_pod()

        lh = host.LocalHost()

        ret = lh.run(f"podman kube down --force {pod_yml}")
        if ret.returncode:
            # Older podman may not support 'down' or '--force'.
            if any(x in ret.err for x in ['unrecognized', 'unknown']):
                logger.warning("podman kube down --force is not supported. Persistent volumes will remain.")
                ret = lh.run(f"podman pod rm -f {name}")

        if ret.returncode:
            logger.error(f"Failed to teardown {name}: {ret.err}")

    def start(self, force: bool = False) -> None:
        self._configure()
        self._ensure_pod_started(force)
        self.wait_for_api()

    def export_snapshot(self, path: str) -> None:
        lh = host.LocalHost()

        def export_vol(path: str, vol_name: str) -> None:
            nested = f"tar -czf /export_data/{vol_name}.tar.gz -C /source_data ."
            cmd = f"podman run -it --name snapshot --privileged -v {vol_name}:/source_data -v {path}:/export_data alpine sh -c '{nested}'"
            logger.info(cmd)
            logger.info(lh.run(cmd))
            logger.info(lh.run("podman rm snapshot"))

        target = ["ai-service-data", "ai-db-data"]
        logger.info(f"exporting {target} to {path}")
        for e in target:
            export_vol(path, e)

    def import_snapshot(self, path: str) -> None:
        self.stop()
        lh = host.LocalHost()

        def import_vol(path: str, vol_name: str) -> None:
            nested = "rm -rf /source_data/*"
            cmd = f"podman run -it --name snapshot --privileged -v {vol_name}:/source_data -v {path}:/export_data alpine sh -c '{nested}'"
            lh.run("podman rm snapshot")
            logger.info(lh.run(cmd))
            logger.info(lh.run("podman rm snapshot"))
            nested = f"tar -xzf /export_data/{vol_name}.tar.gz -C /source_data"
            cmd = f"podman run -it --name snapshot --privileged -v {vol_name}:/source_data -v {path}:/export_data alpine sh -c '{nested}'"
            logger.info(cmd)
            lh.run("podman rm snapshot")
            logger.info(lh.run(cmd))
            logger.info(lh.run("podman rm snapshot"))

        target = ["ai-service-data", "ai-db-data"]
        logger.info(f"importing {target} from {path}")
        for e in target:
            import_vol(path, e)

        self.start(True)
        time.sleep(30)
