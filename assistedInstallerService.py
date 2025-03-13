import json
import time
import sys
import re
from typing import Optional
from typing import Union
from typing import Sequence
from typing import Any
from typing import IO
import yaml
import requests
from requests import get as get_url
from logger import logger
import host
import common
from libvirt import Libvirt
import tempfile
import hashlib
import copy


def load_url_or_file(url_or_file: str) -> str:
    if url_or_file.startswith("http"):
        return get_url(url_or_file).text
    return open(url_or_file).read()


def hash_string(input_string: str) -> str:
    md5_hash = hashlib.md5()
    md5_hash.update(input_string.encode('utf-8'))
    return md5_hash.hexdigest()


def tmp_file() -> IO[str]:
    return tempfile.NamedTemporaryFile(delete=True, mode='w+')


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
    SAAS_VERSION = "latest"
    INSTALLER_IMAGE = "registry.redhat.io/rhai-tech-preview/assisted-installer-rhel8:v1.0.0-347"
    CONTROLLER_IMAGE = "registry.redhat.io/rhai-tech-preview/assisted-installer-reporter-rhel8:v1.0.0-425"
    AGENT_DOCKER_IMAGE = "registry.redhat.io/rhai-tech-preview/assisted-installer-agent-rhel8:v1.0.0-328"

    def __init__(self, version: str, ip: str, resume_deployment: bool = False, proxy: Optional[str] = None, noproxy: Optional[str] = None, branch: str = "master"):
        self._version = version
        self._ip = ip
        self._proxy = proxy
        self._noproxy = noproxy
        self._resume_deployment = resume_deployment
        base_url = f"https://raw.githubusercontent.com/openshift/assisted-service/{branch}"
        pod_config_url = f"{base_url}/deploy/podman/configmap.yml"
        pod_file = f"{base_url}/deploy/podman/pod-persistent.yml"
        self.podConfig = load_url_or_file(pod_config_url)
        self.podFile = load_url_or_file(pod_file)

    def _add_hash_labels(self, pod: dict[str, Any], cm: dict[str, Any]) -> dict[str, Any]:
        ret = copy.deepcopy(pod)
        ret['metadata']['labels'] = {
            'cda-pod/hash': hash_string(yaml.dump(pod)),
            'cda-cm/hash': hash_string(yaml.dump(cm)),
        }
        return ret

    def _strip_unused_versions(self, versions: str) -> str:
        def major_minor(v: str) -> str:
            x = re.match(r"(\d+\.\d+)", v)
            if x is None:
                logger.error(f"Can't extract version {x}")
                sys.exit(-1)
            return x.group(1)

        j = json.loads(versions)
        keep = [e for e in j if major_minor(self._version) == e['openshift_version']]
        return json.dumps(keep)

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
        y["data"]["OS_IMAGES"] = self._strip_unused_versions(y["data"]["OS_IMAGES"])

        # We need this temporary workaround because as of 2/25 the iso name in https://mirror.openshift.com/pub/openshift-v4/x86_64/dependencies/rhcos/pre-release/dev-4.19/
        # no longer matches the iso expected by assisted installer service https://github.com/openshift/assisted-service/blob/master/deploy/podman/configmap.yml#L25

        # Update: The configmap now properly points to the new image, however the new image fails to run bootkube.sh when starting, pin it for now to a local image.
        broken_iso_url = "https://mirror.openshift.com/pub/openshift-v4/x86_64/dependencies/rhcos/pre-release/4.19.0-ec.3/rhcos-4.19.0-ec.3-x86_64-live-iso.x86_64.iso"
        new_iso_url = "http://wsfd-advnetlab-amp04.anl.eng.bos2.dc.redhat.com/rhcos-full-iso-4.19-418.94.202410090804-0-x86_64.iso"

        if broken_iso_url in y["data"]["OS_IMAGES"]:
            logger.info(f"coreos iso {broken_iso_url} does not work, will try to install with {new_iso_url}")
            y["data"]["OS_IMAGES"] = y["data"]["OS_IMAGES"].replace(broken_iso_url, new_iso_url)

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

    def _customized_pod_persistent(self) -> dict[str, Any]:
        y = yaml.safe_load(self.podFile)
        if not isinstance(y, dict):
            logger.error(f"Failed to load yaml: {self.podFile}")
            sys.exit(-1)

        containers = y['spec']['containers']
        for container in containers:
            image = container.get('image', '')
            if image.startswith('quay.io/edge-infrastructure/assisted'):
                container['image'] = image.replace(':latest', f':{AssistedInstallerService.SAAS_VERSION}')
                container['securityContext'] = {"runAsUser": 0}
        return y

    def prep_version(self, version: str) -> dict[str, Union[str, Sequence[str]]]:
        # Latest available Openshift Release versions can be found here: https://quay.io/repository/openshift-release-dev/ocp-release

        # Note how 4.12.0 has the -multi suffix because AI requires that
        # for 4.12. CDA hides this and simply expect 4.12.0 from the user
        # since that follows the same versioning scheme
        if re.search(r'4\.12\.0-ec.[0-9]+', version):
            ret = {
                'openshift_version': '4.12-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_normal_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.12\.0-nightly', version):
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
            ret = {
                'openshift_version': '4.14-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_normal_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.14\.0-nightly', version):
            ret = {
                'openshift_version': '4.14-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_nightly_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.14\.[0-9]+', version):
            ret = {
                'openshift_version': '4.14-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_normal_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.15\.0-ec.[0-9]+', version):
            ret = {
                'openshift_version': '4.15-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_normal_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.15\.0-nightly', version):
            ret = {
                'openshift_version': '4.15-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_nightly_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.15\.[0-9]+', version):
            ret = {
                'openshift_version': '4.15-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_normal_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.16\.0-ec.[0-9]+', version):
            ret = {
                'openshift_version': '4.16-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_normal_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.16\.0-nightly', version):
            ret = {
                'openshift_version': '4.16-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_nightly_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.16\.[0-9]+', version):
            ret = {
                'openshift_version': '4.16-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_normal_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.17\.0-ec.[0-9]+', version):
            ret = {
                'openshift_version': '4.17-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_normal_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.17\.0-nightly', version):
            ret = {
                'openshift_version': '4.17-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_nightly_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.17\.[0-9]+', version):
            ret = {
                'openshift_version': '4.17-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_normal_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.18\.0-ec.[0-9]+', version):
            ret = {
                'openshift_version': '4.18-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_normal_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.18\.0-nightly', version):
            ret = {
                'openshift_version': '4.18-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_nightly_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.18\.[0-9]+', version):
            ret = {
                'openshift_version': '4.18-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_normal_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.19\.0-ec.[0-9]+', version):
            ret = {
                'openshift_version': '4.19-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_normal_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.19\.0-nightly', version):
            ret = {
                'openshift_version': '4.19-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_nightly_pullspec(version),
                'version': version,
            }
        elif re.search(r'4\.19\.[0-9]+', version):
            ret = {
                'openshift_version': '4.19-multi',
                'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
                'url': self.get_normal_pullspec(version),
                'version': version,
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

    def stop_needed(self, pod: dict[str, Any], cm: dict[str, Any], force: bool) -> bool:
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

        lh = host.LocalHost()
        j = json.loads(lh.run("podman inspect assisted-installer").out)
        if "Labels" not in j[0]:
            logger.warn(f"{name} running without label, stop needed")
            return True
        labels = j[0]["Labels"]

        # ignore differences in config in case deployment is resumed since a
        # restart of ai would cause the existing partial deployment to be wiped
        if self._resume_deployment:
            return False

        if "cda-pod/hash" not in labels:
            logger.warn(f"{name} running without label cda-pod/hash, stop needed")
            return True
        logger.debug(yaml.dump(pod))
        pod_hash = hash_string(yaml.dump(pod))
        if labels["cda-pod/hash"] != pod_hash:
            logger.info(f"{name} pod running with different pod hash")
            logger.info(f"New configmap hashmap is {pod_hash}")
            logger.info(f"Old configmap hashmap is {labels['cda-pod/hash']}")
            return True

        if "cda-cm/hash" not in labels:
            logger.warn(f"{name} running without label cda-cm/hash, stop needed")
            return True
        logger.debug(yaml.dump(cm))
        cm_hash = hash_string(yaml.dump(cm))
        if labels["cda-cm/hash"] != cm_hash:
            logger.info(f"{name} pod running with different configmap hash")
            logger.info(f"New configmap hashmap is {cm_hash}")
            logger.info(f"Old configmap hashmap is {labels['cda-cm/hash']}")
            return True
        logger.info(f"{name} already running with the same pod and configmap")
        return False

    def _ensure_pod_started(self, force: bool) -> None:
        cm = self._customized_configmap()
        pod = self._customized_pod_persistent()
        pod_labeled = self._add_hash_labels(pod, cm)

        if self.stop_needed(pod, cm, force):
            self.stop()

        if not self.pod_running():
            logger.info("Starting assisted-installer.")
            self._play_kube(pod_labeled, cm)

    def _play_kube(self, pod: dict[str, Any], cm: dict[str, Any]) -> host.Result:
        with tmp_file() as pod_file, tmp_file() as cm_file:
            pod_file.write(json.dumps(pod))
            pod_file.flush()
            cm_file.write(json.dumps(cm))
            cm_file.flush()
            lh = host.LocalHost()
            r = lh.run_or_die(f"podman play kube --configmap {cm_file.name} {pod_file.name}")
        return r

    def _ensure_libvirt_running(self) -> None:
        lh = host.LocalHost()
        if not common.ip_links(lh, ifname="virbr0"):
            logger.info("Can't find virbr0. Trying to restart libvirt.")
            libvirt = Libvirt(lh)
            libvirt.configure()
            cmd = "virsh net-start default"
            lh.run(cmd)

            # Not sure whether or why this is needed. But we've seen failures w/o this.
            # Need to find out if/how we can remove this to speed up.
            time.sleep(5)

        if not common.ip_links(lh, ifname="virbr0"):
            logger.error_and_exit("Can't find virbr0. Make sure that libvirt is running.")

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

        lh = host.LocalHost()

        with tmp_file() as pod_file:
            file_contents = self._customized_pod_persistent()
            yaml.dump(file_contents, pod_file, default_flow_style=False)
            pod_file.flush()
            ret = lh.run(f"podman kube down --force {pod_file.name}")

        if ret.returncode:
            # Older podman may not support 'down' or '--force'.
            if any(x in ret.err for x in ['unrecognized', 'unknown']):
                logger.warning("podman kube down --force is not supported. Persistent volumes will remain.")
                ret = lh.run(f"podman pod rm -f {name}")

        if ret.returncode:
            logger.error(f"Failed to teardown {name}: {ret.err}")
        lh.run("podman volume rm ai-db-data")
        lh.run("podman volume rm ai-service-data")

    def start(self, force: bool = False) -> None:
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
