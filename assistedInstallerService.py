from requests import get as get_url
import os
from shutil import rmtree as rmdir
import yaml
import json
import time
import requests
import host
import sys
import re
from logger import logger


def load_url_or_file(url_or_file: str):
    if url_or_file.startswith("http"):
        return get_url(url_or_file).text
    else:
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
class AssistedInstallerService():
    def __init__(self, ip: str, branch: str = "master"):
        self._ip = ip
        base_url = f"https://raw.githubusercontent.com/openshift/assisted-service/{branch}"
        pod_config_url = f"{base_url}/deploy/podman/configmap.yml"
        pod_file = f"{base_url}/deploy/podman/pod-persistent.yml"
        self.podConfig = load_url_or_file(pod_config_url)
        self.podFile = load_url_or_file(pod_file)
        self.workdir = os.path.join(os.getcwd(), "build")

    def _configure(self, version) -> None:
        logger.info("creating working directory")
        if os.path.exists(self.workdir):
            rmdir(self.workdir)
        os.mkdir(self.workdir)
        with open(self._config_map_path(), 'w') as out_configmap:
            yaml.dump(self._customized_configmap(version), out_configmap, sort_keys=False)

        with open(self._pod_persistent_path(), 'w') as out_pod:
            yaml.dump(self._customized_pod_persistent(), out_pod, default_flow_style=False)

    def _config_map_path(self) -> str:
        return f'{self.workdir}/configmap.yml'

    def _pod_persistent_path(self) -> str:
        return f'{self.workdir}/pod-persistent.yml'

    def _customized_configmap(self, version):
        y = yaml.safe_load(self.podConfig)
        y["data"]["IMAGE_SERVICE_BASE_URL"] = f"http://{self._ip}:8888"
        y["data"]["SERVICE_BASE_URL"] = f"http://{self._ip}:8090"
        # https://gitlab.cee.redhat.com/service/app-interface/-/blob/dc9614663fc64bb5aad2c11c8c24d731f1dfa7e4/data/services/assisted-installer/cicd/target/production/assisted-service.yaml#L46-48
        y["data"]["INSTALLER_IMAGE"] = f"registry.redhat.io/rhai-tech-preview/assisted-installer-rhel8:v1.0.0-269"
        y["data"]["CONTROLLER_IMAGE"] = f"registry.redhat.io/rhai-tech-preview/assisted-installer-reporter-rhel8:v1.0.0-340"
        y["data"]["AGENT_DOCKER_IMAGE"] = f"registry.redhat.io/rhai-tech-preview/assisted-installer-agent-rhel8:v1.0.0-257"

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
        y["data"]["RELEASE_IMAGES"] = json.dumps([self.prep_version(version)])
        return y

    def _customized_pod_persistent(self) -> str:
        y = yaml.safe_load(self.podFile)

        saas_version = "v2.18.4"

        containers = y['spec']['containers']
        for container in containers:
            image = container.get('image', '')
            if image.startswith('quay.io/edge-infrastructure/assisted'):
                container['image'] = image.replace(':latest', f':{saas_version}')
        
        return y

    def prep_version(self, version):
        if re.search(r'4\.12\.[0-9]+-multi', version):
            # Note how 4.12.0 has the -multi suffix because AI requires that
            # for 4.12. CDA hides this and simply expect 4.12.0 from the user
            # since that follows the same versioning scheme
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
        elif re.search(r'4\.14\.0-nightly', version):
            # workaround: if openshift_version == 4.14-multi, and
            # version == "4.14.0" nightly, it errors out. Instead
            # pretend that we are installing 4.13, but use the 4.14
            # pullspec
            wa_version = "4.13.0-nighty"

            ret = {
              'openshift_version': '4.13-multi',
              'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
              'url': self.get_nightly_pullspec(version),
              'version': wa_version,
            }
        else:
            logger.info(f"Unknown version {version}")
            sys.exit(-1)
        ret["cpu_architecture"] = "multi"
        if "ec" in version or "nightly" in version:
            ret["support_level"] = "beta"
        ret["cpu_architectures"] = ['x86_64', 'arm64', 'ppc64le', 's390x']
        return ret

    def get_nightly_pullspec(self, version) -> str:
        version = version.rstrip("-nightly")
        url = f'https://multi.ocp.releases.ci.openshift.org/api/v1/releasestream/{version}-0.nightly-multi/latest'
        response = requests.get(url)
        j = json.loads(response.content)
        return j["pullSpec"]

    def get_normal_pullspec(self, version) -> str:
        return f"quay.io/openshift-release-dev/ocp-release:{version}-multi"

    def _ensure_pod_started(self) -> None:
        lh = host.LocalHost()
        result = lh.run("podman pod ps --format json")
        if result.err:
            logger.info("Error {result.err}")
            exit(1)
        name = "assisted-installer"
        if name in map(lambda x: x["Name"], json.loads(result.out)):
            logger.info(f"{name} already running, stopping it before restarting")
            lh.run(f"podman pod stop {name}")
            lh.run(f"podman pod rm {name}")
        else:
            logger.info(f"{name} not yet running")
        r = lh.run(f"podman play kube --configmap {self._config_map_path()} {self._pod_persistent_path()}")
        if r.returncode != 0:
            logger.info(r)
            sys.exit(-1)

    def wait_for_api(self) -> None:
        lh = host.LocalHost()
        virbr0_present= list(filter(lambda x: x["ifname"] == "virbr0", lh.all_ports()))

        if not virbr0_present:
            logger.info("Can't find virbr0. Make sure that libvirtd is running.")
            sys.exit(-1)

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
                exit(1)
            count += 1
            time.sleep(2)

    def start(self, version) -> None:
        self._configure(version)
        self._ensure_pod_started()
        self.wait_for_api()
