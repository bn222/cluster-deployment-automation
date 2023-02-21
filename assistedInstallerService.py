from requests import get as get_url
import os
from shutil import rmtree as rmdir
import yaml
import json
import time
import requests
import host

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
    def __init__(self, ip: str, branch: str="master"):
        self._ip = ip
        base_url = f"https://raw.githubusercontent.com/openshift/assisted-service/{branch}"
        self.podConfig = get_url(f"{base_url}/deploy/podman/configmap.yml").text
        self.podFile = get_url(f"{base_url}/deploy/podman/pod-persistent.yml").text
        self.workdir = os.path.join(os.getcwd(), "build")

    def _configure(self) -> None:
        print("creating working directory")
        if os.path.exists(self.workdir):
            rmdir(self.workdir)
        os.mkdir(self.workdir)
        with open(self._config_map_path(), 'w') as out_configmap:
            yaml.dump(self._customized_configmap(), out_configmap, sort_keys=False)

        with open(self._pod_persistent_path(), 'w') as out_pod:
            yaml.dump(yaml.safe_load(self.podFile), out_pod, default_flow_style=False)

    def _config_map_path(self) -> str:
        return f'{self.workdir}/configmap.yml'

    def _pod_persistent_path(self) -> str:
        return f'{self.workdir}/pod-persistent.yml'

    def _customized_configmap(self):
        y = yaml.safe_load(self.podConfig)
        y["data"]["IMAGE_SERVICE_BASE_URL"] = f"http://{self._ip}:8888"
        y["data"]["SERVICE_BASE_URL"] = f"http://{self._ip}:8090"
        y["data"]["AGENT_DOCKER_IMAGE"] = "registry.redhat.io/rhai-tech-preview/assisted-installer-agent-rhel8:latest"
        y["data"]["CONTROLLER_IMAGE"] = "registry.redhat.io/rhai-tech-preview/assisted-installer-reporter-rhel8:latest"
        y["data"]["INSTALLER_IMAGE"] = "registry.redhat.io/rhai-tech-preview/assisted-installer-rhel8:latest"

        j = json.loads(y["data"]["HW_VALIDATOR_REQUIREMENTS"])
        j[0]["master"]["disk_size_gb"] = 8
        j[0]["worker"]["disk_size_gb"] = 8
        j[0]["sno"]["disk_size_gb"] = 8
        y["data"]["HW_VALIDATOR_REQUIREMENTS"] = json.dumps(j)

        j = json.loads(y["data"]["RELEASE_IMAGES"])

        versions = (("4.11", ""), ("4.12", ""), ("4.13", "-ec.3"),)
        for v in versions:
            if "nightly" in v[1]:
                to_add = self._create_nightly_version(v)
            else:
                to_add = self._create_ec_version(v)
            j.append(to_add)

        y["data"]["RELEASE_IMAGES"] = json.dumps(j)
        return y

    def _create_ec_version(self, v: tuple) -> dict:
        version, ec_version = v
        version_string = f"{version}{ec_version}"
        url = f"quay.io/openshift-release-dev/ocp-release:{version}.0{ec_version}-multi"
        return self._create_json_version(version_string, url)

    def _create_json_version(self, version_string: str, url: str) -> dict:
        return {
            'openshift_version': version_string,
            'cpu_architecture': 'multi',
            'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
            'url': url,
            'version': version_string,
        }

    def _create_nightly_version(self, v: tuple) -> dict:
        version, release_type = v
        version_string = f"{version}{release_type}"
        url = f"https://multi.ocp.releases.ci.openshift.org/api/v1/releasestream/{version}.0-0.{release_type}-multi/latest"
        response = requests.get(url)
        j = json.loads(response.content)
        return self._create_json_version(version_string, j["downloadURL"])

    def _ensure_pod_started(self) -> None:
        lh = host.LocalHost()
        result = lh.run("podman pod ps --format json")
        if result.err:
            print("Error {result.err}")
            exit(1)
        name = "assisted-installer"
        if name in map(lambda x: x["Name"], json.loads(result.out)):
            print(f"{name} already running, stopping it before restarting")
            lh.run(f"podman pod stop {name}")
            lh.run(f"podman pod rm {name}")
        else:
            print(f"{name} not yet running")
        lh.run(f"podman play kube --configmap {self._config_map_path()} {self._pod_persistent_path()}")

    def wait_for_api(self) -> None:
        print("Waiting for API to be ready...")
        response, count = 0, 0
        url = f"http://{self._ip}:8090/api/assisted-install/v2/clusters"
        while response != 200:
            try:
                response = get_url(url).status_code
            except Exception:
                pass
            if count == 10:
                print("Error: API is down")
                exit(1)
            count += 1
            time.sleep(2)

    def start(self) -> None:
        self._configure()
        self._ensure_pod_started()
        self.wait_for_api()
