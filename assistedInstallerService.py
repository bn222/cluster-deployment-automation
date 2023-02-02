from requests import get as get_url
import os
import sys
from shutil import rmtree as rmdir
import yaml
import json
import time
import requests
import host


class AssistedInstallerService():
    def __init__(self, ip, branch="master"):
        self._ip = ip
        base_url = f"https://raw.githubusercontent.com/openshift/assisted-service/{branch}"
        self.podConfig = get_url(f"{base_url}/deploy/podman/configmap.yml").text
        self.podFile = get_url(f"{base_url}/deploy/podman/pod-persistent.yml").text
        self.workdir = os.path.join(os.getcwd(), "build")

    def _configure(self) -> None:
        print("creating working dirctory")
        if os.path.exists(self.workdir):
            rmdir(self.workdir)
        os.mkdir(self.workdir)

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
        to_add = {
          'openshift_version': '4.12.0-multi',
          'cpu_architecture': 'multi',
          'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
          'url': 'quay.io/openshift-release-dev/ocp-release:4.12.0-rc.6-multi',
          'version': '4.12.0-multi'
        }
        j.append(to_add)
        to_add = {
          'openshift_version': '4.11.0-multi',
          'cpu_architecture': 'multi',
          'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
          'url': 'quay.io/openshift-release-dev/ocp-release:4.11.0-multi',
          'version': '4.11.0-multi'
        }
        j.append(to_add)

        versions = (("4.13", "ec.2"),)
        for v in versions:
            if "ec" in v[1]:
                to_add = self._create_ec_version(v)
            elif "nightly" in v[1]:
                to_add = self._create_nightly_version(v)
            else:
                print(f"unsupported version {v[1]}")
                sys.exit(-1)
            j.append(to_add)

        y["data"]["RELEASE_IMAGES"] = json.dumps(j)

        with open(f'{self.workdir}/configmap.yml', 'w') as out_configmap:
            yaml.dump(y, out_configmap, sort_keys=False)

        with open(f'{self.workdir}/pod-persistent.yml', 'w') as out_pod:
            yaml.dump(yaml.safe_load(self.podFile), out_pod, default_flow_style=False)

    def _create_ec_version(self, v):
        version, ec_version = v
        version_string = f"{version}-{ec_version}"
        url = f"quay.io/openshift-release-dev/ocp-release:{version}.0-{ec_version}-multi"
        return self._create_json_version(version_string, url)

    def _create_json_version(self, version_string, url):
        return {
          'openshift_version': version_string,
          'cpu_architecture': 'multi',
          'cpu_architectures': ['x86_64', 'arm64', 'ppc64le', 's390x'],
          'url': url,
          'version': version_string,
        }

    def _create_nightly_version(self, v):
        version, release_type = v
        version_string = f"{version}-{release_type}"
        url = f"https://multi.ocp.releases.ci.openshift.org/api/v1/releasestream/{version}.0-0.{release_type}-multi/latest"
        response = requests.get(url)
        j = json.loads(response.content)
        return self._create_json_version(version_string, j["downloadURL"])

    def _start_pod(self) -> None:
        lh = host.LocalHost()
        result = lh.run("podman pod ps --format json")
        if result.err:
            print("Error {result.err}")
            exit(1)
        name = "assisted-installer"
        for pod in json.loads(result.out):
            if pod["Name"] == name:
                print(lh.run(f"podman pod stop {name}"))
                print(lh.run(f"podman pod rm {name}"))
                break

        cfg_map_path = f"{self.workdir}/configmap.yml"
        pod_path = f"{self.workdir}/pod-persistent.yml"
        print(lh.run(f"podman play kube --configmap {cfg_map_path} {pod_path}"))

    def waitForAPI(self) -> None:
        print("Waiting for API to be ready...")
        response, count = 0, 0
        while response != 200:
            try:
                url = f"http://{self._ip}:8090/api/assisted-install/v2/clusters"
                response = get_url(url).status_code
            except:
                pass
            if count == 10:
                print("Error: API is down")
                exit(1)
            count += 1
            time.sleep(2)

    def start(self) -> None:
        self._configure()
        self._start_pod()
        self.waitForAPI()
