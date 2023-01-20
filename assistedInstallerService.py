import subprocess
from collections import namedtuple
from requests import get as get_url
import os, sys
from shutil import rmtree as rmdir
import yaml
import json
import time

def run(cmd):
  if not isinstance(cmd, list):
    cmd = cmd.split()
  Result = namedtuple("Result", "out err")
  with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
    return Result(proc.stdout.read().decode("utf-8"), proc.stderr.read().decode("utf-8"))

class AssistedInstallerService():
  def __init__(self, ip, branch = "master"):
    self._ip = ip
    base_url = f"https://raw.githubusercontent.com/openshift/assisted-service/{branch}"
    self.podConfig = get_url(f"{base_url}/deploy/podman/configmap.yml").text
    self.podFile = get_url(f"{base_url}/deploy/podman/pod.yml").text
    self.workdir = os.path.join(os.getcwd(), "build")

  def _configure(self) -> None:
    print("creating working dirctory")
    if  os.path.exists(self.workdir):
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
    y["data"]["RELEASE_IMAGES"] = json.dumps(j)

    with open(f'{self.workdir}/configmap.yml', 'w') as out_configmap:
      yaml.dump(y, out_configmap, sort_keys=False)

    with open(f'{self.workdir}/pod.yml', 'w') as out_pod:
      yaml.dump(yaml.safe_load(self.podFile), out_pod, default_flow_style=False)

  def _start_pod(self, force) -> None:
    result = run("podman pod ps")
    if result.err:
      print("Error {result.err}")
      exit(1)

    ai = list(filter(lambda x: "assisted-installer" in x, result.out.split("\n")[1:]))
    skip_start = False
    if len(ai) > 1:
      print("too many assisted-installer pods")
      skip_start = True
    elif len(ai) == 1:
      if force:
        print("Stopping assisted-installer")
        hash = ai[0].split()[0]
        run(f"podman pod stop {hash}")
        run(f"podman pod rm {hash}")
      else:
        print("Assisted already running")
        skip_start = True
    else:
      print("assisted-installer is not running")
    if not skip_start:
      run(f"podman play kube --configmap {self.workdir}/configmap.yml {self.workdir}/pod.yml")

  def waitForAPI(self) -> None:
    print("Waiting for API to be ready...")
    response, count = 0 ,0
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

  def start(self, force = False) -> None:
    self._configure()
    self._start_pod(force)
    self.waitForAPI()
