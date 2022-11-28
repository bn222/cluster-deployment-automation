from ailib import AssistedClient
from ailib import boot_hosts as ai_boot_hosts
import socket
from tenacity import retry
import paramiko
import subprocess
from collections import namedtuple
import io

class LocalHost():
  def __init__(self):
    pass

  def run(self, cmd):
    if not isinstance(cmd, list):
       cmd = cmd.split()
    Result = namedtuple("Result", "out err")
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
      return Result(proc.stdout.read().decode("utf-8"), proc.stderr.read().decode("utf-8"))

class RemoteHost():
  def __init__(self, hostname):
    self._hostname = hostname

  def ssh_connect(self, username, id_rsa_path = None):
    self._host = paramiko.SSHClient()
    self._host.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if id_rsa_path is None:
      id_rsa_path = "/root/.ssh/id_rsa"
    with open(id_rsa_path, "r") as f:
      id_rsa = f.read().strip()
    self._pkey = paramiko.RSAKey.from_private_key(io.StringIO(id_rsa))
    self.ssh_connect_looped(username)

  @retry
  def ssh_connect_looped(self, username):
    print(f"trying to connect to {self._hostname}")
    try:
      self._host.connect(self._hostname, username=username, pkey=self._pkey)
    except Exception as e:
      print(e)
      raise e
    print(f"connected to {self._hostname}")

  def run(self, cmd):
    stdin, stdout, stderr = self._host.exec_command(cmd)
    ret = []
    for line in iter(stdout.readline, ""):
      print(f"{self._hostname}: {line.strip()}")
      ret += [line.strip()]
    return ret

  def close(self):
    self._host.close()

  def _bmc_url(self):
      ip = socket.gethostbyname(self._hostname)
      octets = ip.split(".")
      octets[-1] = str(int(octets[-1]) + 1)
      return ".".join(octets)

  def boot_iso_redfish(self, iso_path, bmc_user, bmc_password):
    url = "0.0.0.0"
    ai = AssistedClient(url + ":8090")

    overrides = {}
    overrides['iso_url'] = iso_path
    overrides['bmc_user'] = bmc_user
    overrides['bmc_password'] = bmc_password
    overrides['hosts'] = [{}]
    overrides['hosts'][0]['model'] = "dell"
    overrides["hosts"][0]["bmc_url"] = self._bmc_url()

    ai_boot_hosts(overrides)

class RemoteHostWithBF2(RemoteHost):
  def prep_container(self):
    self._container_name = "bf"
    quay = "quay.io/bnemeth/bf"
    print("starting container")
    cmd = f"sudo podman run --pid host --network host --user 0 --name {self._container_name} -dit --privileged -v /:/host -v /dev:/dev {quay}"
    self.run(cmd)

  def bf_pxeboot(self, iso_name, nfs_server):
    self.prep_container()
    print("mounting nfs inside container")
    cmd = f"sudo killall python3"
    self.run(cmd)
    print("starting pxe server and booting bf")
    cmd = f"sudo podman exec -it {self._container_name} /pxeboot {nfs_server}:/root/iso/{iso_name} {nfs_server}:/root/iso/id_rsa"
    return self.run(cmd)

  def bf_firmware_upgrade(self):
    self.prep_container()
    cmd = f"sudo podman exec {self._container_name} /fwup"
    self.run(cmd)

  def bf_set_nic_mode(self):
    self.prep_container()
    cmd = f"sudo podman exec {self._container_name} /nicmode"

  def bf_firmware_version(self):
    self.prep_container()
    cmd = f"sudo podman exec {self._container_name} /fwversion"
