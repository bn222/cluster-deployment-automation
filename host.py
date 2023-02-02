from ailib import AssistedClient
from ailib import boot_hosts as ai_boot_hosts
from ailib import Redfish
import socket
from tenacity import retry, stop_after_attempt, wait_fixed
import paramiko
import subprocess
from collections import namedtuple
import io
import os
import time
import json
import shlex

Result = namedtuple("Result", "out err returncode")

class LocalHost():
  def __init__(self):
    pass

  def run(self, cmd, env = None):
    if not isinstance(cmd, list):
       cmd = shlex.split(cmd)
    if env is None:
      env = os.environ.copy()
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env) as proc:
      out = proc.stdout.read().decode("utf-8")
      err = proc.stderr.read().decode("utf-8")
      proc.communicate()
      ret = proc.returncode
    return Result(out, err, ret)

  def write(self, fn, contents):
    with open(fn, "w") as f:
      f.write(contents)

  def ipa(self):
      return json.loads(self.run("ip -json a").out)

class RemoteHost():
  def __init__(self, hostname, bmc_user = None, bmc_password = None):
    self._hostname = hostname
    self._bmc_user = bmc_user
    self._bmc_password = bmc_password
    self.auto_reconnect = False

  def enable_autoreconnect(self):
    self.auto_reconnect = True

  def ssh_connect(self, username, id_rsa_path = None):
    if id_rsa_path is None:
      id_rsa_path = "/root/.ssh/id_rsa"
    with open(id_rsa_path, "r") as f:
      self._id_rsa = f.read().strip()
    print(f"waiting for {self._hostname} to respond to ping")
    self.wait_ping()
    print(f"{self._hostname} responded to ping, trying to connect")
    self.ssh_connect_looped(username)

  def ssh_connect_looped(self, username):
    while True:
      self._username = username
      self._host = paramiko.SSHClient()
      self._host.set_missing_host_key_policy(paramiko.AutoAddPolicy())
      self._pkey = paramiko.RSAKey.from_private_key(io.StringIO(self._id_rsa))

      try:
        self._host.connect(self._hostname, username=username, pkey=self._pkey)
      except paramiko.ssh_exception.AuthenticationException as e:
        print(type(e))
        raise e
      except Exception as e:
        print(type(e))
        continue
      print(f"connected to {self._hostname}")
      break

  def _read_output(self, cmd):
    ret = []
    _, stdout, _ = self._host.exec_command(cmd)
    for line in iter(stdout.readline, ""):
      print(f"{self._hostname}: {line.strip()}")
      ret += [line.strip()]

    return ret

  def _read_output2(self, cmd):
    _, stdout, stderr = self._host.exec_command(cmd)

    out = []
    for line in iter(stdout.readline, ""):
      print(f"{self._hostname}: {line.strip()}")
      out += line

    err = []
    for line in iter(stderr.readline, ""):
      err += line

    exit_code = stdout.channel.recv_exit_status()
    out = "".join(out)
    err = "".join(err)

    return Result(out, err, exit_code)

  def run(self, cmd):
    print("warning: using old run, use run2 instead")
    print(cmd)
    if not self.auto_reconnect:
      return self._read_output(cmd)
    else:
      while True:
        try:
          print("running command", cmd)
          return self._read_output(cmd)
        except Exception as e:
          print(e)
          print("Connection lost while running command, trying to reconnect")
          self.ssh_connect_looped(self._username)

  def run2(self, cmd):
    print("warning: using old run, use run2 instead")
    print(cmd)
    if not self.auto_reconnect:
      return self._read_output2(cmd)
    else:
      while True:
        try:
          print("running command", cmd)
          return self._read_output2(cmd)
        except Exception as e:
          print(e)
          print("Connection lost while running command, trying to reconnect")
          self.ssh_connect_looped(self._username)

  def close(self):
    self._host.close()

  def _bmc_url(self):
      ip = socket.gethostbyname(self._hostname)
      octets = ip.split(".")
      octets[-1] = str(int(octets[-1]) + 1)
      return ".".join(octets)

  def boot_iso_redfish(self, iso_path):
    self._boot_with_overrides(iso_path)

  """
  Red Fish is used to boot ISO images with virtual media.
  Make sure redfish is enabled on your server. You can verify this by
  visiting the BMC's web address:
    https://<ip>/redfish/v1/Systems/System.Embedded.1 (For Dell)
  Red Fish uses HTTP POST messages to trigger actions. Some requires
  data. However the Red Fish library takes care of this for you.
  """
  @retry(stop=stop_after_attempt(10), wait=wait_fixed(10))
  def _boot_with_overrides(self, iso_path):
    print(f"Trying to boot {self._bmc_url()}")
    red = self._redfish()
    try:
      red.eject_iso()
    except Exception as e:
      print(e)
      print("eject failed, but continuing")
      pass
    red.insert_iso(iso_path)
    print(f"inserted iso {iso_path}")
    try:
      red.set_iso_once()
    except Exception as e:
      print(e)
      raise e

    print("setting to boot from iso")
    red.restart()
    time.sleep(10)
    print(f"Finished sending boot to {self._bmc_url()}")

  def stop(self):
    red = self._redfish()
    red.stop()

  def start(self):
    red = self._redfish()
    red.start()

  def cold_boot(self):
    self.stop()
    time.sleep(10)
    self.start()
    time.sleep(5)

  def _redfish(self):
    return Redfish(self._bmc_url(), self._bmc_user, self._bmc_password, model='dell', debug=False)

  def wait_ping(self):
    while not self.ping():
      pass

  def ping(self):
    lh = LocalHost()
    ping_cmd = f"timeout 1 ping -4 -c 1 {self._hostname}"
    r = lh.run(ping_cmd)
    return r.returncode == 0

  def os_release(self):
    d = {}
    for e in self.run("cat /etc/os-release"):
      k, v = e.split("=")
      v = v.strip("\"'")
      d[k] = v
    return d

class RemoteHostWithBF2(RemoteHost):
  def prep_container(self):
    self._container_name = "bfb"
    print("starting container")
    cmd = f"sudo podman run --pull always --replace --pid host --network host --user 0 --name {self._container_name} -dit --privileged -v /dev:/dev quay.io/bnemeth/bf"
    self.run2(cmd)

  def bf_pxeboot(self, iso_name, nfs_server):
    self.prep_container()
    print("mounting nfs inside container")
    cmd = f"sudo killall python3"
    self.run2(cmd)
    print("starting pxe server and booting bf")
    cmd = f"sudo podman exec -it {self._container_name} /pxeboot {nfs_server}:/root/iso/{iso_name} -w {nfs_server}:/root/iso/id_rsa"
    return self.run2(cmd)

  def bf_firmware_upgrade(self):
    self.prep_container()
    cmd = f"sudo podman exec {self._container_name} /fwup"
    self.run2(cmd)

  def bf_firmware_defaults(self):
    self.prep_container()
    cmd = f"sudo podman exec {self._container_name} /fwdefaults"
    self.run2(cmd)

  def bf_set_mode(self, mode):
    self.prep_container()
    cmd = f"sudo podman exec {self._container_name} /set_mode {mode}"
    self.run2(cmd)

  def bf_get_mode(self):
    self.prep_container()
    cmd = f"sudo podman exec {self._container_name} /get_mode"
    self.run2(cmd)

  def bf_firmware_version(self):
    self.prep_container()
    cmd = f"sudo podman exec {self._container_name} /fwversion"
    self.run2(cmd)

  def bf_load_bfb(self):
    self.prep_container()
    cmd = f"sudo podman exec {self._container_name} /bfb"
    self.run2(cmd)
