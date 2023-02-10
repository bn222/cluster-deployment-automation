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

    def run(self, cmd: str, env: dict = os.environ.copy()) -> Result:
        args = shlex.split(cmd)
        pipe = subprocess.PIPE
        with subprocess.Popen(args, stdout=pipe, stderr=pipe, env=env) as proc:
            out = proc.stdout.read().decode("utf-8")
            err = proc.stderr.read().decode("utf-8")
            proc.communicate()
            ret = proc.returncode
        return Result(out, err, ret)

    def write(self, fn, contents):
        with open(fn, "w") as f:
            f.write(contents)

    def ipa(self) -> dict:
        return json.loads(self.run("ip -json a").out)


class RemoteHost():
    def __init__(self, hostname: str, bmc_user: str=None, bmc_password: str=None):
        self._hostname = hostname
        self._bmc_user = bmc_user
        self._bmc_password = bmc_password
        self.auto_reconnect = False

    def enable_autoreconnect(self) -> None:
        self.auto_reconnect = True

    def ssh_connect(self, username: str, id_rsa_path: str=None) -> None:
        if id_rsa_path is None:
            id_rsa_path = "/root/.ssh/id_rsa"
        with open(id_rsa_path, "r") as f:
            self._id_rsa = f.read().strip()
        print(f"waiting for {self._hostname} to respond to ping")
        self.wait_ping()
        print(f"{self._hostname} responded to ping, trying to connect")
        self.ssh_connect_looped(username)

    def ssh_connect_looped(self, username: str) -> None:
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

    def _read_output(self, cmd: str) -> Result:
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

    def run(self, cmd: str) -> Result:
        print(cmd)
        if not self.auto_reconnect:
            return self._read_output(cmd)
        else:
            while True:
                try:
                    print(f"running command {cmd}")
                    ret = self._read_output(cmd)
                    print(f"Finished running command {cmd}")
                    return ret
                except Exception as e:
                    print(e)
                    print("Connection lost while running command, trying to reconnect")
                    self.ssh_connect_looped(self._username)

    def close(self) -> None:
        self._host.close()

    def _bmc_url(self) -> str:
        ip = socket.gethostbyname(self._hostname)
        octets = ip.split(".")
        octets[-1] = str(int(octets[-1]) + 1)
        return ".".join(octets)

    def boot_iso_redfish(self, iso_path: str) -> None:
        self._boot_with_overrides(iso_path)

    """
    Red Fish is used to boot ISO images with virtual media.
    Make sure redfish is enabled on your server. You can verify this by
    visiting the BMC's web address:
      https://<ip>/redfish/v1/Systems/System.Embedded.1 (For Dell)
    Red Fish uses HTTP POST messages to trigger actions. Some requires
    data. However the Red Fish library takes care of this for you.

    Red Fish heavily depends on iDRAC and IPMI working. For Dell servers:
    Log into iDRAC, default user is "root" and default password is "calvin".
     1) Try rebooting iDRAC
      a) Go to "Maintenance" tab at the top
      b) Go to the "Diagnostics" sub-tab below the "Maintenance" panel.
      c) Press the "Reboot iDRAC"
      d) Wait a while for iDRAC to come up.
      e) Once the web interface is available, go back to the "Dashboard" tab.
      f) Monitor the system to post after the "Dell" blue screen.
     2) Try upgrading firmware
      a) Go to "Maintenance" tab at the top
      b) Go to the "System Update" sub-tab below the "Maintenance" panel.
      c) Change the "Location Type" to "HTTP"
      d) Under the "HTTP Server Settings", set the "HTTP Address" to be "downloads.dell.com".
      e) Click "Check for Update".
      f) Depending on the missing updates, select what is needed then press "Install and Reboot"
      g) Wait a while for iDRAC to come up.
      h) Once the web interface is available, go back to the "Dashboard" tab.
      i) Monitor the system to post after the "Dell" blue screen.

    """
    @retry(stop=stop_after_attempt(10), wait=wait_fixed(60))
    def _boot_with_overrides(self, iso_path: str) -> None:
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

    def stop(self) -> None:
        red = self._redfish()
        red.stop()

    def start(self) -> None:
        red = self._redfish()
        red.start()

    def cold_boot(self) -> None:
        self.stop()
        time.sleep(10)
        self.start()
        time.sleep(5)

    def _redfish(self) -> Redfish:
        return Redfish(self._bmc_url(), self._bmc_user, self._bmc_password, model='dell', debug=False)

    def wait_ping(self) -> None:
        while not self.ping():
            pass

    def ping(self) -> bool:
        lh = LocalHost()
        ping_cmd = f"timeout 1 ping -4 -c 1 {self._hostname}"
        r = lh.run(ping_cmd)
        return r.returncode == 0

    def os_release(self) -> dict:
        d = {}
        for e in self.run("cat /etc/os-release").out:
            k, v = e.split("=")
            v = v.strip("\"'")
            d[k] = v
        return d


class RemoteHostWithBF2(RemoteHost):
    def prep_container(self) -> None:
        self._container_name = "bfb"
        print("starting container")
        cmd = f"sudo podman run --pull always --replace --pid host --network host --user 0 --name {self._container_name} -dit --privileged -v /dev:/dev quay.io/bnemeth/bf"
        self.run(cmd)

    def bf_pxeboot(self, iso_name: str, nfs_server: str) -> Result:
        self.prep_container()
        print("mounting nfs inside container")
        cmd = "sudo killall python3"
        self.run(cmd)
        print("starting pxe server and booting bf")
        cmd = f"sudo podman exec -it {self._container_name} /pxeboot {nfs_server}:/root/iso/{iso_name} -w {nfs_server}:/root/iso/id_rsa"
        return self.run(cmd)

    def bf_firmware_upgrade(self) -> None:
        self.prep_container()
        cmd = f"sudo podman exec {self._container_name} /fwup"
        self.run(cmd)

    def bf_firmware_defaults(self) -> None:
        self.prep_container()
        cmd = f"sudo podman exec {self._container_name} /fwdefaults"
        self.run(cmd)

    def bf_set_mode(self, mode: str) -> None:
        self.prep_container()
        cmd = f"sudo podman exec {self._container_name} /set_mode {mode}"
        self.run(cmd)

    def bf_get_mode(self) -> None:
        self.prep_container()
        cmd = f"sudo podman exec {self._container_name} /get_mode"
        self.run(cmd)

    def bf_firmware_version(self) -> None:
        self.prep_container()
        cmd = f"sudo podman exec {self._container_name} /fwversion"
        self.run(cmd)

    def bf_load_bfb(self) -> None:
        self.prep_container()
        cmd = f"sudo podman exec {self._container_name} /bfb"
        self.run(cmd)
