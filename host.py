from ailib import Redfish
import socket
from tenacity import retry, stop_after_attempt, wait_fixed
import paramiko
import logging
import subprocess
from scp import SCPClient
from collections import namedtuple
import io
import os
import re
import time
import json
import shlex
import sys
from typing import Optional
import common
import datetime


Result = namedtuple("Result", "out err returncode")


def sync_time(src, dst):
    date = src.run("date").out.strip()
    return dst.run(f"sudo date -s \"{date}\"")

class Host():
    def vm_is_running(self, name: str) -> bool:
        ret = self.run(f"virsh dominfo {name}")
        return not ret.returncode and re.search("State:.*running", ret.out)

    def ipa(self) -> dict:
        return json.loads(self.run("ip -json a").out)

    def ipr(self) -> dict:
        return json.loads(self.run("ip -json r").out)

    def all_ports(self) -> dict:
        return json.loads(self.run("ip -json link").out)

    def ip(self, port_name: str) -> str:
        return common.extract_ip(self.ipa(), port_name)

    def port_from_route(self, route: str) -> str:
        return common.extract_port(self.ipr(), route)

    def port_exists(self, port_name: str) -> bool:
        return self.run(f"ip link show {port_name}").returncode == 0

    def get_hostname(self) -> str:
        return self._hostname

class LocalHost(Host):
    def __init__(self):
        self._hostname = "localhost"

    def run(self, cmd: str, env: dict = os.environ.copy()) -> Result:
        now = datetime.datetime.now()
        print("\t\t", now.strftime("%Y-%m-%d %H:%M:%S: "), "running ", cmd)
        args = shlex.split(cmd)
        pipe = subprocess.PIPE
        with subprocess.Popen(args, stdout=pipe, stderr=pipe, env=env) as proc:
            if proc.stdout is None:
                print("Can't find stdout")
                sys.exit(-1)
            if proc.stderr is None:
                print("Can't find stderr")
                sys.exit(-1)
            out = proc.stdout.read().decode("utf-8")
            err = proc.stderr.read().decode("utf-8")
            proc.communicate()
            ret = proc.returncode
        return Result(out, err, ret)

    def write(self, fn, contents):
        with open(fn, "w") as f:
            f.write(contents)

    def read_file(self, file_name: str) -> str:
        with open(file_name) as f:
            return f.read()


class RemoteHost(Host):
    def __init__(self, hostname: str, bmc_ip: Optional[str] = None, bmc_user: Optional[str] = None, bmc_password: Optional[str] = None):
        self._hostname = hostname
        self._bmc_ip = bmc_ip
        self._bmc_user = bmc_user
        self._bmc_password = bmc_password
        self.auto_reconnect = False
        logger = paramiko.util.logging.getLogger()
        logger.setLevel(logging.WARN)

    def ssh_connect(self, username: str, password: Optional[str] = None, id_rsa_path: Optional[str] = None,
                    id_ed25519_path: Optional[str] = None) -> None:
        if id_rsa_path is None:
            id_rsa_path = os.path.join(os.environ["HOME"], ".ssh/id_rsa")
        if id_ed25519_path is None:
            id_ed25519_path = os.path.join(os.environ["HOME"], ".ssh/id_ed25519")
        try:
            with open(id_rsa_path, "r") as f:
                self._id_rsa = f.read().strip()
        except FileNotFoundError:
            self._id_rsa = None
        try:
            with open(id_ed25519_path, "r") as f:
                self._id_ed25519 = f.read().strip()
        except FileNotFoundError:
            self._id_ed25519 = None
        print(f"\twaiting for '{self._hostname}' to respond to ping")
        self.wait_ping()
        print(f"\t{self._hostname} responded to ping, trying to connect using {username}")
        self.ssh_connect_looped(username, password)


    def ssh_connect_looped(self, username: str, password: str) -> None:
        try:
            pkey = paramiko.RSAKey.from_private_key(io.StringIO(self._id_rsa))
        except (paramiko.ssh_exception.PasswordRequiredException, paramiko.ssh_exception.SSHException):
            if not self._id_ed25519:
                raise
            else:
                pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(
                    self._id_ed25519))

        while True:
            self._username = username
            self._password = password
            self._host = paramiko.SSHClient()
            self._host.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                self._host.connect(self._hostname, username=username,
                                   pkey=pkey, password=password)
            except paramiko.ssh_exception.AuthenticationException as e:
                if pkey.get_name() != "ssh-ed25519" and self._id_ed25519:
                    print("\tRetry connect with es25519.")
                    pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(
                        self._id_ed25519))
                    continue

                print(type(e))
                raise e
            except Exception as e:
                print(type(e))
                time.sleep(10)
                continue
            print(f"\tconnected to {self._hostname} with {self._username}")
            break

    def _read_output(self, cmd: str) -> Result:
        _, stdout, stderr = self._host.exec_command(cmd)

        out = []
        for line in iter(stdout.readline, ""):
            print(f"\t{self._hostname}: {line.strip()}")
            out.append(line)

        err = []
        for line in iter(stderr.readline, ""):
            err.append(line)

        exit_code = stdout.channel.recv_exit_status()
        out = "".join(out)
        err = "".join(err)

        return Result(out, err, exit_code)

    def scp(self, source, destination):
        ssh_scp = SCPClient(self._host.get_transport())
        ssh_scp.put(source, destination)


    def run(self, cmd: str) -> Result:
        while True:
            try:
                now = datetime.datetime.now()
                print("\t\t", now.strftime("%Y-%m-%d %H:%M:%S: "), f"running {cmd} on {self._hostname}")
                return self._read_output(cmd)
            except Exception as e:
                print(e)
                print(f"\tConnection lost while running command {cmd}, reconnecting...")
                self.ssh_connect_looped(self._username, self._password)


    def close(self) -> None:
        self._host.close()

    def _bmc_url(self) -> str:
        res_bmc_ip = self._bmc_ip
        if res_bmc_ip is None:
            ip = socket.gethostbyname(self._hostname)
            octets = ip.split(".")
            octets[-1] = str(int(octets[-1]) + 1)
            res_bmc_ip = ".".join(octets)
        return res_bmc_ip

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
        print(f"\tTrying to boot '{self._hostname}' through {self._bmc_url()}")
        red = self._redfish()
        try:
            red.eject_iso()
        except Exception as e:
            print(e)
            print("\t\teject failed, but continuing")
            pass
        red.insert_iso(iso_path)
        print(f"\t\tinserted iso {iso_path}")
        try:
            red.set_iso_once()
        except Exception as e:
            print(e)
            raise e

        print("\t\tsetting to boot from iso")
        red.restart()
        time.sleep(10)
        print(f"\tFinished sending boot to {self._bmc_url()}")

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
        for e in self.run("cat /etc/os-release").out.split("\n"):
            e = e.split("=", maxsplit=1)
            if len(e) != 2:
                continue
            k, v = e
            v = v.strip("\"'")
            d[k] = v
        return d


class RemoteHostWithBF2(RemoteHost):
    def run_in_container(self, cmd: str, interactive: bool = False) -> Result:
        name = "bf"
        print("starting container")
        setup = f"sudo podman run --pull always --replace --pid host --network host --user 0 --name {name} -dit --privileged -v /dev:/dev quay.io/bnemeth/bf"
        r = self.run(setup)
        if r.returncode != 0:
            return r
        it = "-it" if interactive else ""
        return self.run(f"sudo podman exec {it} {name} {cmd}")

    def bf_pxeboot(self, nfs_iso: str, nfs_key: str) -> Result:
        cmd = "sudo killall python3"
        self.run(cmd)
        print("starting pxe server and booting bf")
        cmd = f"/pxeboot {nfs_iso} -w {nfs_key}"
        return self.run_in_container(cmd, True)

    def bf_firmware_upgrade(self) -> Result:
        print("Upgrading firmware")
        return self.run_in_container("/fwup")

    def bf_firmware_defaults(self) -> Result:
        print("Setting firmware config to defaults")
        return self.run_in_container("/fwdefaults")

    def bf_set_mode(self, mode: str) -> Result:
        return self.run_in_container(f"/set_mode {mode}")

    def bf_get_mode(self) -> Result:
        return self.run_in_container("/getmode")

    def bf_firmware_version(self) -> Result:
        return self.run_in_container("fwversion")

    def bf_load_bfb(self) -> Result:
        print("Loading BFB image")
        return self.run_in_container("/bfb")
