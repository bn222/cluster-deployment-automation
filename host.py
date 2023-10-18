import socket
import subprocess
from collections import namedtuple
import io
import os
import re
import time
import json
import shlex
import shutil
import sys
import logging
import tempfile
from typing import Optional
from typing import Union
from typing import List
from typing import Type
from typing import Dict
from functools import lru_cache
from ailib import Redfish
from tenacity import retry, stop_after_attempt, wait_fixed
import paramiko
from paramiko import ssh_exception, RSAKey, Ed25519Key
from logger import logger
from abc import ABC, abstractmethod


Result = namedtuple("Result", "out err returncode")


class Login(ABC):
    @abstractmethod
    def login(self) -> paramiko.SSHClient:
        pass


class KeyLogin(Login):
    def __init__(self, hostname: str, username: str, key_path: str) -> None:
        self._username = username
        self._hostname = hostname
        self._key_path = key_path
        with open(key_path, "r") as f:
            self._key = f.read().strip()

        key_loader = self._key_loader()
        self._pkey = key_loader.from_private_key(io.StringIO(self._key))

    def _key_loader(self) -> Union[Type[Ed25519Key], Type[RSAKey]]:
        if self._is_rsa():
            return RSAKey
        else:
            return Ed25519Key

    def _is_rsa(self) -> bool:
        lh = LocalHost()
        result = lh.run(f"ssh-keygen -vvv -l -f {self._key_path}")
        print(result)
        return "---[RSA " in result.out

    def login(self) -> paramiko.SSHClient:
        logger.info(f"Logging in into {self._hostname} with {self._key_path}")
        host = paramiko.SSHClient()
        host.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        host.connect(self._hostname, username=self._username, pkey=self._pkey)
        return host


class PasswordLogin(Login):
    def __init__(self, hostname: str, username: str, password: str) -> None:
        self._username = username
        self._password = password
        self._hostname = hostname

    def login(self) -> paramiko.SSHClient:
        logger.info(f"Logging in into {self._hostname} with password")
        host = paramiko.SSHClient()
        host.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        host.connect(self._hostname, username=self._username, password=self._password)
        return host


class Host:
    def __new__(cls, hostname: str, bmc_ip: Optional[str] = None, bmc_user: str = "root", bmc_password: str = "calvin"):
        if hostname not in host_instances:
            host_instances[hostname] = super().__new__(cls)
            logger.debug(f"new instance for {hostname}")
        return host_instances[hostname]

    def __init__(self, hostname: str, bmc_ip: Optional[str] = None, bmc_user: str = "root", bmc_password: str = "calvin"):
        self._hostname = hostname
        self._bmc_ip = bmc_ip
        self._bmc_user = bmc_user
        self._bmc_password = bmc_password
        self._logins: List[Login] = []
        self.sudo_needed = False

    @lru_cache(maxsize=None)
    def is_localhost(self):
        return self._hostname in ("localhost", socket.gethostname())

    def ssh_connect(self, username: str, password: Optional[str] = None, rsa_path: str = default_id_rsa_path(), ed25519_path: str = default_ed25519_path()):
        assert not self.is_localhost()
        logger.info(f"waiting for '{self._hostname}' to respond to ping")
        self.wait_ping()
        logger.info(f"{self._hostname} up, connecting with {username}")

        self._logins = []
        if os.path.exists(rsa_path):
            try:
                id_rsa = KeyLogin(self._hostname, username, rsa_path)
                self._logins.append(id_rsa)
            except Exception:
                pass

        if os.path.exists(ed25519_path):
            try:
                id_ed25519 = KeyLogin(self._hostname, username, ed25519_path)
                self._logins.append(id_ed25519)
            except Exception:
                pass

        if password is not None:
            pw = PasswordLogin(self._hostname, username, password)
            self._logins.append(pw)

        self.ssh_connect_looped(self._logins)

    def ssh_connect_looped(self, logins: List[Login]) -> None:
        if len(logins) == 0:
            raise Exception("No usuable logins found")
        while True:
            for e in logins:
                try:
                    self._host = e.login()
                    return
                except ssh_exception.AuthenticationException as e:
                    logger.info(type(e))
                    raise e
                except Exception as e:
                    logger.info(type(e))
                    time.sleep(10)

    def _rsa_login(self) -> Optional[KeyLogin]:
        for x in self._logins:
            if isinstance(x, KeyLogin) and x._is_rsa():
                return x
        return None

    def remove(self, source):
        if self.is_localhost():
            if os.path.exists(source):
                os.remove(source)
        else:
            assert self._host is not None
            try:
                sftp = self._host.open_sftp()
                sftp.remove(source)
            except FileNotFoundError:
                pass

    # Copying local_file to "Host", which can be local or remote
    def copy_to(self, src_file, dst_file):
        if not os.path.exists(src_file):
            raise FileNotFoundError(2, f"No such file or dir: {src_file}")
        if self.is_localhost():
            shutil.copy(src_file, dst_file)
        else:
            while True:
                try:
                    sftp = self._host.open_sftp()
                    sftp.put(src_file, dst_file)
                    break
                except Exception as e:
                    logger.info(e)
                    logger.info("Disconnected during sftpd, reconnecting...")
                    self.ssh_connect_looped(self._logins)

    def need_sudo(self):
        self.sudo_needed = True

    def run(self, cmd: str, log_level: int = logging.INFO, env: dict = os.environ.copy()) -> Result:
        if self.sudo_needed:
            cmd = "sudo " + cmd

        logger.log(log_level, f"running command {cmd} on {self._hostname}")
        if self.is_localhost():
            return self._run_local(cmd, env)
        else:
            return self._run_remote(cmd, log_level)

    def _run_local(self, cmd: str, env: dict) -> Result:
        args = shlex.split(cmd)
        pipe = subprocess.PIPE
        with subprocess.Popen(args, stdout=pipe, stderr=pipe, env=env) as proc:
            if proc.stdout is None:
                logger.info("Can't find stdout")
                sys.exit(-1)
            if proc.stderr is None:
                logger.info("Can't find stderr")
                sys.exit(-1)
            out = proc.stdout.read().decode("utf-8")
            err = proc.stderr.read().decode("utf-8")
            proc.communicate()
            ret = proc.returncode
        return Result(out, err, ret)

    def _run_remote(self, cmd: str, log_level: int) -> Result:
        def read_output(cmd, log_level):
            assert self._host is not None
            _, stdout, stderr = self._host.exec_command(cmd)

            out = []
            for line in iter(stdout.readline, ""):
                logger.log(log_level, f"{self._hostname}: {line.strip()}")
                out.append(line)

            err = []
            for line in iter(stderr.readline, ""):
                err.append(line)

            exit_code = stdout.channel.recv_exit_status()
            out = "".join(out)
            err = "".join(err)

            return Result(out, err, exit_code)

        # Make sure multiline command is not seen as multiple commands
        cmd = cmd.replace("\n", "\\\n")
        while True:
            try:
                return read_output(cmd, log_level)
            except Exception as e:
                logger.log(log_level, e)
                logger.log(log_level, f"Connection lost while running command {cmd}, reconnecting...")
                self.ssh_connect_looped(self._logins)

    def run_or_die(self, cmd: str) -> Result:
        ret = self.run(cmd)
        if ret.returncode:
            logger.error(f"{cmd} failed: {ret.err}")
            sys.exit(-1)
        else:
            logger.debug(ret.out.strip())
        return ret

    def close(self) -> None:
        assert self._host is not None
        self._host.close()

    def _bmc_url(self) -> str:
        res_bmc_ip = self._bmc_ip
        if res_bmc_ip is None:
            ip = socket.gethostbyname(self._hostname)
            octets = ip.split(".")
            octets[-1] = str(int(octets[-1]) + 1)
            res_bmc_ip = ".".join(octets)
        return f"https://{res_bmc_ip}/redfish/v1/Systems/System.Embedded.1"

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
      d) Under the "HTTP Server Settings", set the "HTTP Address" to be
         "downloads.dell.com".
      e) Click "Check for Update".
      f) Depending on the missing updates, select what is needed then press
         "Install and Reboot"
      g) Wait a while for iDRAC to come up.
      h) Once the web interface is available, go back to the "Dashboard" tab.
      i) Monitor the system to post after the "Dell" blue screen.

    """

    @retry(stop=stop_after_attempt(10), wait=wait_fixed(60))
    def _boot_with_overrides(self, iso_path: str) -> None:
        assert ":" in iso_path
        logger.info(f"Trying to boot '{self._hostname}' through {self._bmc_url()} using {iso_path}")
        red = self._redfish()
        try:
            red.eject_iso()
        except Exception as e:
            logger.info(e)
            logger.info("eject failed, but continuing")
        logger.info(f"inserting iso {iso_path}")
        red.insert_iso(iso_path)
        try:
            red.set_iso_once()
        except Exception as e:
            logger.info(e)
            raise e

        logger.info("setting to boot from iso")
        red.restart()
        time.sleep(10)
        logger.info(f"Finished sending boot to {self._bmc_url()}")

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
        lh = Host("localhost")
        ping_cmd = f"timeout 1 ping -4 -c 1 {self._hostname}"
        r = lh.run(ping_cmd)
        return r.returncode == 0

    def os_release(self) -> dict:
        d = {}
        for e in self.read_file("/etc/os-release"):
            split_e = e.split("=", maxsplit=1)
            if len(split_e) != 2:
                continue
            k, v = split_e
            v = v.strip("\"'")
            d[k] = v
        return d

    def running_fcos(self):
        d = self.os_release()
        return d["NAME"], d["VARIANT"] == 'Fedora Linux', 'CoreOS'

    def vm_is_running(self, name: str) -> bool:
        def state_running(out: str) -> bool:
            return re.search("State:.*running", out) is not None

        ret = self.run(f"virsh dominfo {name}")
        return not ret.returncode and state_running(ret.out)

    def ipa(self) -> dict:
        return json.loads(self.run("ip -json a", logging.DEBUG).out)

    def ipr(self) -> dict:
        return json.loads(self.run("ip -json r", logging.DEBUG).out)

    def all_ports(self) -> dict:
        return json.loads(self.run("ip -json link", logging.DEBUG).out)

    def port_exists(self, port_name: str) -> bool:
        return self.run(f"ip link show {port_name}").returncode == 0

    def port_has_carrier(self, port_name: str) -> bool:
        ports = {x["ifname"]: x for x in self.ipa()}
        if port_name not in ports:
            return False
        return "NO-CARRIER" not in ports[port_name]["flags"]

    def write(self, fn, contents):
        if self.is_localhost():
            with open(fn, "w") as f:
                f.write(contents)
        else:
            with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                tmp_filename = tmp_file.name
                tmp_file.write(contents.encode('utf-8'))
            self.copy_to(tmp_filename, fn)
            os.remove(tmp_filename)

    def read_file(self, file_name: str) -> str:
        if self.is_localhost():
            with open(file_name) as f:
                return f.read()
        else:
            ret = self.run(f"cat {file_name}")
            if ret.returncode == 0:
                return ret.out
            raise Exception(f"Error reading {file_name}")

    def listdir(self, path: Optional[str] = None) -> List[str]:
        if self.is_localhost():
            return os.listdir(path)
        path = path if path is not None else ""
        ret = self.run(f"ls {path}")
        if ret.returncode == 0:
            return ret.out.strip().split("\n")
        raise Exception(f"Error listing dir {path}")

    def hostname(self) -> str:
        return self._hostname

    def exists(self, path: str) -> bool:
        return self.run(f"stat {path}", logging.DEBUG).returncode == 0


class HostWithBF2(Host):
    def connect_to_bf(self, bf_addr: str):
        self.ssh_connect("core")
        prov_host = self._host
        rsa_login = self._rsa_login()
        if rsa_login is None:
            logger.error("Missing login with key")
            sys.exit(-1)
        pkey = rsa_login._pkey

        logger.info(f"Connecting to BF through host {self._hostname}")

        jumpbox_private_addr = '172.31.100.1'  # TODO

        transport = prov_host.get_transport()
        if transport is None:
            return
        src_addr = (jumpbox_private_addr, 22)
        dest_addr = (bf_addr, 22)
        chan = transport.open_channel("direct-tcpip", dest_addr, src_addr)

        self._bf_host = paramiko.SSHClient()
        self._bf_host.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._bf_host.connect(bf_addr, username='core', pkey=pkey, sock=chan)

    def run_on_bf(self, cmd: str, log_level: int = logging.DEBUG) -> Result:
        _, stdout, stderr = self._bf_host.exec_command(cmd)

        out = []
        for line in iter(stdout.readline, ""):
            logger.log(log_level, f"{self._hostname} -> BF: {line.strip()}")
            out.append(line)

        err: List[str] = []
        for line in iter(stderr.readline, ""):
            err.append(line)

        exit_code = stdout.channel.recv_exit_status()
        return Result("".join(out), "".join(err), exit_code)

    def run_in_container(self, cmd: str, interactive: bool = False) -> Result:
        name = "bf"
        setup = f"sudo podman run --pull always --replace --pid host --network host --user 0 --name {name} -dit --privileged -v /dev:/dev quay.io/bnemeth/bf"
        r = self.run(setup, logging.DEBUG)
        if r.returncode != 0:
            return r
        it = "-it" if interactive else ""
        return self.run(f"sudo podman exec {it} {name} {cmd}")

    def bf_pxeboot(self, nfs_iso: str, nfs_key: str) -> Result:
        cmd = "sudo killall python3"
        self.run(cmd)
        logger.info("starting pxe server and booting bf")
        cmd = f"/pxeboot {nfs_iso} -w {nfs_key}"
        return self.run_in_container(cmd, True)

    def bf_firmware_upgrade(self) -> Result:
        logger.info("Upgrading firmware")
        return self.run_in_container("/fwup")

    def bf_firmware_defaults(self) -> Result:
        logger.info("Setting firmware config to defaults")
        return self.run_in_container("/fwdefaults")

    def bf_set_mode(self, mode: str) -> Result:
        return self.run_in_container(f"/set_mode {mode}")

    def bf_get_mode(self) -> Result:
        return self.run_in_container("/getmode")

    def bf_firmware_version(self) -> Result:
        return self.run_in_container("fwversion")

    def bf_load_bfb(self) -> Result:
        logger.info("Loading BFB image")
        return self.run_in_container("/bfb")


host_instances: Dict[str, Host] = {}


def sync_time(src: Host, dst: Host):
    date = src.run("date").out.strip()
    return dst.run(f"sudo date -s \"{date}\"")


def LocalHost() -> Host:
    return Host("localhost")


def RemoteHost(ip: str) -> Host:
    return Host(ip)


def default_id_rsa_path() -> str:
    return os.path.join(os.environ["HOME"], ".ssh/id_rsa")


def default_ed25519_path() -> str:
    return os.path.join(os.environ["HOME"], ".ssh/id_ed25519")
