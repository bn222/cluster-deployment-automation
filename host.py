import socket
import subprocess
import io
import os
import re
import time
import shlex
import shutil
import sys
import logging
import tempfile
from bmc import BMC
from typing import Optional
from typing import Union
from functools import lru_cache
import paramiko
from paramiko import ssh_exception, RSAKey, Ed25519Key
from logger import logger
from abc import ABC, abstractmethod


def default_id_rsa_path() -> str:
    return os.path.join(os.environ["HOME"], ".ssh/id_rsa")


def default_ed25519_path() -> str:
    return os.path.join(os.environ["HOME"], ".ssh/id_ed25519")


class Result:
    def __init__(self, out: str, err: str, returncode: int):
        self.out = out
        self.err = err
        self.returncode = returncode

    def __str__(self) -> str:
        return f"(returncode: {self.returncode}, error: {self.err})"

    def success(self) -> bool:
        return self.returncode == 0

    @staticmethod
    def result_success() -> 'Result':
        return Result("", "", 0)


class Login(ABC):
    def __init__(self, hostname: str, username: str) -> None:
        self._username = username
        self._hostname = hostname
        self.host = paramiko.SSHClient()
        self.host.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def debug_details(self) -> str:
        return str({k: v for k, v in vars(self).items() if k not in ['_key', '_password']})

    @abstractmethod
    def login(self) -> paramiko.SSHClient:
        pass


class KeyLogin(Login):
    def __init__(self, hostname: str, username: str, key_path: str) -> None:
        super().__init__(hostname, username)
        self._key_path = key_path
        with open(key_path, "r") as f:
            self._key = f.read().strip()

        key_loader = self._key_loader()
        self._pkey = key_loader.from_private_key(io.StringIO(self._key))

    def _key_loader(self) -> Union[type[Ed25519Key], type[RSAKey]]:
        if self._is_rsa():
            return RSAKey
        else:
            return Ed25519Key

    def _is_rsa(self) -> bool:
        lh = LocalHost()
        result = lh.run(f"ssh-keygen -vvv -l -f {self._key_path}")
        logger.debug(result.out)
        return "---[RSA " in result.out

    def login(self) -> paramiko.SSHClient:
        logger.info(f"Logging in into {self._hostname} with {self._key_path}")
        self.host.connect(self._hostname, username=self._username, pkey=self._pkey, look_for_keys=False, allow_agent=False)
        return self.host


class PasswordLogin(Login):
    def __init__(self, hostname: str, username: str, password: str) -> None:
        super().__init__(hostname, username)
        self._password = password

    def login(self) -> paramiko.SSHClient:
        logger.info(f"Logging into {self._hostname} with password")
        self.host.connect(self._hostname, username=self._username, password=self._password, look_for_keys=False, allow_agent=False)
        return self.host


class AutoLogin(Login):
    def __init__(self, hostname: str, username: str) -> None:
        super().__init__(hostname, username)

    def login(self) -> paramiko.SSHClient:
        logger.info(f"Logging into {self._hostname} with Paramiko 'Auto key discovery' & 'Ssh-Agent'")
        self.host.connect(self._hostname, username=self._username, look_for_keys=True, allow_agent=True)
        return self.host


class Host:
    def __new__(cls, hostname: str, bmc: Optional[BMC] = None) -> 'Host':
        key = (hostname, bmc.url if bmc else None)
        if key not in host_instances:
            host_instances[key] = super().__new__(cls)
        return host_instances[key]

    def __init__(self, hostname: str, bmc: Optional[BMC] = None):
        self._hostname = hostname
        self._bmc = bmc
        self._logins: list[Login] = []
        self.sudo_needed = False

    @lru_cache(maxsize=None)
    def is_localhost(self) -> bool:
        return self._hostname in ("localhost", socket.gethostname())

    def ssh_connect(self, username: str, password: Optional[str] = None, discover_auth: bool = True, rsa_path: str = default_id_rsa_path(), ed25519_path: str = default_ed25519_path()) -> None:
        assert not self.is_localhost()
        logger.info(f"waiting for '{self._hostname}' to respond to ping")
        self.wait_ping()
        logger.info(f"{self._hostname} up, connecting with {username}")

        self._logins = []

        if password is not None:
            pw = PasswordLogin(self._hostname, username, password)
            self._logins.append(pw)

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

        if discover_auth:
            auto = AutoLogin(self._hostname, username)
            self._logins.append(auto)

        self.ssh_connect_looped(self._logins)

    def ssh_connect_looped(self, logins: list[Login], timeout: float = 3600) -> None:
        if not logins:
            raise RuntimeError("No usable logins found")

        login_details = ", ".join([login.debug_details() for login in logins])
        logger.info(f"Attempting SSH connections on {self._hostname} with logins: {login_details}")

        first_attempt = True
        end_time = time.monotonic() + timeout
        while time.monotonic() < end_time:
            for login in logins:
                try:
                    self._host = login.login()
                    logger.info(f"Login successful on {self._hostname}")
                    return
                except (ssh_exception.AuthenticationException, ssh_exception.NoValidConnectionsError, ssh_exception.SSHException, socket.error, socket.timeout) as e:
                    if first_attempt:
                        logger.info(f"{type(e).__name__} - {str(e)} for login {login.debug_details()} on host {self._hostname}")
                        first_attempt = False
                    else:
                        logger.debug(f"{type(e).__name__} - {str(e)} for login {login.debug_details()} on host {self._hostname}")
                    time.sleep(10)
                except Exception as e:
                    logger.exception(f"SSH connect, login {login.debug_details()} user {login._username} on host {self._hostname}: {type(e).__name__} - {str(e)}")
                    raise e

        raise ConnectionError(f"Failed to establish an SSH connection to {self._hostname}")

    def _rsa_login(self) -> Optional[KeyLogin]:
        for x in self._logins:
            if isinstance(x, KeyLogin) and x._is_rsa():
                return x
        return None

    def remove(self, source: str) -> None:
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
    def copy_to(self, src_file: str, dst_file: str) -> None:
        if not os.path.exists(src_file):
            raise FileNotFoundError(2, f"No such file or dir: {src_file}")
        self._copy(src_file, dst_file, True)

    # Copying remote_file from "Host", which can be local or remote
    def copy_from(self, src_file: str, dst_file: str) -> None:
        self._copy(src_file, dst_file, False)

    def _copy(self, src_file: str, dst_file: str, to: bool) -> None:
        if self.is_localhost():
            shutil.copy(src_file, dst_file)
        else:
            while True:
                try:
                    sftp = self._host.open_sftp()
                    if to:
                        sftp.put(src_file, dst_file)
                    else:
                        sftp.get(src_file, dst_file)
                    break
                except Exception as e:
                    logger.info(e)
                    logger.info("Disconnected during sftpd, reconnecting...")
                    self.ssh_connect_looped(self._logins)

    def need_sudo(self) -> None:
        self.sudo_needed = True

    def run(self, cmd: str, log_level: int = logging.DEBUG, env: dict[str, str] = os.environ.copy(), quiet: bool = False) -> Result:
        if self.sudo_needed:
            cmd = "sudo " + cmd

        if not quiet:
            logger.log(log_level, f"running command {cmd} on {self._hostname}")
        if self.is_localhost():
            ret_val = self._run_local(cmd, env, quiet)
        else:
            ret_val = self._run_remote(cmd, log_level, quiet)

        logger.log(log_level, ret_val)
        return ret_val

    def _run_local(self, cmd: str, env: dict[str, str], quiet: bool = False) -> Result:
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

    def _run_remote(self, cmd: str, log_level: int, quiet: bool = False) -> Result:
        def read_output(cmd: str, log_level: int) -> Result:
            assert self._host is not None
            _, stdout, stderr = self._host.exec_command(cmd)

            out = []
            for line in iter(stdout.readline, ""):
                logger.log(log_level, f"{self._hostname}: {line.rstrip()}")
                out.append(line)

            err = []
            for line in iter(stderr.readline, ""):
                err.append(line)

            exit_code = stdout.channel.recv_exit_status()

            return Result("".join(out), "".join(err), exit_code)

        # Make sure multiline command is not seen as multiple commands
        cmd = cmd.replace("\n", "\\\n")
        while True:
            try:
                return read_output(cmd, log_level)
            except Exception as e:
                logger.log(log_level, e)
                cmd_str = ""
                if not quiet:
                    cmd_str = cmd
                logger.log(log_level, f"Connection lost while running command {cmd_str}, reconnecting...")
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

    def boot_iso_redfish(self, iso_path: str) -> None:
        if self._bmc is None:
            raise Exception(f"Can't boot iso without bmc on {self.hostname()}")
        self._bmc.boot_iso_redfish(iso_path)

    def stop(self) -> None:
        if self._bmc is None:
            raise Exception(f"Can't stop host without bmc on {self.hostname()}")
        self._bmc.stop()

    def start(self) -> None:
        if self._bmc is None:
            raise Exception(f"Can't start host without bmc on {self.hostname()}")
        self._bmc.start()

    def cold_boot(self) -> None:
        if self._bmc is None:
            raise Exception(f"Can't cold boot host without bmc on {self.hostname()}")
        self._bmc.cold_boot()

    def wait_ping(self) -> None:
        while not self.ping():
            pass

    def ping(self) -> bool:
        lh = Host("localhost")
        ping_cmd = f"timeout 1 ping -4 -c 1 {self._hostname}"
        r = lh.run(ping_cmd)
        return r.returncode == 0

    def os_release(self) -> dict[str, str]:
        d = {}
        for e in self.read_file("/etc/os-release").split("\n"):
            split_e = e.split("=", maxsplit=1)
            if len(split_e) != 2:
                continue
            k, v = split_e
            v = v.strip("\"'")
            d[k] = v
        return d

    def running_fcos(self) -> bool:
        d = self.os_release()
        return (d["NAME"], d["VARIANT"]) == ('Fedora Linux', 'CoreOS')

    def vm_is_running(self, name: str) -> bool:
        def state_running(out: str) -> bool:
            return re.search("State:.*running", out) is not None

        ret = self.run(f"virsh dominfo {name}", logging.DEBUG)
        return not ret.returncode and state_running(ret.out)

    def write(self, fn: str, contents: str) -> None:
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

    def listdir(self, path: Optional[str] = None) -> list[str]:
        if self.is_localhost():
            return os.listdir(path)
        path = path if path is not None else ""
        ret = self.run(f"ls {path}")
        if ret.returncode == 0:
            return ret.out.strip().split("\n")
        raise Exception(f"Error listing dir {path}")

    def hostname(self) -> str:
        return self._hostname

    def home_dir(self, *path_components: str) -> str:
        ret = self.run("bash -c 'echo -n ~'")
        path = ret.out
        if not ret.success() or not path or path[0] != "/":
            raise RuntimeError("Failure getting home directory")
        if path_components:
            path = os.path.join(path, *path_components)
        return path

    def exists(self, path: str) -> bool:
        return self.run(f"stat {path}", logging.DEBUG).returncode == 0


class HostWithCX(Host):
    def cx_firmware_upgrade(self) -> Result:
        logger.info("Upgrading CX firmware")
        return self.run_in_container("/cx_fwup")

    def run_in_container(self, cmd: str, interactive: bool = False) -> Result:
        name = "cx"
        setup = f"sudo podman run --pull always --replace --pid host --network host --user 0 --name {name} -dit --privileged -v /dev:/dev quay.io/bnemeth/bf"
        r = self.run(setup, logging.DEBUG)
        if r.returncode != 0:
            return r
        it = "-it" if interactive else ""
        return self.run(f"sudo podman exec {it} {name} {cmd}")


class HostWithBF2(Host):
    def connect_to_bf(self, bf_addr: str) -> None:
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

        err: list[str] = []
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
        logger.info("Upgrading BF firmware")
        # We need to temporarily pin the BF-2 firmware due to an issue with the latest release: https://issues.redhat.com/browse/OCPBUGS-29882
        # Without this, the sriov-network-operator will fail to put the card into NIC mode
        return self.run_in_container("/fwup -v 24.39.2048")

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


host_instances: dict[tuple[str, Optional[str]], Host] = {}


def sync_time(src: Host, dst: Host) -> Result:
    date = src.run("date").out.strip()
    return dst.run(f"sudo date -s \"{date}\"")


def LocalHost() -> Host:
    return Host("localhost")


def RemoteHost(ip: str) -> Host:
    return Host(ip)
