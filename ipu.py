import shlex
import os
import time
import typing
import itertools
from logger import logger
from clustersConfig import NodeConfig
from bmc import BmcConfig
from clusterNode import ClusterNode
import host
from bmc import BMC
import common
from typing import Any
import urllib.parse
from urllib.parse import urlparse
from typing import Optional
import json
import requests
import re
import hashlib
import timer


def is_http_url(url: str) -> bool:
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False


"""
ExtraConfigIPU is used to provision and IPUs specified via Redfish through the IMC.
This works by making some assumptions about the current state of the IPU:
- The IMC is on MeV 1.2 / Mev 1.3
- BMD_CONF has been set to allow for iso Boot
- ISCSI attempt has been added to allow for booting into the installed media
- The specified ISO contains full installation kickstart / kargs required for automated boot
- The specified ISO handles installing dependencies like dhclient and microshift
- The specified ISO architecture is aarch64
- There is an additional connection between the provisioning host and the acc on an isolated subnet to serve dhcp / provide acc with www
"""


class IPUClusterNode(ClusterNode):
    external_port: str
    network_api_port: str
    config: NodeConfig
    apply_work_around: bool

    def __init__(self, config: NodeConfig, external_port: str, network_api_port: str):
        super().__init__(config)
        self.external_port = external_port
        self.network_api_port = network_api_port
        self.config = config
        self.apply_work_around = True

    def _boot_iso(self, iso: str) -> None:
        assert self.config.ip
        self._redfish_boot_ipu(self.external_port, self.config, iso)
        logger.info("Redfish installation triggered")

        if self.apply_work_around:
            self.work_around()

        logger.info("Validating ACC is connectable to block before proceeding")
        assert self.config.ip is not None
        acc = host.RemoteHost(self.config.ip)
        self._wait_for_acc_with_retry(acc=acc)
        # configure_iso_network_port(self.network_api_port, self.config.ip)

    def _wait_for_acc_with_retry(self, acc: host.Host) -> None:
        logger.info("Waiting for ACC to come up")
        failures = 0
        # Typically if the acc booted properly it will take < 20 minutes to come
        t = timer.Timer("20m")
        while True:
            if acc.ping():
                logger.info(f"ACC responded to ping after {t}, connecting")
                break
            if t.triggered():
                logger.info("ACC has not responded in a reasonable amount of time")
                failures += 1
                if failures == 5:
                    logger.error_and_exit(f"Too many failures {failures} trying to get ACC up")
                else:
                    assert self.config.bmc is not None
                    imc = host.RemoteHost(self.config.bmc.url)
                    imc.ssh_connect(self.config.bmc.user, self.config.bmc.password)
                    imc.run("reboot")
                    t.reset()
            time.sleep(1)

        acc.ssh_connect("root", "redhat")
        logger.info(acc.run("uname -a"))
        logger.info("Connected to ACC")

    def start(self, iso_or_image_path: str) -> bool:
        assert self.config.bmc is not None
        ipu_bmc = IPUBMC(self.config.bmc)
        if ipu_bmc.version() != "1.8.0" and ipu_bmc.version() != "2.0.0":
            logger.error_and_exit(f"Unexpected version {ipu_bmc.version()}, should be 1.8.0 or 2.0.0")
        if self.recovery_mode():
            logger.error_and_exit("IPU is in recovery mode, exiting")

        self._boot_iso(iso_or_image_path)
        return True

    def recovery_mode(self) -> bool:
        assert self.config.bmc is not None
        imc = host.RemoteHost(self.config.bmc.url)
        imc.ssh_connect(self.config.bmc.user, self.config.bmc.password)
        return "ipu-recovery" in imc.run("cat /etc/hostname").out

    def has_booted(self) -> bool:
        return True

    def _redfish_boot_ipu(self, external_port: str, node: NodeConfig, iso: str) -> None:
        def helper(node: NodeConfig, iso_address: str) -> str:
            assert node.bmc is not None
            logger.info(f"Booting {node.bmc.url} with {iso_address}")
            bmc = IPUBMC(node.bmc)
            bmc.boot_iso_with_redfish(iso_path=iso_address)
            return "Boot command sent"

        if is_http_url(iso):
            logger.info(helper(node, iso))
        else:
            logger.debug(f"Hosting local file {iso}")
            if not os.path.exists(iso):
                logger.error(f"ISO file {iso} does not exist, exiting")
                raise ValueError(f"ISO file {iso} does not exist, exiting")
            serve_path = os.path.dirname(iso)
            iso_name = os.path.basename(iso)
            lh = host.LocalHost()
            lh_ip = common.port_to_ip(lh, external_port)

            with common.HttpServerManager(serve_path, 8000) as http_server:
                iso_address = f"http://{lh_ip}:{str(http_server.port)}/{iso_name}"
                logger.info(helper(node, iso_address))

    def post_boot(self, *, desired_ip_range: Optional[tuple[str, str]] = None) -> bool:
        return True

    def work_around(self) -> None:
        assert self.config.ip is not None
        assert self.config.bmc is not None
        logger.info("Applying workaround")

        imc = host.RemoteHost(self.config.bmc.url)
        imc.ssh_connect(self.config.bmc.user, self.config.bmc.password)
        imc.run("hostname")
        logger.info("Waiting until ssh is up on ACC")
        cmd = 'ssh -o StrictHostKeyChecking=no -o PubkeyAuthentication=no -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o ChallengeResponseAuthentication=no 192.168.0.2 2>&1 | grep "Permission denied"'
        timeout_timer = timer.Timer("25m")
        for tries in itertools.count(0):
            ret = imc.run(cmd)
            if ret.returncode == 0:
                logger.info(f"Connected to ACC through IMC after {tries} tries")
                break
            time.sleep(1)
            if timeout_timer.triggered():
                logger.error_and_exit(f"Waited for {timeout_timer.elapsed()} but ACC wasn't reachable through IMC")

        # As a WA for https://issues.redhat.com/browse/IIC-527 we need to reload the idpf driver since this seems to fail
        # after an IMC reboot (which occurs during the RHEL installation)
        assert self.config.dpu_host is not None
        logger.info(f"Reloading idpf on host side {self.config.dpu_host}")

        ipu_host = host.RemoteHost(self.config.dpu_host)
        ipu_host.ssh_connect("core")
        ipu_host.run("sudo rmmod idpf")
        time.sleep(10)
        ipu_host.run("sudo modprobe idpf")
        logger.info("Reload of idpf on host sode complete")


class IPUBMC(BMC):
    def __init__(self, bmc_config: BmcConfig, host_bmc: Optional[BMC] = None):
        if bmc_config.password == "calvin":
            password = "calvincalvincalvin"
        else:
            password = bmc_config.password
        super().__init__(bmc_config.url, bmc_config.user, password)
        self._host_bmc = host_bmc

    def _restart_redfish(self) -> None:
        rh = host.RemoteHost(self.url)
        rh.ssh_connect("root", password="", discover_auth=False)

        rh.run("systemctl restart redfish")
        # it takes some time before the server is ready to accept incoming connections
        time.sleep(10)

    def _prepare_imc(self, server_with_key: str) -> None:
        script = """
#!/bin/sh

CURDIR=$(pwd)
WORKDIR=`dirname $(realpath $0)`

if [ -d "$WORKDIR" ]; then
    cd $WORKDIR
    if [ -e load_custom_pkg.sh ]; then
        # Fix up the cp_init.cfg file
        ./load_custom_pkg.sh
    fi
fi
cd $CURDIR
date -s "Thu Sep 19 08:18:22 AM EDT 2024"
cp /work/redfish/certs/server.key /etc/pki/ca-trust/source/anchors/
cp /work/redfish/certs/server.crt /etc/pki/ca-trust/source/anchors/
update-ca-trust
sleep 10 # wait for ip address so that redfish starts with that in place
systemctl restart redfish
        """
        sha = self.current_file_sha()
        server = host.RemoteHost(server_with_key)
        server.ssh_connect("root", "redhat")
        imc = self._create_imc_rsh()
        if imc.exists("/work/cda_sha") and imc.read_file("/work/cda_sha") == sha:
            logger.info("Skipping preparing IMC")
            return

        imc.run("mkdir -pm 0700 /work/redfish/certs")
        imc.run("chmod 0700 /work/redfish")
        imc.run("chmod 0700 /work/redfish/certs")
        imc.write("/work/redfish/certs/server.crt", server.read_file("/root/.local-container-registry/domain.crt"))
        imc.write("/work/redfish/certs/server.key", server.read_file("/root/.local-container-registry/domain.key"))

        imc.write("/work/scripts/pre_init_app.sh", script)
        # WA: use idpf for ACC to IMC. Remove when we've moved to icc-net:
        # https://issues.redhat.com/browse/IIC-485
        imc.run("/usr/bin/imc-scripts/cfg_boot_options \"init_app_acc_nboot_net_name\" \"enp0s1f0\"")
        imc.run("/usr/bin/imc-scripts/cfg_boot_options \"init_app_acc_nboot_stage\"  \"0\"")
        # When developing / frequently re-deploying the ACC, we can update the watchdog timeout to avoid ending up in recovery mode
        # https://issues.redhat.com/browse/IIC-369
        if imc.exists("/mnt/imc/acc_variable/acc-config.json"):
            acc_config = imc.read_file("/mnt/imc/acc_variable/acc-config.json")
        else:
            contents = {"acc_watchdog_timer": 9999, "kernel": {"boot_params": ""}}
            acc_config = json.dumps(contents)
        imc.write("/mnt/imc/acc_variable/acc-config.json", acc_config.replace("\"acc_watchdog_timer\": 60", "\"acc_watchdog_timer\": 9999"))

        imc.run("mkdir -m 0700 /work/redfish")
        imc.run("cp /etc/imc-redfish-configuration.json /work/redfish/")
        imc.run(f"echo {self.password} | bash /usr/bin/ipu-redfish-generate-password-hash.sh")

        logger.info("Rebooting IMC")
        imc.run("reboot")
        time.sleep(20)
        imc.wait_ping()
        imc.ssh_connect("root", password="", discover_auth=False)
        logger.info("Reboot IMC finished")
        imc.write("/work/cda_sha", sha)

    def current_file_sha(self) -> str:
        def sha(input: str) -> str:
            hash_object = hashlib.sha512()
            hash_object.update(input.encode('utf-8'))
            return hash_object.hexdigest()

        with open(__file__) as f:
            return sha("".join(f.readlines()))

    def _create_imc_rsh(self) -> host.Host:
        rsh = host.RemoteHost(self.url)
        rsh.ssh_connect("root", password="", discover_auth=False)
        return rsh

    @staticmethod
    def _get_file_size(rsh: host.Host, filename: str) -> Optional[int]:
        try:
            res = rsh.run(f"du -b {shlex.quote(filename)}", log_level=-1)
            if res.returncode != 0:
                return None
            val = int(res.out.split()[0])
        except Exception:
            return None
        if val < 0:
            return None
        return val

    def _cleanup_iso(self) -> None:
        imc = self._create_imc_rsh()
        imc.run("rm -f /mnt/imc/acc-os.iso")

    def boot_iso_with_redfish(self, iso_path: str) -> None:
        expected_size = url_get_size(iso_path)
        if expected_size is None:
            raise RuntimeError(f"failed to determine file size of URL {repr(iso_path)}")
        self._prepare_imc(extract_server(iso_path))
        logger.info("restarting Redfish")
        self._restart_redfish()
        imc = self._create_imc_rsh()
        imc_url_path = "/work/url"

        def matching_url(imc: host.Host) -> bool:
            try:
                contents = imc.read_file(imc_url_path)
            except Exception:
                return False
            return contents == iso_path

        def same_size(imc: host.Host, expected_size: int) -> bool:
            fs = self._get_file_size(imc, "/mnt/imc/acc-os.iso")
            return fs is not None and expected_size == fs

        if not matching_url(imc) or not same_size(imc, expected_size):
            logger.info("Cleaning up iso")
            self._cleanup_iso()
            logger.info("inserting iso")
            self._insert_media(iso_path, expected_size=expected_size)
        else:
            logger.info("Keeping existing iso since url and size didn't change")
        imc.write(imc_url_path, iso_path)
        logger.info("setting boot source override")
        self._bootsource_override_cd()
        logger.info("triggering reboot")
        self._reboot()

    def _requests_get(self, url: str) -> dict[str, str]:
        try:
            response = requests.get(url, auth=(self.user, self.password), verify=False)
            response.raise_for_status()
            ret: dict[str, str] = response.json()
            return ret
        except requests.exceptions.RequestException as e:
            logger.error_and_exit(f"Request failed: {e}")
        except json.JSONDecodeError as e:
            logger.error_and_exit(f"Failed to parse JSON: {e}")

    def _requests_post(self, url: str, data: dict[str, str]) -> None:
        try:
            response = requests.post(url, json=data, auth=(self.user, self.password), verify=False)
            response.raise_for_status()
            logger.debug(f"HTTP Code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")

    def _requests_patch(self, url: str, data: dict[str, Any]) -> None:
        try:
            response = requests.patch(url, json=data, auth=(self.user, self.password), verify=False)
            response.raise_for_status()
            logger.debug(f"HTTP Code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")

    def _redfish_available(self, url: str) -> bool:
        full_url = f"https://{url}:8443/redfish/v1/Systems/1"
        try:
            response = requests.get(full_url, auth=(self.user, self.password), verify=False)
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException:
            return False
        except json.JSONDecodeError:
            return False

    def _virtual_media_is_inserted(self, filename: str) -> bool:
        url = f"https://{self.url}:8443/redfish/v1/Systems/1/VirtualMedia/1"
        data = self._requests_get(url)
        inserted = data.get("Inserted")
        if not isinstance(inserted, bool) or not inserted:
            return False
        image_name = data.get("ImageName")
        if not isinstance(image_name, str) or image_name != filename:
            return False
        return True

    def _wait_iso_downloaded(self, iso_path: str, *, expected_size: int) -> None:
        def log_progress() -> None:
            downloaded_size = self._get_file_size(imc, "/mnt/imc/acc-os.iso") or 0
            percentage = float(downloaded_size) / float(expected_size) * 100.0
            logger.info(f"BMC downloaded {downloaded_size} of {expected_size} bytes ({percentage:.2f}%)")

        logger.info(f"Waiting for {repr(iso_path)} ({expected_size} bytes) to be inserted as VirtualMedia")
        filename = url_extract_filename(iso_path)

        imc = self._create_imc_rsh()

        logger.info(f"Downloading {repr(iso_path)} on BMC")
        loop_count = 0
        t = timer.Timer("1h")
        for loop_count in itertools.count(0):
            time.sleep(1)
            if loop_count % 60 == 0:
                log_progress()
            if t.triggered():
                raise RuntimeError(f"Timeout waiting for {t.elapsed()} to be inserted as VirtualMedia")
            if self._virtual_media_is_inserted(filename):
                break
        logger.info(f"Done iso_path {repr(iso_path)} is inserted as VirtualMedia, took {t.elapsed()}")

    def _insert_media(self, iso_path: str, *, expected_size: int) -> None:
        url = f"https://{self.url}:8443/redfish/v1/Systems/1/VirtualMedia/1/Actions/VirtualMedia.InsertMedia"
        data = {"Image": iso_path, "TransferMethod": "Upload"}
        self._requests_post(url, data)
        self._wait_iso_downloaded(iso_path, expected_size=expected_size)

    def _bootsource_override_cd(self) -> None:
        url = f"https://{self.url}:8443/redfish/v1/Systems/1"
        data = {"Boot": {"BootSourceOverrideEnabled": "Once", "BootSourceOverrideTarget": "Cd"}}
        self._requests_patch(url, data)

    def _reboot(self) -> None:
        url = f"https://{self.url}:8443/redfish/v1/Managers/1/Actions/Manager.Reset"
        data = {"ResetType": "ForceRestart"}
        self._requests_post(url, data)

    def stop(self) -> None:
        pass

    def start(self) -> None:
        pass

    def cold_boot(self) -> None:
        assert self._host_bmc is not None
        self._host_bmc.cold_boot()
        # Cold boot should also reboot IMC, give time to settle before trying to ping IMC
        time.sleep(20)

    def _redfish_version(self) -> str:
        url = f"https://{self.url}:8443/redfish/v1/Managers/1"
        data = self._requests_get(url)
        fwversion = data.get("FirmwareVersion")
        if not isinstance(fwversion, str):
            logger.error_and_exit("Failed to get FirmwareVersion")
        match = re.search(r"^MEV-.*\.([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+$", fwversion.strip())
        if not match:
            logger.error_and_exit("Failed to extract version")
        return match.group(1)

    def _redfish_name(self) -> str:
        url = f"https://{self.url}:8443/redfish/v1/"
        data = self._requests_get(url)
        name = data.get("Name")
        if not isinstance(name, str):
            logger.error_and_exit("Failed to get Name")
        return name

    def _version_via_ssh(self) -> Optional[str]:
        rh = host.RemoteHost(self.url)
        # TODO: after mev ts upgrade, remove the timeout + try/except
        try:
            rh.ssh_connect("root", password="", discover_auth=False, timeout="5s")
        except Exception as e:
            logger.info(f"Couldn't connect to IPU through SSH with exception {e}")
            return None

        contents = rh.read_file("/etc/issue")
        match = re.search(r"Version: (\S+)", contents)
        if not match:
            return None
        return match.group(1).strip()

    def version(self) -> str:
        if self._redfish_available(self.url):
            return self._redfish_version()
        else:
            fwversion = self._version_via_ssh()
            if not fwversion:
                raise RuntimeError("Failed to detect imc version thourgh ssh")
            return fwversion

    def is_ipu(self) -> bool:
        logger.info(f"Checking if DPU is IPU via {self.url}")
        if self._redfish_available(self.url):
            return "Intel IPU" in self._redfish_name()
        else:
            # workaround: remove when redfish is started properly at boot
            logger.info(f"Redfish is not up on {self.url}, using SSH to check")
            return self._version_via_ssh() is not None

    def ensure_firmware(self, force: bool, version: str) -> None:
        def firmware_is_same() -> bool:
            imc.ssh_connect(self.user, self.password)
            ret = imc.run("cat /etc/issue.net")
            if version in ret.out:
                logger.info(f"Current MeV fw version is {ret.out.strip()}")
                return True
            else:
                return False

        assert self.is_ipu()
        imc = host.Host(self.url)

        logger.info(f"Will ensure {self.url} is on firmware version: {version}")
        logger.info("Checking if firmware update is required")

        if force or (not firmware_is_same()):
            logger.info("Proceeding with firmware update")
        else:
            logger.info("Skipping firmware update")
            return

        # Perform upgrade
        lh = host.LocalHost()

        logger.info("Starting flash of SSD/SPI (this will take some time ~40min)")
        fw_up_cmd = f"--dpu-type ipu --imc-address {self.url} firmware up --version {version}"
        ret = lh.run_in_container(fw_up_cmd, interactive=True)

        if not ret.success():
            logger.error_and_exit(f"Failed to flash new firmware. Error: {ret.err}")

        self.cold_boot()

        if not firmware_is_same():
            logger.error_and_exit(f"Mev firmware release is not the expected version: {ret.out}")

        logger.info("MeV firmware flash complete")


def extract_server(url: str) -> str:
    """
    Extract the server name from a given URL.

    Args:
        url (str): The URL to extract the server name from.

    Returns:
        str: The server name (without port number).
    """
    parsed_url = urlparse(url)
    return parsed_url.netloc.split(':')[0]


def url_extract_filename(url: str) -> str:
    parsed_url = urlparse(url)
    if not parsed_url.path:
        raise ValueError(f"URL {repr(url)} has not path name")
    return os.path.basename(parsed_url.path)


def url_get_size(iso_path: str) -> Optional[int]:
    header_value: typing.Any
    try:
        response = requests.head(iso_path, verify=False, allow_redirects=True, timeout=3600.0)
        header_value = response.headers.get('Content-Length')
        val = int(header_value.strip())
    except Exception:
        return None
    if val < 0:
        return None
    return val
