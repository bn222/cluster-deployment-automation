import shlex
import os
import time
import typing
from logger import logger
import dhcpConfig
from clustersConfig import NodeConfig
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

    def __init__(self, config: NodeConfig, external_port: str, network_api_port: str):
        super().__init__(config)
        self.external_port = external_port
        self.network_api_port = network_api_port
        self.config = config

    def _boot_iso(self, iso: str) -> None:
        assert self.config.ip
        dhcpConfig.configure_iso_network_port(self.network_api_port, self.config.ip)
        dhcpConfig.configure_dhcpd(self.config)
        self._redfish_boot_ipu(self.external_port, self.config, iso)
        logger.info(f"Redfish boot triggered, attempting to connect to ACC at ip {self.config.ip}")
        # wait on install + reboot to complete
        acc = host.RemoteHost(self.config.ip)
        # WA since we can't reliably expect the acc to get a dhcp lease due to https://issues.redhat.com/browse/IIC-427
        self._wait_for_acc_with_retry(acc=acc)
        # configure_iso_network_port(self.network_api_port, self.config.ip)

    def _wait_for_acc_with_retry(self, acc: host.Host, timeout: int = 1200) -> None:
        # Typically if the acc booted properly it will take < 20 minutes to come up (including the 10 min sleep we do during boot)
        logger.info("Waiting for ACC to come up")
        failures = 0
        while True:
            if acc.ping():
                logger.info("ACC responded to ping, connecting")
                break
            time.sleep(20)
            timeout -= 20
            if timeout <= 0:
                failures += 1
                if failures == 5:
                    logger.error_and_exit("Too many failures trying to get ACC up")
                logger.info("ACC has not responded in a reasonable amount of time, rebooting IMC")
                imc = host.RemoteHost(self.config.bmc)
                imc.ssh_connect(self.config.bmc_user, self.config.bmc_password)
                imc.run("reboot")
                timeout = 240

        acc.ssh_connect("root", "redhat")
        logger.info(acc.run("uname -a"))
        logger.info("Connected to ACC")

    def start(self, iso_or_image_path: str) -> bool:
        ipu_bmc = IPUBMC(self.config.bmc)
        if ipu_bmc.version() != "1.8.0":
            logger.error_and_exit(f"Unexpected version {ipu_bmc.version()}, should be 1.8.0")
        self._boot_iso(iso_or_image_path)
        return True

    def has_booted(self) -> bool:
        return True

    def _redfish_boot_ipu(self, external_port: str, node: NodeConfig, iso: str) -> None:
        def helper(node: NodeConfig, iso_address: str) -> str:
            logger.info(f"Booting {node.bmc} with {iso_address}")
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
        logger.info("Workaround: cold booting the host since currently driver can't deal with host rebooting without coordination")
        assert self.config.host_side_bmc is not None
        ipu_host_bmc = BMC.from_bmc(self.config.host_side_bmc)
        ipu_host_bmc.cold_boot()
        assert self.config.ip is not None
        acc = host.RemoteHost(self.config.ip)
        self._wait_for_acc_with_retry(acc=acc, timeout=300)
        return True

    def _ipu_host(self) -> host.Host:
        def host_from_imc(imc: str) -> str:
            ipu_host = imc.split('-intel-ipu-imc')[0]
            return ipu_host

        node = self.config
        ipu_host_name = host_from_imc(node.bmc)
        ipu_host_url = f"{ipu_host_name}-drac.anl.eng.bos2.dc.redhat.com"
        ipu_host_bmc = BMC.from_bmc(ipu_host_url, "root", "calvin")
        return host.Host(ipu_host_name, ipu_host_bmc)


class IPUBMC(BMC):
    def __init__(self, full_url: str, user: str = "root", password: str = "calvin"):
        if password == "calvin":
            password = "calvincalvincalvin"
        super().__init__(full_url, user, password)

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
cp /work/redfish/redfish-1.8-iso-filesize-hotfix /usr/bin/ipu-redfish-server
cp /work/redfish/certs/server.key /etc/pki/ca-trust/source/anchors/
cp /work/redfish/certs/server.crt /etc/pki/ca-trust/source/anchors/
rm -rf /home/root/MtRemoteRunner # workaround to free up some space: https://issues.redhat.com/browse/IIC-372
update-ca-trust
sleep 10 # wait for ip address so that redfish starts with that in place
systemctl restart redfish
#  workaround to ensure acc has connectivity https://issues.redhat.com/browse/IIC-266
nohup sh -c '
    while true; do
        if [ -f /work/scripts/ipu_port1_setup.sh ]; then
            count=0
            while [ $count -lt 20 ]; do
                /work/scripts/ipu_port1_setup.sh
                count=$((count + 1))
                sleep $count
            done
            break
        else
            break
        fi
    done
' &


        """
        server = host.RemoteHost(server_with_key)
        server.ssh_connect("root", "redhat")
        imc = self._create_imc_rsh()
        imc.run("mkdir -pm 0700 /work/redfish/certs")
        imc.run("chmod 0700 /work/redfish")
        imc.run("chmod 0700 /work/redfish/certs")

        # WA: default MeV 1.8 Redfish silently fails when booting isos above 9.5GB, install MeV 1.20 Redfish binary in the meantime
        server.copy_from("/root/webserver/redfish-1.8-iso-filesize-hotfix", "/tmp/redfish-1.8-iso-filesize-hotfix")
        imc.copy_to("/tmp/redfish-1.8-iso-filesize-hotfix", "/work/redfish/redfish-1.8-iso-filesize-hotfix")
        imc.write("/work/redfish/certs/server.crt", server.read_file("/root/.local-container-registry/domain.crt"))
        imc.write("/work/redfish/certs/server.key", server.read_file("/root/.local-container-registry/domain.key"))

        imc.write("/work/scripts/pre_init_app.sh", script)
        # WA: use idpf for ACC to IMC. Remove when we've moved to icc-net:
        # https://issues.redhat.com/browse/IIC-485
        contents = "{\"init_app_acc_nboot_net_name\": \"enp0s1f0\"}"  # Soon, this will not be required anymore
        imc.write("/work/cfg/config.json", contents)
        imc.run("mkdir -m 0700 /work/redfish")
        imc.run("cp /etc/imc-redfish-configuration.json /work/redfish/")
        imc.run(f"echo {self.password} | bash /usr/bin/ipu-redfish-generate-password-hash.sh")

        # WA: We need to manually install this file to enable networking with the fxp-net_linux-networking.pkg
        imc.copy_to("./manifests/dpu/ipu_port1_setup.sh", "/work/scripts/ipu_port1_setup.sh")
        imc.run("chmod +x /work/scripts/ipu_port1_setup.sh")

        imc.run("reboot")
        time.sleep(10)
        imc.wait_ping()

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
        logger.info("sleeping 5 minutes")
        time.sleep(5 * 60)
        logger.info("restarting Redfish")
        self._restart_redfish()  # make sure redfish is started after IP has been assigned
        logger.info("unsetting boot source override")
        self._unset_bootsource_override()

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
        try:
            response = requests.get(url, auth=(self.user, self.password), verify=False)
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
        wait_until = time.monotonic() + 3600
        filename = url_extract_filename(iso_path)

        imc = self._create_imc_rsh()

        logger.info(f"Downloading {repr(iso_path)} on BMC")
        loop_count = 0
        while not self._virtual_media_is_inserted(filename):
            time.sleep(10)
            if time.monotonic() >= wait_until:
                raise RuntimeError(f"Timeout waiting for {repr(iso_path)} to be inserted as VirtualMedia")
            if loop_count % 6 == 0:
                log_progress()
            loop_count += 1
        logger.info(f"Done iso_path {repr(iso_path)} is inserted as VirtualMedia")

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

    def _unset_bootsource_override(self) -> None:
        url = f"https://{self.url}:8443/redfish/v1/Systems/1"
        data = {"Boot": {"BootSourceOverrideEnabled": "Disabled"}}
        self._requests_patch(url, data)

    def stop(self) -> None:
        pass

    def start(self) -> None:
        pass

    def cold_boot(self) -> None:
        pass

    def _version_via_redfish(self) -> str:
        url = f"https://{self.url}:8443/redfish/v1/Managers/1"
        data = self._requests_get(url)
        fwversion = data.get("FirmwareVersion")
        if not isinstance(fwversion, str):
            logger.error_and_exit("Failed to get FirmwareVersion")
        match = re.search(r"^MEV-.*\.([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+$", fwversion.strip())
        if not match:
            logger.error_and_exit("Failed to extract version")
        return match.group(1)

    def _version_via_ssh(self) -> Optional[str]:
        rh = host.RemoteHost(self.url)
        rh.ssh_connect("root", password="", discover_auth=False)
        contents = rh.read_file("/etc/issue")
        match = re.search(r"Version: (\S+)", contents)
        if not match:
            return None
        return match.group(1).strip()

    def version(self) -> str:
        if self._redfish_available(self.url):
            return self._version_via_redfish()
        else:
            fwversion = self._version_via_ssh()
            if not fwversion:
                raise RuntimeError("Failed to detect imc version thourgh ssh")
            return fwversion


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
