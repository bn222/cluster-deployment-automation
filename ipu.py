import logging
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
from concurrent.futures import ThreadPoolExecutor
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


class IPUClusterNodeVersion(ClusterNode):
    external_port: str
    network_api_port: str
    cluster_node: ClusterNode

    def __init__(self, config: NodeConfig, external_port: str, network_api_port: str):
        super().__init__(config)
        self.external_port = external_port
        self.network_api_port = network_api_port
        ipu_bmc = IPUBMC(config.bmc)
        if ipu_bmc.version() == "1.8.0":
            self.cluster_node = IPUClusterNode(config, external_port, network_api_port)
        else:
            self.cluster_node = IPUClusterNodeOld(config, external_port, network_api_port)

    def start(self, iso_or_image_path: str, executor: ThreadPoolExecutor) -> None:
        self.cluster_node.start(iso_or_image_path, executor)
        self.future = self.cluster_node.future

    def has_booted(self) -> bool:
        return self.cluster_node.has_booted()

    def post_boot(self, desired_ip_range: tuple[str, str]) -> bool:
        return self.cluster_node.post_boot(desired_ip_range)


class IPUClusterNode(ClusterNode):
    external_port: str
    network_api_port: str

    def __init__(self, config: NodeConfig, external_port: str, network_api_port: str):
        super().__init__(config)
        self.external_port = external_port
        self.network_api_port = network_api_port

    def _boot_iso(self, iso: str) -> None:
        assert self.config.ip
        dhcpConfig.configure_iso_network_port(self.network_api_port, self.config.ip)
        dhcpConfig.configure_dhcpd(self.config)
        self._redfish_boot_ipu(self.external_port, self.config, iso)
        # wait on install + reboot to complete
        acc = host.RemoteHost(self.config.ip)
        acc.ssh_connect("root", "redhat")
        logger.info(acc.run("uname -a"))
        # configure_iso_network_port(self.network_api_port, self.config.ip)

    def start(self, iso_or_image_path: str, executor: ThreadPoolExecutor) -> None:
        self.future = executor.submit(self._boot_iso, iso_or_image_path)

    def has_booted(self) -> bool:
        return self.get_future_done()

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

    def post_boot(self, desired_ip_range: tuple[str, str]) -> bool:
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


class IPUClusterNodeOld(ClusterNode):
    external_port: str
    network_api_port: str

    def __init__(self, config: NodeConfig, external_port: str, network_api_port: str):
        super().__init__(config)
        self.external_port = external_port
        self.network_api_port = network_api_port

    def _boot_iso(self, iso: str) -> None:
        self._redfish_boot_ipu(self.external_port, self.config, iso)
        assert self.config.ip
        dhcpConfig.configure_iso_network_port(self.network_api_port, self.config.ip)
        dhcpConfig.configure_dhcpd(self.config)
        self._enable_acc_connectivity()

    def start(self, iso_or_image_path: str, executor: ThreadPoolExecutor) -> None:
        self.future = executor.submit(self._boot_iso, iso_or_image_path)

    def has_booted(self) -> bool:
        return self.get_future_done()

    def _redfish_boot_ipu(self, external_port: str, node: NodeConfig, iso: str) -> None:
        def helper(node: NodeConfig) -> str:
            logger.info(f"Booting {node.bmc} with {iso_address}")
            bmc = BMC.from_bmc(node.bmc)
            bmc.boot_iso_redfish(iso_path=iso_address, retries=5, retry_delay=15)

            imc = host.Host(node.bmc)
            imc.ssh_connect(node.bmc_user, node.bmc_password)
            # TODO: Remove once https://issues.redhat.com/browse/RHEL-32696 is solved
            logger.info("Waiting for 25m (workaround)")
            time.sleep(25 * 60)
            return f"Finished booting imc {node.bmc}"

        # Ensure dhcpd is stopped before booting the IMC to avoid unintentionally setting the ACC hostname during the installation
        # https://issues.redhat.com/browse/RHEL-32696
        lh = host.LocalHost()
        lh.run("systemctl stop dhcpd")

        if is_http_url(iso):
            iso_address = iso
            logger.info(helper(node))
        else:
            logger.debug(f"Hosting local file {iso}")
            if not os.path.exists(iso):
                raise ValueError(f"ISO file {iso} does not exist, exiting")
            serve_path = os.path.dirname(iso)
            iso_name = os.path.basename(iso)
            lh = host.LocalHost()
            lh_ip = common.port_to_ip(lh, external_port)

            with common.HttpServerManager(serve_path, 8000) as http_server:
                iso_address = f"http://{lh_ip}:{str(http_server.port)}/{iso_name}"
                logger.info(helper(node))

    def _enable_acc_connectivity(self) -> None:
        node = self.config
        logger.info(f"Establishing connectivity to {node.name}")
        ipu_imc = host.RemoteHost(node.bmc)
        ipu_imc.ssh_connect(node.bmc_user, node.bmc_password)

        # """
        # We need to ensure the ACC physical port connectivity is enabled during reboot to ensure dhcp gets an ip.
        # Trigger an acc reboot and try to run python /usr/bin/scripts/cfg_acc_apf_x2.py. This will fail until the
        # ACC_LAN_APF_VPORTs are ready. Once this succeeds, we can try to connect to the ACC
        # """
        logger.info("Rebooting IMC to trigger ACC reboot")
        ipu_imc.run("systemctl reboot")
        time.sleep(30)
        ipu_imc.ssh_connect(node.bmc_user, node.bmc_password)
        logger.info(f"Attempting to enable ACC connectivity from IMC {node.bmc} on reboot")
        retries = 30
        for _ in range(retries):
            ret = ipu_imc.run("/usr/bin/scripts/cfg_acc_apf_x2.py")
            if ret.returncode == 0:
                logger.info("Enabled ACC physical port connectivity")
                break
            logger.debug(f"ACC SPF script failed with returncode {ret.returncode}")
            logger.debug(f"out: {ret.out}\n err: {ret.err}")
            time.sleep(15)
        else:
            logger.error_and_exit("Failed to enable ACC connectivity")

        ipu_acc = host.RemoteHost(str(node.ip))
        ipu_acc.ping()
        ipu_acc.ssh_connect("root", "redhat")
        ipu_acc.run("nmcli con mod enp0s1f0 ipv4.route-metric 0")
        ipu_acc.run("ip route delete default via 192.168.0.1")  # remove imc default route to avoid conflict
        logger.info(f"{node.name} connectivity established")

    def post_boot(self, desired_ip_range: tuple[str, str]) -> bool:
        return True


class IPUBMC(BMC):
    def __init__(self, full_url: str, user: str = "root", password: str = "calvin"):
        if password == "calvin":
            password = "calvincalvincalvin"
        super().__init__(full_url, user, password)

    def _run_curl(self, command: str, *, quiet: bool = False) -> host.Result:
        lh = host.LocalHost()
        if not quiet:
            logger.info(command)
        result = lh.run(
            f"curl -v -u {self.user}:{self.password} {command}",
            log_level=-1 if quiet else logging.DEBUG,
        )
        if not quiet:
            logger.info(result)
        return result

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
rm -rf /home/root/MtRemoteRunner # workaround to free up some space: https://issues.redhat.com/browse/IIC-372
update-ca-trust
sleep 10 # wait for ip address so that redfish starts with that in place
systemctl restart redfish
#  workaround to ensure acc has connectivity https://issues.redhat.com/browse/IIC-266
nohup sh -c '
    while true; do
        sleep 30
        python /usr/bin/scripts/cfg_acc_apf_x2.py
        ping -c 1 192.168.0.2
        if [ $? -eq 0 ]; then
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
        imc.write("/work/redfish/certs/server.crt", server.read_file("/root/.local-container-registry/domain.crt"))
        imc.write("/work/redfish/certs/server.key", server.read_file("/root/.local-container-registry/domain.key"))

        imc.write("/work/scripts/pre_init_app.sh", script)
        contents = "{\"init_app_acc_nboot_net_name\": \"enp0s1f0\"}"  # Soon, this will not be required anymore
        imc.write("/work/cfg/config.json", contents)
        imc.run("mkdir -m 0700 /work/redfish")
        imc.run("cp /etc/imc-redfish-configuration.json /work/redfish/")
        imc.run(f"echo {self.password} | bash /usr/bin/ipu-redfish-generate-password-hash.sh")

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

    def _cleanup_iso(self, iso_path: str) -> None:
        imc = self._create_imc_rsh()
        imc.run("rm -f /mnt/imc/acc-os.iso")

    def boot_iso_with_redfish(self, iso_path: str) -> None:
        expected_size = url_get_size(iso_path)
        if expected_size is None:
            raise RuntimeError(f"failed to determine file size of URL {repr(iso_path)}")
        self._prepare_imc(extract_server(iso_path))
        logger.info("restarting Redfish")
        self._restart_redfish()
        # W/A delete iso before downloading it if partially downladed
        # https://issues.redhat.com/browse/IIC-382
        logger.info("Cleaning up iso")
        self._cleanup_iso(iso_path)
        logger.info("inserting iso")
        self._insert_media(iso_path, expected_size=expected_size)
        logger.info("setting boot source override")
        self._bootsource_override_cd()
        logger.info("triggering reboot")
        self._reboot()
        logger.info("sleeping 10 minutes")
        time.sleep(600)
        logger.info("restarting Redfish")
        self._restart_redfish()  # make sure redfish is started after IP has been assigned
        logger.info("unsetting boot source override")
        self._unset_bootsource_override()

    def _virtual_media_is_inserted(self, filename: str) -> bool:
        result = self._run_curl(
            f"-k 'https://{self.url}:8443/redfish/v1/Systems/1/VirtualMedia/1'",
            quiet=True,
        )
        if result.returncode != 0:
            return False
        try:
            data = json.loads(result.out)
        except Exception:
            return False
        v_inserted = data.get("Inserted")
        if not isinstance(v_inserted, bool) or not v_inserted:
            return False
        v_imageName = data.get("ImageName")
        if not isinstance(v_imageName, str) or v_imageName != filename:
            return False

        return True

    def _wait_iso_downloaded(self, iso_path: str, *, expected_size: int) -> None:
        logger.info(f"Waiting for iso_path {repr(iso_path)} ({expected_size} bytes) to be inserted as VirtualMedia")
        wait_until = time.monotonic() + 3600
        filename = url_extract_filename(iso_path)

        imc = self._create_imc_rsh()

        sleep_time = 60.0
        while True:
            time.sleep(sleep_time)
            sleep_time = max(5.0, sleep_time / 1.1)
            if self._virtual_media_is_inserted(filename):
                logger.info(f"Done iso_path {repr(iso_path)} is inserted as VirtualMedia")
                return
            if time.monotonic() >= wait_until:
                raise RuntimeError("Timeout waiting for iso_path {repr(iso_path)} to be inserted as VirtualMedia")

            downloaded_size = self._get_file_size(imc, "/mnt/imc/acc-os.iso")
            if downloaded_size is not None and downloaded_size < expected_size:
                percentage = float(downloaded_size) / float(expected_size) * 100.0
            else:
                percentage = 100.0
            logger.info(f"BMC downloaded {downloaded_size} of {expected_size} bytes ({percentage:.2f}%) of {repr(iso_path)}...")

    def _insert_media(self, iso_path: str, *, expected_size: int) -> None:
        url = f"https://{self.url}:8443/redfish/v1/Systems/1/VirtualMedia/1/Actions/VirtualMedia.InsertMedia"
        data = {"Image": iso_path, "TransferMethod": "Upload"}
        json_data = json.dumps(data)
        self._run_curl(f"-k -X POST {url} -d '{json_data}'")
        self._wait_iso_downloaded(iso_path, expected_size=expected_size)

    def _bootsource_override_cd(self) -> None:
        url = f"https://{self.url}:8443/redfish/v1/Systems/1"
        data = {"Boot": {"BootSourceOverrideEnabled": "Once", "BootSourceOverrideTarget": "Cd"}}
        json_data = json.dumps(data)
        self._run_curl(f"-k -X PATCH {url} -d '{json_data}' --write-out 'HTTP Code: %{{http_code}}\n'")

    def _reboot(self) -> None:
        url = f"https://{self.url}:8443/redfish/v1/Managers/1/Actions/Manager.Reset"
        data = {"ResetType": "ForceRestart"}
        json_data = json.dumps(data)
        self._run_curl(f"-k -d '{json_data}' -X POST {url} --write-out 'HTTP Code: %{{http_code}}\n'")

    def _unset_bootsource_override(self) -> None:
        url = f"https://{self.url}:8443/redfish/v1/Systems/1"
        data = {"Boot": {"BootSourceOverrideEnabled": "Disabled"}}
        json_data = json.dumps(data)
        self._run_curl(f"-k -X PATCH {url} -d '{json_data}' --write-out 'HTTP Code: %{{http_code}}\n'")

    def stop(self) -> None:
        pass

    def start(self) -> None:
        pass

    def cold_boot(self) -> None:
        pass

    def version(self) -> str:
        url = f"https://{self.url}:8443/redfish/v1/Managers/1"
        res = self._run_curl(f"-k '{url}'")
        if res.returncode != 0:
            raise RuntimeError(f"Cannot detect Redfish version: failure to fetch URL {repr(url)}")
        try:
            data = json.loads(res.out)
        except Exception:
            raise RuntimeError(f"Cannot detect Redfish version: not valid JSON received but {repr(res.out)}")
        fwversion = data.get("FirmwareVersion")
        if not isinstance(fwversion, str):
            raise RuntimeError(f"Cannot detect Redfish version: FirmwareVersion field not present in {repr(res.out)}")
        fwversion = fwversion.strip()
        match = re.search(r"^MEV-.*\.([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+$", fwversion)
        if not match:
            raise RuntimeError(f"Cannot detect Redfish version: FirmwareVersion is unexpected {repr(fwversion)}")
        return match.group(1)


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
