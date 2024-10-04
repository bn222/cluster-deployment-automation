from logger import logger
import sys
import time
from ailib import Redfish
from typing import Optional
import json
import host
import requests
from urllib.parse import urlparse
import re


class BMC:
    def __init__(self, full_url: str, user: str = "root", password: str = "calvin"):
        self.url = full_url
        self.user = user
        self.password = password
        logger.info(f"{full_url} {user} {password}")

    @staticmethod
    def from_url(url: str, user: str = "root", password: str = "calvin") -> 'BMC':
        url = f"{url}/redfish/v1/Systems/System.Embedded.1"
        return BMC(url, user, password)

    @staticmethod
    def from_bmc(ip_or_hostname: str, user: str = "root", password: str = "calvin") -> 'BMC':
        if ip_or_hostname == "":
            logger.error("BMC not defined")
            sys.exit(-1)
        url = f"https://{ip_or_hostname}/redfish/v1/Systems/System.Embedded.1"
        return BMC(url, user, password)

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

    def boot_iso_redfish(self, iso_path: str, retries: int = 10, retry_delay: int = 60) -> None:
        assert ":" in iso_path
        for attempt in range(retries):
            try:
                self.boot_iso_with_retry(iso_path)
                return
            except Exception as e:
                if attempt == retries - 1:
                    raise e
                else:
                    time.sleep(retry_delay)

    def boot_iso_with_retry(self, iso_path: str) -> None:
        logger.info(iso_path)
        logger.info(f"Trying to boot {self.url} using {iso_path}")
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
        logger.info(f"Finished sending boot to {self.url}")

    def _redfish(self) -> Redfish:
        return Redfish(self.url, self.user, self.password, model='dell', debug=False)

    def stop(self) -> None:
        self._redfish().stop()

    def start(self) -> None:
        self._redfish().start()

    def cold_boot(self) -> None:
        self.stop()
        time.sleep(10)
        self.start()
        time.sleep(5)


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


def get_size(iso_path: str) -> Optional[str]:
    response = requests.head(iso_path, verify=False, allow_redirects=True)
    return response.headers.get('Content-Length')


class IPUBMC(BMC):
    def __init__(self, full_url: str, user: str = "root", password: str = "calvin"):
        if password == "calvin":
            password = "calvincalvincalvin"
        super().__init__(full_url, user, password)

    def _run_curl(self, command: str) -> None:
        lh = host.LocalHost()
        logger.info(command)
        result = lh.run(f"curl -v -u {self.user}:{self.password} {command}")
        logger.info(result)

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
        """
        server = host.RemoteHost(server_with_key)
        server.ssh_connect("root", "redhat")
        imc = host.RemoteHost(self.url)
        imc.ssh_connect("root", password="", discover_auth=False)
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

    def cleanup_iso_if_needed(self, iso_path: str) -> None:
        imc = host.RemoteHost(self.url)
        imc.ssh_connect("root", password="", discover_auth=False)
        expected_size = get_size(iso_path)
        result = imc.run("du -b /mnt/imc/acc-os.iso").out.split()
        logger.info(result)
        if len(result) != 0 and result[0] != expected_size:
            imc.run("rm /mnt/imc/acc-os.iso")

    def boot_iso_with_redfish(self, iso_path: str) -> None:
        self._prepare_imc(extract_server(iso_path))
        logger.info("restarting Redfish")
        self._restart_redfish()
        # W/A delete iso before downloading it if partially downladed
        # https://issues.redhat.com/browse/IIC-382
        logger.info("Checking if iso needs to be cleaned up")
        self.cleanup_iso_if_needed(iso_path)
        logger.info("inserting iso")
        self._insert_media(iso_path)
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

    def _wait_iso_downloaded(self, iso_path: str) -> None:
        size = get_size(iso_path)
        if size is None:
            logger.error_and_exit(f"Couldn't get size of iso {iso_path}")
        logger.info(f"Size of {iso_path} is {size}")

        rh = host.RemoteHost(self.url)
        rh.ssh_connect("root", password="", discover_auth=False)
        loop_count = 0
        while True:
            result = rh.run("du -b /mnt/imc/acc-os.iso").out.split()
            if len(result) == 0:
                continue
            downloaded_size = rh.run("du -b /mnt/imc/acc-os.iso").out.split()[0]
            percentage = (int(downloaded_size) / int(size)) * 100
            if loop_count % 6 == 0:
                logger.info(f"Downloaded {downloaded_size} of {size} ({percentage:.2f}%)")
            loop_count += 1
            if downloaded_size == size:
                break
            time.sleep(10)
        logger.info(f"Downloaded {downloaded_size} of {size} ({percentage:.2f}%)")

    def _insert_media(self, iso_path: str) -> None:
        url = f"https://{self.url}:8443/redfish/v1/Systems/1/VirtualMedia/1/Actions/VirtualMedia.InsertMedia"
        data = {"Image": iso_path, "TransferMethod": "Upload"}
        json_data = json.dumps(data)
        self._run_curl(f"-k -X POST {url} -d '{json_data}'")

        # Since there is no API to check when iso has been completely
        # insertered (downloaded), check for this manually
        # https://issues.redhat.com/browse/IIC-379
        # TODO: Turns out there is an API, Kamil will provide it
        logger.info("Waiting for the size of iso_path to be the same the IMC")
        self._wait_iso_downloaded(iso_path)

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
        rh = host.RemoteHost(self.url)
        rh.ssh_connect("root", password="", discover_auth=False)
        contents = rh.read_file("/etc/issue")
        match = re.search(r"Version: (\S+)", contents)
        if match is None:
            sys.exit(-1)
        return match.group(1).strip()


def main() -> None:
    pass


if __name__ == "__main__":
    main()
