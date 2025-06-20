from logger import logger
import time
from ailib import Redfish
from dataclasses import dataclass
import requests
import timer


@dataclass(frozen=True)
class BmcConfig:
    url: str
    user: str = "root"
    password: str = "calvin"


class BMC:
    def __init__(self, full_url: str, user: str = "root", password: str = "calvin"):
        self.url = full_url
        self.user = user
        self.password = password
        logger.info(f"{full_url} {user} {password}")

    @staticmethod
    def from_bmc_config(bmc_config: BmcConfig) -> 'BMC':
        return BMC.from_bmc(bmc_config.url, bmc_config.user, bmc_config.password)

    @staticmethod
    def from_bmc(ip_or_hostname: str, user: str = "root", password: str = "calvin") -> 'BMC':
        if ip_or_hostname == "":
            raise ValueError("BMC not defined")
        return BMC(ip_or_hostname, user, password)

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
        def boot_iso_with_retry(iso_path: str, attempt: int) -> None:
            logger.info(iso_path)
            logger.info(f"Trying to boot {self.url} using {iso_path}, attempt {attempt}")
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

        assert ":" in iso_path
        for attempt in range(retries):
            try:
                boot_iso_with_retry(iso_path, attempt)
                return
            except Exception as e:
                if attempt % 5 == 4:
                    logger.info("Restarting redfish")
                    self.restart_redfish()
                elif attempt == retries - 1:
                    raise e
                time.sleep(retry_delay)

    def restart_redfish(self) -> None:
        red = self._redfish()
        # Only Dell servers thus far would have BMCs that need to be restarted.
        if red.model == 'dell':
            for _ in range(10):
                headers = {"Content-Type": "application/json"}
                payload = {"ResetType": "GracefulRestart"}
                full_url = f"{self.url}/redfish/v1/Managers/iDRAC.Embedded.1/Actions/Manager.Reset"
                response = requests.post(full_url, auth=(self.user, self.password), headers=headers, json=payload, verify=False)
                if 200 <= response.status_code < 300:
                    logger.info("Command to reset redfish sent successfully")
                    break
                else:
                    logger.error(f"Failed to reset redfish with status {response.status_code} while sending request to {full_url}")
                    time.sleep(5)

            t = timer.Timer("10m")

            while not t.triggered():
                response = requests.get(self.url, auth=(self.user, self.password), verify=False, timeout=5)
                if response.status_code == 200:
                    logger.info("Redfish reset completed")
                    return
                else:
                    logger.info("Waiting for redfish reset to complete")
                    time.sleep(1)
            logger.error_and_exit(f"Redfish didn't come up after {t} time")

    def _redfish(self) -> Redfish:
        return Redfish(self.url, self.user, self.password, debug=False)

    def stop(self) -> None:
        self._redfish().stop()

    def start(self) -> None:
        self._redfish().start()

    def cold_boot(self) -> None:
        self.stop()
        time.sleep(10)
        self.start()
        time.sleep(5)


def main() -> None:
    pass


if __name__ == "__main__":
    main()
