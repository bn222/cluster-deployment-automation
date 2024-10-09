from logger import logger
import time
from ailib import Redfish


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
            raise ValueError("BMC not defined")
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


def main() -> None:
    pass


if __name__ == "__main__":
    main()
