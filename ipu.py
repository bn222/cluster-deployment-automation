import sys
import os
import time
from logger import logger
import dhcpConfig
from clustersConfig import NodeConfig
from clusterNode import ClusterNode
import host
from bmc import IPUBMC, BMC
import common
from concurrent.futures import ThreadPoolExecutor
import urllib.parse


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
        dhcpConfig.configure_dhcpd(self.config)
        self._redfish_boot_ipu(self.external_port, self.config, iso)
        # wait on install + reboot to complete
        acc = host.RemoteHost(self.config.ip)
        acc.ssh_connect("root", "redhat")
        logger.info(acc.run("uname -a"))
        # configure_iso_network_port(self.network_api_port, self.config.ip)
        self._ensure_ipu_netdevs_available()

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
                sys.exit(-1)
            serve_path = os.path.dirname(iso)
            iso_name = os.path.basename(iso)
            lh = host.LocalHost()
            lh_ip = common.port_to_ip(lh, external_port)

            with common.HttpServerManager(serve_path, 8000) as http_server:
                iso_address = f"http://{lh_ip}:{str(http_server.port)}/{iso_name}"
                logger.info(helper(node, iso_address))

    def post_boot(self, desired_ip_range: tuple[str, str]) -> bool:
        return True

    # TODO: Remove this workaround once rebooting the IMC no longer
    # causes the netdevs on the IPU host to be removed
    def _ensure_ipu_netdevs_available(self) -> None:
        # This is a hack, iso_cluster deployments in general should not need to know about the x86 host they are connected to.
        # However, since we need to cold boot the corresponding host, for the time being, infer this from the IMC address
        # rather than requiring the user to provide this information.
        ipu_host = self._ipu_host()
        ipu_host.ssh_connect("core")
        ret = ipu_host.run("test -d /sys/class/net/ens2f0")
        retries = 3
        while ret.returncode != 0:
            logger.error(f"{ipu_host.hostname()} does not have a network device ens2f0 cold booting node to try to recover")
            ipu_host.cold_boot()
            logger.info("Cold boot triggered, waiting for host to reboot")
            time.sleep(60)
            ipu_host.ssh_connect("core")
            retries = retries - 1
            if retries == 0:
                logger.error_and_exit(f"Failed to bring up IPU net device on {ipu_host.hostname()}")
            ret = ipu_host.run("test -d /sys/class/net/ens2f0")

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
                logger.error(f"ISO file {iso} does not exist, exiting")
                sys.exit(-1)
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
        self.ensure_ipu_netdevs_available()

    def post_boot(self, desired_ip_range: tuple[str, str]) -> bool:
        return True

    # TODO: Remove this workaround once rebooting the IMC no longer causes the netdevs on the IPU host to be removed
    def ensure_ipu_netdevs_available(self) -> None:
        def host_from_imc(imc: str) -> str:
            ipu_host = imc.split('-intel-ipu-imc')[0]
            return ipu_host

        node = self.config
        # This is a hack, iso_cluster deployments in general should not need to know about the x86 host they are connected to.
        # However, since we need to cold boot the corresponding host, for the time being, infer this from the IMC address
        # rather than requiring the user to provide this information.
        ipu_host_name = host_from_imc(node.bmc)
        ipu_host_bmc = BMC.from_bmc(ipu_host_name + "-drac.anl.eng.bos2.dc.redhat.com", "root", "calvin")
        ipu_host = host.Host(ipu_host_name, ipu_host_bmc)
        ipu_host.ssh_connect("core")
        ret = ipu_host.run("test -d /sys/class/net/ens2f0")
        retries = 3
        while ret.returncode != 0:
            logger.error(f"{ipu_host.hostname()} does not have a network device ens2f0 cold booting node to try to recover")
            ipu_host.cold_boot()
            logger.info("Cold boot triggered, waiting for host to reboot")
            time.sleep(60)
            ipu_host.ssh_connect("core")
            retries = retries - 1
            if retries == 0:
                logger.error_and_exit(f"Failed to bring up IPU net device on {ipu_host.hostname()}")
            ret = ipu_host.run("test -d /sys/class/net/ens2f0")
