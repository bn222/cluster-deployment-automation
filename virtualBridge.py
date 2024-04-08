import os
import re
import sys
import time
from logger import logger
from typing import Optional

import common
import host
from clustersConfig import BridgeConfig, NodeConfig


def bridge_dhcp_range_str(dhcp_range: Optional[tuple[str, str]]) -> str:
    if dhcp_range is not None:
        return f"<range start='{dhcp_range[0]}' end='{dhcp_range[1]}'/>"
    return ""


def bridge_ip_address_str(ip: str, mask: str) -> str:
    return f"<ip address='{ip}' netmask='{mask}'>"


class VirBridge:
    """
    Wrapper on top of the libvirt virtual bridge.

    It can be running locally or remote.
    """

    hostconn: host.Host
    config: BridgeConfig

    def __init__(self, h: host.Host, config: BridgeConfig):
        self.hostconn = h
        self.config = config

    def setup_dhcp_entry(self, cfg: NodeConfig) -> None:
        if cfg.ip is None:
            logger.error_and_exit(f"Missing IP for node {cfg.name}")
        ip = cfg.ip
        mac = cfg.mac
        name = cfg.name
        # If adding a worker node fails, one might want to retry w/o tearing down
        # the whole cluster. In that case, the DHCP entry might already be present,
        # with wrong mac -> remove it

        cmd = "virsh net-dumpxml default"
        ret = self.hostconn.run_or_die(cmd)
        if f"'{name}'" in ret.out:
            logger.info(f"{name} already configured as static DHCP entry - removing before adding back with proper configuration")
            host_xml = f"<host name='{name}'/>"
            cmd = f"virsh net-update default delete ip-dhcp-host \"{host_xml}\" --live --config"
            self.hostconn.run_or_die(cmd)

        cmd = "virsh net-dhcp-leases default"
        ret = self.hostconn.run(cmd)
        # Look for "{name} " in the output. The space is intended to differentiate between "bm-worker-2 " and e.g. "bm-worker-20"
        if f"{name} " in ret.out:
            logger.error(f"Error: {name} found in dhcp leases")
            logger.error("To fix this, run")
            logger.error("\tvirsh net-destroy default")
            logger.error("\tRemove wrong entries from /var/lib/libvirt/dnsmasq/virbr0.status")
            logger.error("\tvirsh net-start default")
            logger.error("\tsystemctl restart libvirt")
            sys.exit(-1)

        host_xml = f"<host mac='{mac}' name='{name}' ip='{ip}'/>"
        logger.info(f"Creating static DHCP entry for VM {name}, ip {ip} mac {mac}")
        cmd = f"virsh net-update default add ip-dhcp-host \"{host_xml}\" --live --config"
        self.hostconn.run_or_die(cmd)

    def _ensure_started(self, bridge_xml: str, api_port: str) -> None:
        cmd = "virsh net-destroy default"
        self.hostconn.run(cmd)  # ignore return code - it might fail if net was not started

        cmd = "virsh net-undefine default"
        ret = self.hostconn.run(cmd)
        if ret.returncode != 0 and "Network not found" not in ret.err:
            logger.error_and_exit(str(ret))

        # Fix cases where virsh net-start fails with error "... interface virbr0: File exists"
        cmd = "ip link delete virbr0"
        self.hostconn.run(cmd)  # ignore return code - it might fail if virbr did not exist

        cmd = f"virsh net-define {bridge_xml}"
        self.hostconn.run_or_die(cmd)

        # set interface down before starting bridge as otherwise bridge start might fail if interface
        # already got an IP address in same network as bridge
        self.hostconn.run(f"ip link set {api_port} down")

        cmd = "virsh net-start default"
        self.hostconn.run_or_die(cmd)

        self.hostconn.run(f"ip link set {api_port} up")

    def _network_xml(self) -> str:
        if self.config.dynamic_ip_range is None:
            dhcp_part = ""
        else:
            dhcp_part = f"""<dhcp>
                {bridge_dhcp_range_str(self.config.dynamic_ip_range)}
                </dhcp>"""

        return f"""
                <network>
                <name>default</name>
                <forward mode='nat'/>
                <bridge name='virbr0' stp='off' delay='0'/>
                {bridge_ip_address_str(self.config.ip, self.config.mask)}
                {dhcp_part}
                </ip>
                </network>"""

    def _restart(self) -> None:
        self.hostconn.run_or_die("systemctl restart libvirtd")

    def _ensure_run_as_root(self) -> None:
        qemu_conf = self.hostconn.read_file("/etc/libvirt/qemu.conf")
        if re.search('\nuser = "root"', qemu_conf) and re.search('\nuser = "root"', qemu_conf):
            return
        self.hostconn.run("sed -e 's/#\\(user\\|group\\) = \".*\"$/\\1 = \"root\"/' -i /etc/libvirt/qemu.conf")
        self._restart()

    def configure(self, api_port: str) -> None:
        hostname = self.hostconn.hostname()
        cmd = "systemctl enable libvirtd --now"
        self.hostconn.run_or_die(cmd)

        self._ensure_run_as_root()

        # stp must be disabled or it might conflict with default configuration of some physical switches
        # 'bridge' section of network 'default' can't be updated => destroy and recreate
        # check that default exists and contains stp=off
        cmd = "virsh net-dumpxml default"
        ret = self.hostconn.run(cmd)

        needs_reconfigure = False

        expected_dhcp_range = bridge_dhcp_range_str(self.config.dynamic_ip_range)
        if expected_dhcp_range not in ret.out:
            needs_reconfigure = True

        if not expected_dhcp_range and "dhcp" in ret.out:
            needs_reconfigure = True

        # Make sure STP is off on the virtual bridge.
        if "stp='off'" not in ret.out:
            needs_reconfigure = True

        # Make sure the correct bridge IP is configured.
        if bridge_ip_address_str(self.config.ip, self.config.mask) not in ret.out:
            needs_reconfigure = True

        if needs_reconfigure:
            logger.info("Destoying and recreating bridge")
            logger.info(f"creating default-net.xml on {hostname}")
            contents = self._network_xml()

            bridge_xml = os.path.join("/tmp", 'vir_bridge.xml')
            self.hostconn.write(bridge_xml, contents)
            # Not sure why/whether this is needed. But we saw failures w/o it.
            # Without this, net-undefine within ensure_bridge_is_started fails as libvirtd fails to restart
            # We need to investigate how to remove the sleep to speed up
            time.sleep(5)
            self._ensure_started(bridge_xml, api_port)

            self._restart()

            # Not sure why/whether this is needed. But we saw failures w/o it.
            # We need to investigate how to remove the sleep to speed up
            time.sleep(5)

    def eth_address(self) -> str:
        max_tries = 3
        logger.info(f"Will try {max_tries} to get the virbr0 ethernet address on {self.hostconn.hostname()}")

        for i in range(max_tries):
            logger.debug(f"Trying to get the virbr0 ethernet address on {self.hostconn.hostname()} (try #{i})")
            bridge_port = common.find_port(self.hostconn, 'virbr0')
            if bridge_port is not None:
                return bridge_port.address
            time.sleep(5)

        logger.error_and_exit(f"Failed to get the virbr0 ethernet address on {self.hostconn.hostname()}")
        return ""
