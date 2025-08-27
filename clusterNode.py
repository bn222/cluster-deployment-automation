import abc
import os
import paramiko
import sys
import time
from logger import logger
from typing import Optional

import common
import host
from clustersConfig import NodeConfig
from bmc import BMC
from nfs import NFS


class ClusterNode:
    """
    Base class for all k8s-like nodes to inherit from.

    At a minimum, a correct implementation should provide:
    - a start() method: to provision the node.
    - a has_booted() method: to determine if the node has booted
    - a post_boot() method: to execute actions after the node has been
      provisioned and booted for the first time
    """

    config: NodeConfig
    dynamic_ip: Optional[str]

    __slots__ = [
        "config",
        "future",
        "dynamic_ip",
    ]

    def __init__(self, config: NodeConfig):
        self.config = config
        self.dynamic_ip = None

    def ip(self) -> str:
        if self.config.ip is not None:
            return self.config.ip
        if self.dynamic_ip is None:
            logger.error_and_exit(f"Node {self.config.name} has no IP address")
        return self.dynamic_ip

    @abc.abstractmethod
    def start(self, iso_or_image_path: str) -> bool:
        pass

    def has_booted(self) -> bool:
        return True

    def post_boot(self, *, desired_ip_range: Optional[tuple[str, str]] = None) -> bool:
        return True

    def teardown(self) -> None:
        pass

    def ensure_reboot(self) -> bool:
        return True

    def set_password(self, user: str = "root", password: str = "redhat") -> None:
        rh = host.RemoteHost(self.ip())
        rh.ssh_connect("core")
        rh.run_or_die(f"echo {user}:{password} | sudo chpasswd")

    def print_logs(self) -> None:
        rh = host.RemoteHost(self.ip())
        logger.info(f"Gathering logs from {self.config.name}")
        logger.info(rh.run("sudo journalctl TAG=agent --no-pager").out)

    def _verify_package_is_installed(self, package: str) -> bool:
        rh = host.RemoteHost(self.ip())
        rh.ssh_connect("core")
        ret = rh.run(f"rpm -qa | grep {package}")
        return not ret.returncode

    def health_check(self) -> None:
        # Check that the right packages are installed.
        required_packages = ["kernel-modules-extra"]
        missing_packages = [p for p in required_packages if not self._verify_package_is_installed(p)]
        for p in missing_packages:
            logger.error(f"Required rpm '{p}' is not installed")
        if any(missing_packages):
            sys.exit(-1)

    def wait_for_boot(self, desired_ip_range: tuple[str, str]) -> bool:
        if not common.wait_true(f"{self.config.name} boot", 10, self.has_booted):
            return False

        if not common.wait_true(f"{self.config.name} post_boot", 10, self.post_boot, desired_ip_range=desired_ip_range):
            return False

        self.health_check()
        return True


class VmClusterNode(ClusterNode):
    hostconn: host.Host
    install_wait: bool

    __slots__ = [
        "hostconn",
        "install_wait",
    ]

    def __init__(self, h: host.Host, config: NodeConfig):
        super().__init__(config)
        self.hostconn = h
        self.install_wait = True

    def setup_vm(self, iso_or_image_path: str) -> host.Result:
        disk_size_gb = self.config.disk_size
        if iso_or_image_path.endswith(".iso"):
            options = "-o preallocation="
            if self.config.is_preallocated():
                options += "full"
            else:
                options += "off"

            os.makedirs(os.path.dirname(self.config.image_path), exist_ok=True)
            logger.info(f"creating {disk_size_gb}GB storage for VM {self.config.name} at {self.config.image_path}")
            with self.hostconn.mutex():
                self.hostconn.run_or_die(f'qemu-img create -f qcow2 {options} {self.config.image_path} {disk_size_gb}G')

            cdrom_line = f"--cdrom {iso_or_image_path}"
        else:
            cdrom_line = ""

        if self.hostconn.is_localhost():
            network = "network=default"
        else:
            network = "bridge=virbr0"
        cmd = f"""
        virt-install
            --connect qemu:///system
            -n {self.config.name}
            -r {self.config.ram}
            --cpu host
            --vcpus {self.config.cpu}
            --os-variant={self.config.os_variant}
            --import
            --network {network},mac={self.config.mac}
            --events on_reboot=restart
            {cdrom_line}
            --disk path={self.config.image_path}
            --noreboot
            --noautoconsole
        """

        logger.info(f"Starting VM {self.config.name}")
        ret = self.hostconn.run(cmd)
        if ret.returncode != 0:
            logger.info(f"Finished starting VM {self.config.name}, cmd = {cmd}, ret = {ret}")
        else:
            logger.info(f"Finished starting VM {self.config.name} successfully")
        return ret

    def start(self, iso_or_image_path: str) -> bool:
        return self.setup_vm(iso_or_image_path).success()

    def has_booted(self) -> bool:
        return self.hostconn.vm_is_running(self.config.name)

    def teardown(self) -> None:
        # remove the image only if it really exists
        image_path = self.config.image_path
        self.hostconn.remove(image_path.replace(".qcow2", ".img"))
        self.hostconn.remove(image_path)

        # destroy the VM only if it really exists
        if self.hostconn.run(f"virsh desc {self.config.name}").returncode == 0:
            r = self.hostconn.run(f"virsh destroy {self.config.name}")
            logger.info(r.err if r.err else r.out.strip())
            r = self.hostconn.run(f"virsh undefine {self.config.name}")
            logger.info(r.err if r.err else r.out.strip())

    def ensure_reboot(self) -> bool:
        def vm_state(h: host.Host, node_name: str, running: bool) -> bool:
            return running == h.vm_is_running(node_name)

        name = self.config.name

        # Wait for VM to go from running to not-running (reboot starts)
        common.wait_true(f"reboot of {name} to occur", 0, vm_state, h=self.hostconn, node_name=name, running=False)

        # Check if VM is already running (auto-restart due to --events on_reboot=restart)
        if not self.hostconn.vm_is_running(name):
            # VM is not running, so we need to start it manually
            logger.info(f"VM {name} is not running after reboot, starting it manually")
            r = self.hostconn.run(f"virsh start {name}")
            if not r.success():
                # Check if it failed because domain is already active (race condition)
                if "Domain is already active" in r.err:
                    logger.info(f"VM {name} is already active (race condition resolved)")
                else:
                    logger.error(f"Failed to start VM {name}: {r.err}")
                    return False
        else:
            logger.info(f"VM {name} is already running after reboot (auto-restarted)")

        # Wait for VM to be fully running
        common.wait_true(f"reboot of {name} to finish", 0, vm_state, h=self.hostconn, node_name=name, running=True)

        return True


class X86ClusterNode(ClusterNode):
    external_port: str

    __slots__ = [
        "external_port",
    ]

    def __init__(self, config: NodeConfig, external_port: str):
        super().__init__(config)
        self.external_port = external_port

    def _boot_iso_x86(self, iso: str) -> host.Result:
        logger.info(f"trying to boot {self.config.node} using {iso}")

        lh = host.LocalHost()
        nfs = NFS(lh, self.external_port)

        assert self.config.bmc is not None
        bmc = BMC.from_bmc_config(self.config.bmc)
        h = host.HostWithBF2(self.config.node, bmc)

        iso = nfs.host_file(os.path.join(os.getcwd(), iso))
        h.boot_iso_redfish(iso)
        h.ssh_connect("core")
        logger.info("connected")
        return h.run("hostname")

    def start(self, iso_or_image_path: str) -> bool:
        return self._boot_iso_x86(iso_or_image_path).success()

    def post_boot(self, *, desired_ip_range: Optional[tuple[str, str]] = None) -> bool:
        rh = host.RemoteHost(self.config.node)
        rh.ssh_connect("core")
        ips = []
        if desired_ip_range is None:
            logger.debug("Require \"desired_ip_range\" argument to post_boot()")
            return False
        for ipr in common.ip_addrs(rh):
            for addr_info in ipr.addr_info:
                if addr_info.family != "inet":
                    continue
                if common.ip_range_contains(desired_ip_range, addr_info.local):
                    ips.append(addr_info.local)

        if len(ips) != 1:
            logger.debug(f"Node {self.config.name} has unexpected IP addresses in range {desired_ip_range}.  Got: {ips}")
            return False
        self.dynamic_ip = ips[0]
        return True


class BFClusterNode(ClusterNode):
    external_port: str

    __slots__ = [
        "external_port",
    ]

    def __init__(self, config: NodeConfig, external_port: str):
        super().__init__(config)
        self.external_port = external_port

    def _boot_iso_bf(self, iso: str) -> host.Result:
        lh = host.LocalHost()
        nfs = NFS(lh, self.external_port)

        logger.info(f"Preparing BF on host {self.config.node}")
        assert self.config.bmc is not None
        bmc = BMC.from_bmc_config(self.config.bmc)
        h = host.HostWithBF2(self.config.node, bmc)
        skip_boot = False
        if h.ping():
            try:
                h.ssh_connect("core")
                skip_boot = h.running_fcos()
            except paramiko.ssh_exception.AuthenticationException:
                logger.info("Authentication failed, will not be able to skip boot")

        if skip_boot:
            logger.info(f"Skipping booting {self.config.node}, already booted with FCOS")
        else:
            nfs_file = nfs.host_file("/root/iso/fedora-coreos.iso")
            h.boot_iso_redfish(nfs_file)
            time.sleep(10)
            h.ssh_connect("core")

        if not h.running_fcos():
            logger.error_and_exit("Expected FCOS after booting host {self.config.node} but booted something else")

        nfs_iso = nfs.host_file(f"/root/iso/{iso}")
        nfs_key = nfs.host_file("/root/iso/ssh_priv_key")
        output = h.bf_pxeboot(nfs_iso, nfs_key)
        logger.debug(output)
        if output.returncode:
            logger.error_and_exit(f"Failed to run pxeboot on bf {self.config.node}")
        else:
            logger.info(f"succesfully ran pxeboot on bf {self.config.node}")

        # ip is printed as the last thing when bf is pxeboot'ed
        bf_ip = output.out.strip().split("\n")[-1].strip()
        h.connect_to_bf(bf_ip)
        max_tries = 3
        bf_interfaces = ["enp3s0f0", "enp3s0f0np0"]
        logger.info(f'Will try {max_tries} times to get an IP on {" or ".join(bf_interfaces)}')
        ip = None
        tries = 0
        while True:
            # FIXME: instead of calling h.run_on_bf(), we should be able to
            # have a host.Host instace where h.run() does the right thing. With
            # such abstraction, we could call common.ip_addrs(h).
            ipa = h.run_on_bf("ip -json addr").out
            detected = common.ip_addrs_parse(ipa)
            found = [e for e in detected if e.ifname in bf_interfaces]
            if len(found) != 1:
                logger.error(f"Failed to find expected number of interfaces on bf {self.config.node}")
                logger.error(f"Output was: {ipa}")
                sys.exit(-1)

            ip = None
            for e in found[0].addr_info:
                if e.family == "inet":
                    ip = e.local
            if ip is not None:
                break
            logger.info(f"IP missing on {found[0]}, output was {ipa}")
            tries += 1
            if tries >= max_tries:
                logger.error(f"IP missing on {found[0]}")
                break
            time.sleep(10)

        if ip is None:
            return host.Result(out="", err="Could not detect IP", returncode=1)
        logger.info(f"Detected ip {ip}")
        return host.Result(out=f"{ip}", err="", returncode=0)

    def start(self, iso_or_image_path: str) -> bool:
        result = self._boot_iso_bf(iso_or_image_path)
        if result is not None:
            self.dynamic_ip = result.out
            return result.success()
        else:
            logger.error_and_exit(f"Couldn't find ip of worker {self.config.name}")
