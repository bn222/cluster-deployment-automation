import abc
import os
import paramiko
import shlex
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor
from logger import logger
from typing import Optional

import common
import host
from clustersConfig import NodeConfig
from host import BMC
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
    future: Future[Optional[host.Result]]
    dynamic_ip: Optional[str] = None

    def __init__(self, config: NodeConfig):
        def empty() -> Future[Optional[host.Result]]:
            f: Future[Optional[host.Result]] = Future()
            f.set_result(None)
            return f

        self.config = config
        self.future = empty()

    def ip(self) -> str:
        if self.config.ip is not None:
            return self.config.ip
        if self.dynamic_ip is None:
            logger.error_and_exit(f"Node {self.config.name} has no IP address")
        return self.dynamic_ip

    @abc.abstractmethod
    def start(self, iso_or_image_path: str, executor: ThreadPoolExecutor) -> None:
        pass

    @abc.abstractmethod
    def has_booted(self) -> bool:
        pass

    @abc.abstractmethod
    def post_boot(self, desired_ip_range: tuple[str, str]) -> bool:
        pass

    def teardown(self) -> None:
        pass

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
        # Check that the boot stage completed correctly.
        if self.get_future_done():
            result = self.future.result()
            if result is not None and result.returncode != 0:
                logger.error_and_exit(f"Failed to provision node {self.config.name}: {result.err}")

        # Check that the right packages are installed.
        required_packages = ["kernel-modules-extra"]
        missing_packages = [p for p in required_packages if not self._verify_package_is_installed(p)]
        for p in missing_packages:
            logger.error(f"Required rpm '{p}' is not installed")
        if any(missing_packages):
            sys.exit(-1)

    def get_future_done(self) -> bool:
        state = self.future.done()
        if state is True:
            exception = self.future.exception()
            if exception is not None:
                raise Exception(f"Got exception from future {exception}")

        return state


class VmClusterNode(ClusterNode):
    hostconn: host.Host
    install_wait: bool = True

    def __init__(self, h: host.Host, config: NodeConfig):
        super().__init__(config)
        self.hostconn = h

    def ip(self) -> str:
        assert self.config.ip is not None
        return self.config.ip

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
            self.hostconn.run_or_die(f'qemu-img create -f qcow2 {options} {self.config.image_path} {disk_size_gb}G')

            cdrom_line = f"--cdrom {iso_or_image_path}"
            append = "--wait=-1"
            self.install_wait = True
        else:
            cdrom_line = ""
            append = "--noautoconsole"
            self.install_wait = False

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
            {append}
        """
        cmd = shlex.join(shlex.split(cmd))

        logger.info(f"Starting VM {self.config.name}")
        ret = self.hostconn.run(cmd)
        if ret.returncode != 0:
            logger.info(f"Finished starting VM {self.config.name}, cmd = {cmd}, ret = {ret}")
        else:
            logger.info(f"Finished starting VM {self.config.name} without any errors")
        return ret

    def start(self, iso_or_image_path: str, executor: ThreadPoolExecutor) -> None:
        self.future = executor.submit(self.setup_vm, iso_or_image_path)

    def has_booted(self) -> bool:
        if self.install_wait:
            # If the future is done an error probably happened.  Declare
            # successful "boot".  The real status is checked in the
            # health_check stage.
            if self.get_future_done():
                return True
            return self.hostconn.vm_is_running(self.config.name)
        return self.get_future_done()

    def post_boot(self, desired_ip_range: tuple[str, str]) -> bool:
        if not self.install_wait:
            self.future.result()
        return True

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


class X86ClusterNode(ClusterNode):
    external_port: str

    def __init__(self, config: NodeConfig, external_port: str):
        super().__init__(config)
        self.external_port = external_port

    def _boot_iso_x86(self, iso: str) -> host.Result:
        logger.info(f"trying to boot {self.config.node} using {iso}")

        lh = host.LocalHost()
        nfs = NFS(lh, self.external_port)

        bmc = BMC.from_bmc(self.config.bmc, self.config.bmc_user, self.config.bmc_password)
        h = host.HostWithBF2(self.config.node)

        iso = nfs.host_file(os.path.join(os.getcwd(), iso))
        bmc.boot_iso_redfish(iso)
        h.ssh_connect("core")
        logger.info("connected")
        return h.run("hostname")

    def start(self, iso_or_image_path: str, executor: ThreadPoolExecutor) -> None:
        self.future = executor.submit(self._boot_iso_x86, iso_or_image_path)

    def has_booted(self) -> bool:
        return self.get_future_done()

    def post_boot(self, desired_ip_range: tuple[str, str]) -> bool:
        rh = host.RemoteHost(self.config.node)
        rh.ssh_connect("core")
        ipr_entries = common.ipa_to_entries(rh.run("ip -json a").out)
        ips = []
        for ipr in ipr_entries:
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

    def __init__(self, config: NodeConfig, external_port: str):
        super().__init__(config)
        self.external_port = external_port

    def _boot_iso_bf(self, iso: str) -> host.Result:
        lh = host.LocalHost()
        nfs = NFS(lh, self.external_port)

        logger.info(f"Preparing BF on host {self.config.node}")
        bmc = BMC.from_bmc(self.config.bmc, self.config.bmc_user, self.config.bmc_password)
        h = host.HostWithBF2(self.config.node)
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
            bmc.boot_iso_redfish(nfs_file)
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
            ipa = h.run_on_bf("ip -json a").out
            detected = common.ipa_to_entries(ipa)
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

    def start(self, iso_or_image_path: str, executor: ThreadPoolExecutor) -> None:
        self.future = executor.submit(self._boot_iso_bf, iso_or_image_path)

    def has_booted(self) -> bool:
        return self.get_future_done()

    def post_boot(self, desired_ip_range: tuple[str, str]) -> bool:
        result: Optional[host.Result] = self.future.result()
        if result is not None:
            self.dynamic_ip = result.out
        else:
            logger.error_and_exit(f"Couldn't find ip of worker {self.config.name}")
        return True
