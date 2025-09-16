import os
import shlex
import typing
import bmc
from clustersConfig import NodeConfig
from clusterNode import ClusterNode
import common
import host
from logger import logger
import coreosBuilder
from nfs import NFS


class MarvellBMC(bmc.BaseBMC):
    def __init__(
        self,
        bmc: bmc.BmcConfig,
        *,
        bmc_host: typing.Optional[bmc.BmcConfig] = None,
        get_external_port: typing.Optional[typing.Callable[[], str]] = None,
    ) -> None:
        assert (bmc_host is None) == (get_external_port is None)
        self.bmc = bmc
        self._bmc_host = bmc_host
        self._get_external_port = get_external_port

    def get_dpu_flavor(self) -> str:
        return "marvell"

    def _ssh_to_bmc(self, *, boot_coreos: bool = True) -> typing.Optional[host.Host]:
        # For Marvell DPU, the "BMC" is the host where the DPU is plugged in.
        #
        # That host also has the serial console of the DPU connected to
        # /dev/ttyUSB[01] and "eno4" is (by default) switched together with the
        # primary interface enP2p3s0 on the DPU.  This interface is also used
        # for pxeboot installation. See
        # https://github.com/wizhaoredhat/marvell-octeon-10-tools project.
        #
        # To access those interfaces, the host must be accessible via SSH.
        # This function returns a Host instance with SSH connected (usually
        # to the "core" user, use via sudo).
        #
        # If the host is not accessible, the function may first call _boot_coreos()
        # method, to boot a CoreOS Live image. For that, the host needs a separate
        # bmc_host (which is supposed to be a Redfish BMC of the host).
        rsh = host.RemoteHost(self.bmc.url)

        try:
            rsh.ssh_connect("core", timeout="2m")
        except Exception as e:
            logger.info(f"Cannot connect to core @ {self.bmc.url}: {e}")
        else:
            return rsh

        if self._bmc_host is None or not boot_coreos:
            # There is no fallback to boot a CoreOS Live ISO.
            return None

        self._boot_coreos()

        rsh = host.RemoteHost(self.bmc.url)
        rsh.ssh_connect("core", timeout="15m")
        return rsh

    def _boot_coreos(self) -> None:
        assert self._bmc_host
        assert self._get_external_port

        logger.info(f"For Marvell host {self.bmc.url} boot CoreOS Live via BMC {self._bmc_host.url}")

        coreosBuilder.ensure_fcos_exists()
        lh = host.LocalHost()
        nfs = NFS(lh, self._get_external_port())
        iso_url = nfs.host_file("/root/iso/fedora-coreos.iso")

        bmc2 = bmc.BMC.from_bmc_config(self._bmc_host)
        bmc2.boot_iso_redfish(iso_url)

    def is_marvell(self) -> bool:
        rsh = self._ssh_to_bmc()
        if rsh is None:
            return False
        return "177d:b900" in rsh.run("lspci -nn -d :b900").out

    def pxeboot(
        self,
        name: str,
        mac: str,
        ip: str,
        iso: str,
    ) -> None:
        rsh = self._ssh_to_bmc(boot_coreos=False)

        if rsh is None:
            raise RuntimeError(f"Cannot connect to {self.bmc.url} for pxeboot of Marvell DPU")

        ip_addr = f"{ip}/24"
        ip_gateway = common.ip_to_gateway(ip, "255.255.255.0")

        # An empty entry means to use the host's "id_ed25519.pub". We want that.
        ssh_keys = [""]
        for _, pub_key_content, _ in common.iterate_ssh_keys():
            ssh_keys.append(pub_key_content)

        ssh_key_options = [f"--ssh-key={shlex.quote(s)}" for s in ssh_keys]

        image = os.environ.get("CDA_MARVELL_TOOLS_IMAGE", "quay.io/sdaniele/marvell-tools:latest")

        logger.info(f"run pxeboot for {self.bmc.url} to install {image}")

        r = rsh.run(
            "set -o pipefail ; "
            "sudo "
            "podman "
            "run "
            "--pull always "
            "--rm "
            "--replace "
            "--privileged "
            "--pid host "
            "--network host "
            "--user 0 "
            "--name marvell-tools "
            "-i "
            "-v /:/host "
            "-v /dev:/dev "
            f"{shlex.quote(image)} "
            "./pxeboot.py "
            f"--dpu-name={shlex.quote(name)} "
            "--host-mode=coreos "
            f"--nm-secondary-cloned-mac-address={shlex.quote(mac)} "
            f"--nm-secondary-ip-address={shlex.quote(ip_addr)} "
            f"--nm-secondary-ip-gateway={shlex.quote(ip_gateway)} "
            "--yum-repos=rhel-nightly "
            "--default-extra-packages "
            "--octep-cp-agent-service-disable "
            f"{' '.join(ssh_key_options)} "
            f"{shlex.quote(iso)} "
            "2>&1 "
            "| tee \"/tmp/pxeboot-log-$(date '+%Y%m%d-%H%M%S')\""
        )
        if not r.success():
            raise RuntimeError(f"Failure to to pxeboot: {r}")


class MarvellClusterNode(ClusterNode):
    def __init__(self, node: NodeConfig, marvell_bmc: MarvellBMC) -> None:
        assert node.ip is not None
        assert node.bmc is not None
        self._name = node.name
        self._ip = node.ip
        self._mac = node.mac
        self._bmc = node.bmc
        self._marvell_bmc = marvell_bmc

    def start(self, install_iso: str) -> bool:
        self._marvell_bmc.pxeboot(self._name, self._mac, self._ip, install_iso)
        return True
