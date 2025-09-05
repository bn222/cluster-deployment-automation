import os
import shlex
import typing
from clustersConfig import NodeConfig
from bmc import BMC
from bmc import BmcConfig
import common
import host
from logger import logger
import coreosBuilder
from nfs import NFS


def marvell_bmc_rsh(
    bmc: BmcConfig,
    *,
    bmc_host: typing.Optional[BmcConfig] = None,
    get_external_port: typing.Optional[typing.Callable[[], str]] = None,
) -> typing.Optional[host.Host]:
    # For Marvell DPU, we require that our "BMC" is the host on has the DPU
    # plugged in.
    #
    # We also assume, that the user name is "core" and that we can SSH into
    # that host with public key authentication. We ignore the `bmc.user`
    # setting. The reason for that is so that dpu-operator's
    # "hack/cluster-config/config-dpu.yaml" (which should work with IPU and
    # Marvell DPU) does not need to specify different BMC user name and
    # passwords. If you solve how to express the BMC authentication in the
    # cluster config in a way that is suitable for IPU and Marvell DPU at the
    # same time (e.g. via Jinja2 templates), we can start honoring
    # bmc.user/bmc.password.
    rsh = host.RemoteHost(bmc.url)

    try:
        rsh.ssh_connect("core", timeout="2m")
    except Exception as e:
        logger.info(f"Cannot connect to core @ {bmc.url}: {e}")
    else:
        return rsh

    if bmc_host is None:
        return None

    assert get_external_port

    logger.info(f"For Marvell host {bmc.url} boot CoreOS Live via BMC {bmc_host.url}")

    coreosBuilder.ensure_fcos_exists()
    lh = host.LocalHost()
    nfs = NFS(lh, get_external_port())
    iso_url = nfs.host_file("/root/iso/fedora-coreos.iso")

    BMC.from_bmc_config(bmc_host).boot_iso_redfish(iso_url)

    rsh.ssh_connect("core", timeout="15m")
    return rsh


def is_marvell(
    bmc: BmcConfig,
    *,
    bmc_host: typing.Optional[BmcConfig] = None,
    get_external_port: typing.Optional[typing.Callable[[], str]] = None,
) -> bool:
    rsh = marvell_bmc_rsh(
        bmc,
        bmc_host=bmc_host,
        get_external_port=get_external_port,
    )
    if rsh is None:
        return False
    return "177d:b900" in rsh.run("lspci -nn -d :b900").out


def _pxeboot_marvell_dpu(name: str, bmc: BmcConfig, mac: str, ip: str, iso: str) -> None:
    rsh = marvell_bmc_rsh(bmc)

    if rsh is None:
        raise RuntimeError(f"Cannot connect to {bmc.url} for pxeboot of Marvell DPU")

    ip_addr = f"{ip}/24"
    ip_gateway = common.ip_to_gateway(ip, "255.255.255.0")

    # An empty entry means to use the host's "id_ed25519.pub". We want that.
    ssh_keys = [""]
    for _, pub_key_content, _ in common.iterate_ssh_keys():
        ssh_keys.append(pub_key_content)

    ssh_key_options = [f"--ssh-key={shlex.quote(s)}" for s in ssh_keys]

    image = os.environ.get("CDA_MARVELL_TOOLS_IMAGE", "quay.io/sdaniele/marvell-tools:latest")

    logger.info(f"run pxeboot via {image}")

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


def MarvellIsoBoot(node: NodeConfig, iso: str) -> None:
    assert node.ip is not None
    assert node.bmc is not None
    _pxeboot_marvell_dpu(node.name, node.bmc, node.mac, node.ip, iso)


def main() -> None:
    pass


if __name__ == "__main__":
    main()
