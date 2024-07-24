import host
from logger import logger

MODULAR_SERVICES = ["qemu", "interface", "network", "nodedev", "nwfilter", "secret", "storage"]
MODULAR_SOCKET_SUFFIXES = [".socket", "-ro.socket", "-admin.socket"]
MONOLITHIC_SOCKET_SUFFIXES = [".socket", "-ro.socket", "-admin.socket", "-tcp.socket", "-tls.socket"]


class Libvirt:
    """
    Wrapper on top of the Libvirt service.

    It can be running locally or remote.
    """

    hostconn: host.Host

    def __init__(self, h: host.Host) -> None:
        self.hostconn = h

    def configure(self) -> None:
        logger.info("Configuring Libvirt modules")

        # Stop and disable the monolithic Libvirt service
        self.hostconn.run_or_die("systemctl stop libvirtd.service")
        self._run_per_suffix("systemctl stop", "libvirtd", MONOLITHIC_SOCKET_SUFFIXES)
        self.hostconn.run_or_die("systemctl disable libvirtd.service")
        self._run_per_suffix("systemctl disable", "libvirtd", MONOLITHIC_SOCKET_SUFFIXES)

        for service in MODULAR_SERVICES:
            self.hostconn.run_or_die(f"systemctl enable virt{service}d.service")
            self._run_per_suffix("systemctl enable", f"virt{service}d", MODULAR_SOCKET_SUFFIXES)
            self._run_per_suffix("systemctl start", f"virt{service}d", MODULAR_SOCKET_SUFFIXES)

    def restart(self) -> None:
        for service in MODULAR_SERVICES:
            self.hostconn.run_or_die(f"systemctl restart virt{service}d.service")
            self._run_per_suffix("systemctl restart", f"virt{service}d", MODULAR_SOCKET_SUFFIXES)

    def _run_per_suffix(self, cmd: str, service: str, suffixes: list[str]) -> None:
        for suffix in suffixes:
            self.hostconn.run_or_die(f"{cmd} {service}{suffix}")
