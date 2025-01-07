import host
from typing import Optional
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
        self._disable_monolithic()

        if not self._service_is_active("virtqemud.service"):
            self.hostconn.run_or_die("systemctl start virtqemud.service")

        for service in MODULAR_SERVICES:
            self._enable_modular(service)

    def restart(self, service: Optional[str] = None) -> None:
        if service is not None:
            self.hostconn.run_or_die(f"systemctl restart virt{service}d.service")
            self._run_per_suffix("systemctl start", f"virt{service}d", MODULAR_SOCKET_SUFFIXES)
            return

        for service in MODULAR_SERVICES:
            self.hostconn.run_or_die(f"systemctl restart virt{service}d.service")
            self._run_per_suffix("systemctl start", f"virt{service}d", MODULAR_SOCKET_SUFFIXES)

    def _disable_monolithic(self) -> None:
        if self._service_is_active("libvirtd.service") or self._service_is_enabled("libvirtd.service"):
            self.hostconn.run_or_die("systemctl stop libvirtd.service")
            self._run_per_suffix("systemctl stop", "libvirtd", MONOLITHIC_SOCKET_SUFFIXES)
            self.hostconn.run_or_die("systemctl disable libvirtd.service")
            self._run_per_suffix("systemctl disable", "libvirtd", MONOLITHIC_SOCKET_SUFFIXES)

    def _enable_modular(self, service: str) -> None:
        if not self._service_is_enabled(f"virt{service}d.service"):
            self.hostconn.run_or_die(f"systemctl enable virt{service}d.service")

        for suffix in MODULAR_SOCKET_SUFFIXES:
            socket_service = f"virt{service}d{suffix}"

            if not self._service_is_enabled(socket_service):
                self.hostconn.run_or_die(f"systemctl enable {socket_service}")

            if not self._service_is_active(socket_service):
                self.hostconn.run_or_die(f"systemctl start {socket_service}")

    def _run_per_suffix(self, cmd: str, service: str, suffixes: list[str]) -> None:
        for suffix in suffixes:
            self.hostconn.run_or_die(f"{cmd} {service}{suffix}")

    def _service_is_active(self, service: str) -> bool:
        return self.hostconn.run(f"systemctl is-active {service}").out.strip() == "active"

    def _service_is_enabled(self, service: str) -> bool:
        return self.hostconn.run(f"systemctl is-enabled {service}").out.strip() == "enabled"
