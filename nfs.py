import host
import os
import common
from logger import logger
from typing import Optional
import sys
import threading
import time


"""
NFS is needed in many cases to network mount the folder that contains
ISO files such that Red Fish Virtual Media managers can load the image.
"""

_lock = threading.Lock()


class NFS:
    def __init__(self, host: host.Host, port: str):
        self._host = host
        self._port = port
        pass

    def host_file(self, file: str) -> str:
        with _lock:
            dir_name = os.path.dirname(file)
            if not self._exists(dir_name):
                self._add(dir_name)
            self._export_fs()
            ip = self._ip()
            if ip is None:
                logger.error(f"Failed to get ip when hosting file {file} on nfs")
                sys.exit(-1)
            ret = f"{self._ip()}:{file}"
            return ret

    def _exists(self, dir_name: str) -> bool:
        exports = self._host.read_file("/etc/exports")
        return any(dir_name in x.split(" ")[0] for x in exports.split("\n"))

    def _add(self, dir_name: str) -> None:
        contents = self._host.read_file("/etc/exports")
        # Export options: ro for ISO hosting, insecure for BMC/iDRAC access
        export_line = f"{dir_name} *(ro,sync,no_root_squash,insecure,no_subtree_check)"
        self._host.write("/etc/exports", f"{contents}\n{export_line}")

    def _export_fs(self) -> None:
        self._host.run("systemctl enable nfs-server")
        self._configure_firewall()
        started_at = time.monotonic()
        while True:
            ret = self._host.run("systemctl restart nfs-server")
            if ret.success():
                break
            if time.monotonic() > started_at + 60:
                logger.error_and_exit(f"failed to `systemctl restart nfs-server`: {ret}")
            time.sleep(1)

    def _configure_firewall(self) -> None:
        """Configure firewall to allow NFS traffic."""
        # Check if firewalld is running
        ret = self._host.run("systemctl is-active firewalld")
        if not ret.success():
            logger.info("firewalld not active, skipping firewall configuration")
            return

        # Add NFS services to firewall
        nfs_services = ["nfs", "nfs3", "mountd", "rpc-bind"]
        for service in nfs_services:
            ret = self._host.run(f"firewall-cmd --query-service={service}")
            if not ret.success():
                logger.info(f"Adding {service} to firewall")
                self._host.run(f"firewall-cmd --add-service={service} --permanent")

        self._host.run("firewall-cmd --reload")

    def _ip(self) -> Optional[str]:
        return common.port_to_ip(self._host, self._port)
