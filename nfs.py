import host
import os
import common


"""
NFS is needed in many cases to network mount the folder that contains
ISO files such that Red Fish Virtual Media managers can load the image.
"""


class NFS:
    def __init__(self, host: host.Host, port: str):
        self._host = host
        self._port = port
        pass

    def host_file(self, file: str) -> str:
        dir_name = os.path.dirname(file)
        if not self._exists(dir_name):
            self._add(dir_name)
        self._export_fs()
        return f"{self._ip()}:{file}"

    def _exists(self, dir_name: str) -> bool:
        exports = self._host.read_file("/etc/exports")
        return any(dir_name in x.split(" ")[0] for x in exports.split("\n"))

    def _add(self, dir_name: str) -> None:
        contents = self._host.read_file("/etc/exports")
        self._host.write("/etc/exports", f"{contents}\n{dir_name}")

    def _export_fs(self) -> None:
        self._host.run("systemctl enable nfs-server")
        self._host.run("systemctl restart nfs-server")

    def _ip(self) -> str:
        return common.port_to_ip(self._host, self._port)
