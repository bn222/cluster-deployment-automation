# from bmc import BMC
# import host
# from typing import Optional
# from nfs import NFS
# import paramiko
# import time
# from logger import logger
# import logging
# import sys
# 
# # use the x86 host as a BMC for BF. The most interesting function is
# # the one that boots an iso
# 
# 
# class BMCBF(BMC):
#     def __init__(self, host: host.Host, nfs: NFS, nfs_key: Optional[str] = None):
#         self.host = host
#         self.nfs_key = nfs_key
#         self.nfs = nfs
#         self._bf_ip: Optional[str] = None
# 
#     def boot_iso(self, iso_path: str) -> None:
#         self._ensure_host_booted()
#         ret = self._pxeboot(iso_path)
#         self._bf_ip = ret.out.strip().split("\n")[-1].strip()
# 
#     def bf_ip(self) -> str:
#         if self._bf_ip is None:
#             logger.error("Failed to get IP for BF, boot_iso not called")
#             sys.exit(-1)
#         return self._bf_ip
# 
#     def _ensure_host_booted(self) -> None:
#         skip_boot = False
#         if self.host.ping():
#             try:
#                 self.host.ssh_connect("core")
#                 skip_boot = self.host.running_fcos()
#             except paramiko.ssh_exception.AuthenticationException:
#                 logger.info("Authentication failed, will not be able to skip boot")
#         if skip_boot:
#             logger.info(f"Skipping booting {self.host.hostname()}, already booted with FCOS")
#         else:
#             nfs_file = self.nfs.host_file("/root/iso/fedora-coreos.iso")
#             # self.host.boot_iso(nfs_file)
#             time.sleep(10)
#             self.host.ssh_connect("core")
# 
#     def _run_in_container(self, cmd: str, interactive: bool = False) -> host.Result:
#         name = "bf"
#         setup = f"sudo podman run --pull always --replace --pid host --network host --user 0 --name {name} -dit --privileged -v /dev:/dev quay.io/bnemeth/bf"
#         r = self.host.run(setup, logging.DEBUG)
#         if r.returncode != 0:
#             return r
#         it = "-it" if interactive else ""
#         return self.host.run(f"sudo podman exec {it} {name} {cmd}")
# 
#     def _pxeboot(self, nfs_iso: str) -> host.Result:
#         cmd = "sudo killall python3"
#         self.host.run(cmd)
#         logger.info("starting pxe server and booting bf")
#         if self.nfs_key is not None:
#             cmd = f"/pxeboot {nfs_iso} -w {self.nfs_key}"
#         else:
#             logger.error("not implemented")
#         return self._run_in_container(cmd, True)
# 
#     def firmware_upgrade(self) -> host.Result:
#         logger.info("Upgrading firmware")
#         return self._run_in_container("/fwup")
# 
#     def firmware_defaults(self) -> host.Result:
#         logger.info("Setting firmware config to defaults")
#         return self._run_in_container("/fwdefaults")
# 
#     def set_mode(self, mode: str) -> host.Result:
#         return self._run_in_container(f"/set_mode {mode}")
# 
#     def get_mode(self) -> host.Result:
#         return self._run_in_container("/getmode")
# 
#     def firmware_version(self) -> host.Result:
#         return self._run_in_container("fwversion")
# 
#     def load_bfb(self) -> host.Result:
#         logger.info("Loading BFB image")
#         return self._run_in_container("/bfb")
