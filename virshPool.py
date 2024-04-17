from dataclasses import dataclass
from typing import Optional

import host
from logger import logger


@dataclass(frozen=True)
class VirshPool:
    name: str
    rsh: host.Host
    image_path: Optional[str] = None

    def __str__(self) -> str:
        return f"{self.name}@{self.rsh.hostname()}"

    def rsh_run(self, cmd: str) -> host.Result:
        return self.rsh.run(cmd)

    def initialized(self) -> bool:
        cmd = f"virsh pool-info {self.name}"
        return self.rsh_run(cmd).success()

    def ensure_initialized(self) -> None:
        if not self.initialized():
            self.initialize()
        else:
            logger.info(f"virsh-pool[{self}]: Pool {self.name} already initialized (image-path={self.image_path})")

    def initialize(self) -> None:
        if not self.image_path:
            raise RuntimeError("The VirshPool is created without an image path and cannot be initialized")

        logger.info(f"virsh-pool[{self}]: Initializing pool {self.name} at {self.image_path}")
        self.rsh_run(f"virsh pool-define-as {self.name} dir - - - - {self.image_path}")
        self.rsh_run(f"mkdir -p {self.image_path}")
        self.rsh_run(f"chmod a+rw {self.image_path}")
        self.rsh_run(f"virsh pool-start {self.name}")
        logger.info(f"virsh-pool[{self}]: Pool initialized")

    def ensure_removed(self) -> None:
        if self.initialized():
            self.remove()

    def remove(self) -> None:
        self.rsh_run(f"virsh pool-destroy {self.name}")
        self.rsh_run(f"virsh pool-undefine {self.name}")
