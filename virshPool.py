from logger import logger


class VirshPool:
    def __init__(self, host, name: str, images_path: str):
        self._host = host
        self._name = name
        self._images_path = images_path

    def name(self) -> str:
        return self._name

    def images_path(self) -> str:
        return self._images_path

    def initialized(self) -> bool:
        cmd = f"virsh pool-info {self._name}"
        return self._host.run(cmd).returncode == 0

    def ensure_initialized(self) -> None:
        if not self.initialized():
            self.initialize()
        else:
            logger.info(f"Pool {self._name} already initialized")

    def remove(self) -> None:
        logger.info(self._host.run(f"virsh pool-destroy {self._name}"))
        logger.info(self._host.run(f"virsh pool-undefine {self._name}"))

    def ensure_removed(self) -> None:
        if self.initialized():
            self.remove()

    def initialize(self) -> None:
        def run_and_log(cmd):
            r = self._host.run(cmd)
            logger.debug(cmd)
            if r.returncode:
                logger.warn(f"Ran {cmd} and got error: {r}")

        logger.info(f"Initializing pool {self._name} at {self._images_path}")
        run_and_log(f"virsh pool-define-as {self._name} dir - - - - {self._images_path}")
        run_and_log(f"mkdir -p {self._images_path}")
        run_and_log(f"chmod a+rw {self._images_path}")
        run_and_log(f"virsh pool-start {self._name}")
        logger.info("Pool initialized")
