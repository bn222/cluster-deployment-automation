import sys

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
            print(f"Pool {self._name} already initialized on {self._host._hostname}")

    def remove(self) -> None:
        r = self._host.run(f"virsh pool-destroy {self._name}")
        print("\t" + r.err if r.err else "\t" + r.out)
        r = self._host.run(f"virsh pool-undefine {self._name}")
        print("\t" + r.err if r.err else "\t" + r.out)

    def ensure_removed(self) -> None:
        if self.initialized():
            self.remove()

    def initialize(self) -> None:
        print(f"\tInitializing pool {self._name} at {self._images_path}")
        ret = self._host.run(f"virsh pool-define-as {self._name} dir - - - - {self._images_path}")
        if ret.returncode == 0:
            ret = self._host.run(f"mkdir -p {self._images_path}")
        if ret.returncode == 0:
            ret = self._host.run(f"chmod a+rw {self._images_path}")
        if ret.returncode == 0:
            ret = self._host.run(f"virsh pool-start {self._name}")
        if ret.returncode != 0:
            print(f"\tUnable to initialize pool {self._name}: {ret.err}")
            sys.exit(-1)
