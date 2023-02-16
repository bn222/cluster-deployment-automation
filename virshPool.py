class VirshPool:
    def __init__(self, host, name: str, images_path: str):
        self._host = host
        self._name = name
        self._images_path = images_path

    def name(self) -> None:
        return self._name

    def images_path(self) -> None:
        return self._images_path

    def initialized(self) -> None:
        cmd = f"virsh pool-info {self._name}"
        return self._host.run(cmd).returncode == 0

    def ensure_initialized(self) -> None:
        if not self.initialized():
            self.initialize()
        else:
            print(f"Pool {self._name} already initialized")

    def remove(self) -> None:
        print(self._host.run(f"virsh pool-destroy {self._name}"))
        print(self._host.run(f"virsh pool-undefine {self._name}"))

    def ensure_removed(self) -> None:
        if self.initialized():
            self.remove()

    def initialize(self) -> None:
        print(f"Initializing pool {self._name} at {self._images_path}")
        print(self._host.run(f"virsh pool-define-as {self._name} dir - - - - {self._images_path}"))
        print(self._host.run(f"mkdir -p {self._images_path}"))
        print(self._host.run(f"chmod a+rw {self._images_path}"))
        print(self._host.run(f"virsh pool-start {self._name}"))
