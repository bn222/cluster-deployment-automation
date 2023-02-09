class VirshPool:
    def __init__(self, host, name, images_path):
        self._host = host
        self._name = name
        self._images_path = images_path

    def name(self):
        return self._name

    def images_path(self):
        return self._images_path

    def initialized(self):
        cmd = f"virsh pool-info {self._name}"
        return self._host.run(cmd).returncode == 0

    def ensure_initialized(self):
        if not self.initialized():
            self.initialize()
        else:
            print(f"Pool {self._name} already initialized")

    def remove(self):
        print(self._host.run(f"virsh pool-destroy {self._name}"))
        print(self._host.run(f"virsh pool-undefine {self._name}"))

    def ensure_removed(self):
        if self.initialized():
            self.remove()

    def initialize(self):
        print(f"Initializing pool {self._name}")
        print(self._host.run(f"virsh pool-define-as {self._name} dir - - - - {self._images_path}"))
        print(self._host.run(f"mkdir -p {self._images_path}"))
        print(self._host.run(f"chmod a+rw {self._images_path}"))
        print(self._host.run(f"virsh pool-start {self._name}"))
