import os
import json
from cdaConfig import CdaConfig


class StateFile:
    default_dict = {
        "pre-step": "offline",
        "masters": "offline",
        "workers": "offline",
        "post-step": "offline",
        "cluster-name": "",
    }
    state_dict: dict[str, str]

    def __init__(self, conf: CdaConfig):
        path: str
        if conf:
            os.makedirs(conf.state_file_dir, exist_ok=True)
            path = conf.state_file_dir + "state_file"
        else:
            path = "state_file"

        self.f = open(path, "a+")
        self.f.seek(0)

        stats = os.stat(path)
        if not stats.st_size:
            self.state_dict = self.default_dict
            self.write_dict_json()
        else:
            self.state_dict = self.to_dict()
        return

    def dinsert(self, name: str, value: str) -> None:
        self.state_dict[name] = value
        s = json.dumps(self.state_dict)
        self.write_json(s)
        self.f.flush()
        return

    def read(self) -> str:
        self.f.seek(0)
        s = self.f.read()
        return s

    def write_json(self, s: str) -> None:
        self.f.truncate(0)
        self.f.seek(0, os.SEEK_END)
        self.f.write(s)
        return

    def to_dict(self) -> dict[str, str]:
        d: dict[str, str] = json.loads(self.read())
        return d

    def not_deployed(self, name: str) -> bool:
        if self.state_dict[name] == "offline":
            return True
        else:
            return False

    def write_dict_json(self) -> None:
        s = json.dumps(self.state_dict)
        return

    def clear_state(self) -> None:
        self.f.truncate(0)
        self.state_dict = self.default_dict
        return

    def default_values(self) -> None:
        self.f.truncate(0)
        return

    def formatted(self) -> None:
        print("\nCluster Deployment State:")
        for key, value in self.state_dict.items():
            print(f"{key:12}: {value:}")
        return

    def __del__(self) -> None:
        self.f.close()
        return
