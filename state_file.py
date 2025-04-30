import os
import json


class StateFile:
    default_dict = {
        "cluster-name": "",
        "pre-step": "offline",
        "masters": "offline",
        "workers": "offline",
        "post-step": "offline",
    }

    def __init__(self, path: str) -> None:
        self.path = path
        if not os.path.exists(path):
            self.clear_state()
            dir = os.path.dirname(path)
            if dir != '':
                os.makedirs(dir, exist_ok=True)
        self["cluster-name"] = os.path.basename(path)

    def _load_state(self) -> dict[str, str]:
        with open(self.path, 'r') as f:
            return dict[str, str](json.load(f))

    def _save_state(self, state: dict[str, str]) -> None:
        with open(self.path, 'w') as f:
            f.write(json.dumps(state))

    def cluster_name(self) -> str:
        return self._load_state()["cluster-name"]

    def not_deployed(self, name: str) -> bool:
        return self._load_state()[name] == "offline"

    def clear_state(self) -> None:
        self._save_state(self.default_dict)

    def __getitem__(self, key: str) -> str | None:
        state = self._load_state()
        return state.get(key)

    def __setitem__(self, key: str, value: str) -> None:
        state = self._load_state()
        state[key] = value
        self._save_state(state)

    def formatted(self) -> None:
        print(json.dumps(self._load_state(), indent=4))
