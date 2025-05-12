import os
import json


class StateFile:
    default_dict = {
        "pre-step": "offline",
        "masters": "offline",
        "workers": "offline",
        "post-step": "offline",
    }

    def __init__(self, cluster_name: str, path: str) -> None:
        self.cluster_name = cluster_name
        self.path = path.normpath(path) + "/" + cluster_name

    def _load_state(self) -> dict[str, dict[str, str]]:
        if os.path.exists(self.path):
            with open(self.path, 'r') as f:
                return dict[str, dict[str, str]](json.load(f))
        else:
            return {}

    def _save_state(self, state: dict[str, dict[str, str]]) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, 'w') as f:
            f.write(json.dumps(state))

    def deployed(self, name: str) -> bool:
        state = self._load_state()
        return self.cluster_name in state and name in self.cluster_name and state[self.cluster_name][name] == "online"

    def clear_state(self) -> None:
        state = self._load_state()
        if self.cluster_name in state:
            del state[self.cluster_name]
        self._save_state(state)

    def __getitem__(self, key: str) -> str | None:
        state = self._load_state()
        if self.cluster_name not in state:
            state[self.cluster_name] = {}
        if key not in state[self.cluster_name]:
            state[self.cluster_name][key] = "offline"
        return state[self.cluster_name][key]

    def __setitem__(self, key: str, value: str) -> None:
        state = self._load_state()
        if self.cluster_name not in state:
            state[self.cluster_name] = {}
        state[self.cluster_name][key] = value
        self._save_state(state)

    def __str__(self) -> str:
        return json.dumps(self._load_state(), indent=4)
