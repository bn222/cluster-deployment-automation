import base64
import json
import os
from dataclasses import dataclass
from typing import cast

from logger import logger


def encode_to_base64(input_string: str) -> str:
    input_bytes = input_string.encode('utf-8')
    encoded_bytes = base64.b64encode(input_bytes)
    return encoded_bytes.decode('utf-8')


def import_secret_path(secret_path: str) -> dict[str, dict[str, str]]:
    """Merges auths from secret_path into the existing auth.json at auth_path."""
    if not os.path.exists(secret_path):
        return {}

    try:
        with open(secret_path) as f:
            secret_data = json.load(f)
        return cast(dict[str, dict[str, str]], secret_data.get("auths", {}))
    except json.JSONDecodeError:
        logger.warning(f"Invalid JSON in secret: {secret_path}")
        return {}


@dataclass
class RegistryInfo:
    registry_url: str
    user: str
    token: str
    auth_path: str = "/run/user/0/containers/auth.json"

    def prep_auth(self) -> dict[str, dict[str, str]]:
        return {self.registry_url: {"auth": encode_to_base64(f"{self.user}:{self.token}")}}

    def inject_if_missing(self) -> None:
        """
        Inject this registry's auth into the given auth.json file, if not already present.
        """
        # Load existing auth.json
        if os.path.exists(self.auth_path):
            try:
                with open(self.auth_path, "r") as f:
                    auth_data = json.load(f)
            except json.JSONDecodeError:
                auth_data = {"auths": {}}
        else:
            auth_data = {"auths": {}}

        # Ensure the "auths" key exists
        if "auths" not in auth_data:
            auth_data["auths"] = {}

        # Only inject if not already present
        if self.registry_url not in auth_data["auths"]:
            logger.info(f"Injecting {self.registry_url} auth into {self.auth_path}")
            auth_data["auths"].update(self.prep_auth())
            os.makedirs(os.path.dirname(self.auth_path), exist_ok=True)
            with open(self.auth_path, "w") as f:
                json.dump(auth_data, f, indent=2)
