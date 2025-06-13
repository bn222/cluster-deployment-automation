from concurrent.futures import Future
from typing import Optional
from auth import import_secret_path
from clustersConfig import ClustersConfig
from logger import logger
from clustersConfig import ExtraConfigArgs
import host
import os
import json


def ExtraConfigHostRegistry(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]

    auth_path = "/run/user/0/containers/auth.json"

    # Load existing data
    if os.path.exists(auth_path):
        with open(auth_path, "r") as f:
            try:
                auth_data = json.load(f)
            except json.JSONDecodeError:
                logger.warning(f"{auth_path} is invalid. Resetting.")
                auth_data = {"auths": {}}
    else:
        auth_data = {"auths": {}}

    # Merge pull secret
    if cfg.import_pull_secret:
        logger.info(f"Importing secrets_path: {cc.secrets_path}")
        auth_data["auths"].update(import_secret_path(cc.secrets_path))

    # Merge other user-defined registries
    if cfg.registries:
        logger.info(f"Preparing registries: {cfg.registries}")
        for r in cfg.registries:
            auth_data["auths"].update(r.prep_auth())

    # Write once
    os.makedirs(os.path.dirname(auth_path), exist_ok=True)
    with open(auth_path, "w") as f:
        json.dump(auth_data, f, indent=2)
