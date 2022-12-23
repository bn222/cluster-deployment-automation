from os import path, getcwd
from sys import exit
from yaml import safe_load, safe_dump
import logging
import os

logging.basicConfig(level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s', datefmt='%H:%M:%S'
)

class ClustersConfig():
    def __init__(self, yamlPath):
        if not path.exists(yamlPath):
            logging.error(f"could not find config in path: '{yamlPath}'")
            exit(1)

        with open(yamlPath, 'r') as f:
            self.fullConfig = safe_load(f)

        for cc in self.fullConfig["clusters"]:
            if "masters" not in cc:
                cc["masters"] = []
            if "workers" not in cc:
                cc["workers"] = []
            if "kubeconfig" not in cc:
                cc["kubeconfig"] = path.join(getcwd(), f'kubeconfig.{cc["name"]}')
            if "preconfig" not in cc:
                cc["preconfig"] = ""
            if "version" not in cc:
                cc["version"] = "4.11.0-multi"
            if not cc["version"].endswith("-multi"):
                cc["version"] += "-multi"

    def print(self) -> None:
        print(safe_dump(self.fullConfig))

def main():
    pass

if __name__ is "__main__":
    main()


