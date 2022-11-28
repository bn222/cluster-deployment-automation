from os import path
from sys import exit
from yaml import safe_load, safe_dump
import logging

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

    def print(self) -> None:
        print(safe_dump(self.fullConfig))

def main():
    pass

if __name__ is "__main__":
    main()


