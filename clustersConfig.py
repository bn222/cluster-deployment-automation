from os import path, getcwd
from sys import exit
from yaml import safe_load, safe_dump
import logging
import os
import io
import sys
import jinja2
import gspread
from oauth2client.service_account import ServiceAccountCredentials
import host
import re

logging.basicConfig(level=logging.INFO,
        format='%(asctime)s %(levelname)s: %(message)s', datefmt='%H:%M:%S'
)


class ClusterInfo:
    def __init__(self, name):
        self.name = name
        self.provision_host = ""
        self.workers = []


def read_sheet():
    print("Downloading sheet from Google")
    scopes = [
        'https://www.googleapis.com/auth/spreadsheets',
        'https://www.googleapis.com/auth/drive'
    ]
    cred_paths = [
        os.path.join(os.getcwd(), "credentials.json"),
        os.path.join(os.environ["HOME"], "credentials.json")
    ]
    cred_path = None
    for e in cred_paths:
        if os.path.exists(e):
            cred_path = e
    if cred_path is None:
        print("Missing credentials.json while using templated config file")
    credentials = ServiceAccountCredentials.from_json_keyfile_name(cred_path, scopes)
    file = gspread.authorize(credentials)
    sheet = file.open("ANL lab HW enablement clusters and connections")
    sheet = sheet.sheet1
    recs = sheet.get_all_records()
    ret = []

    for e in recs:
        ret.append(list(e.values()))
    return ret

class ClustersConfig():
    def __init__(self, yamlPath):
        self._clusters = None

        lh = host.LocalHost()
        self._current_host = lh.run("hostname").out.strip().split(".")[0]

        if not path.exists(yamlPath):
            logging.error(f"could not find config in path: '{yamlPath}'")
            exit(1)

        with open(yamlPath, 'r') as f:
            contents = f.read()
            # load it twice, so that self-reference becomes possible
            self.fullConfig = safe_load(io.StringIO(contents))
            contents = self._apply_jinja(contents)
            self.fullConfig = safe_load(io.StringIO(contents))

        for cc in self.fullConfig["clusters"]:
            if "masters" not in cc:
                cc["masters"] = []
            if "workers" not in cc:
                cc["workers"] = []
            if "kubeconfig" not in cc:
                cc["kubeconfig"] = path.join(getcwd(), f'kubeconfig.{cc["name"]}')
            if "preconfig" not in cc:
                cc["preconfig"] = ""
            if "postconfig" not in cc:
                cc["postconfig"] = ""
            if "version" not in cc:
                cc["version"] = "4.12.0-multi"
            if not cc["version"].endswith("-multi"):
                cc["version"] += "-multi"

            if "hosts" not in cc:
              cc["hosts"] = []

            # creates hosts entries for each referenced node name
            all_nodes = cc["masters"] + cc["workers"]
            node_names = set(x["name"] for x in cc["hosts"])
            for h in all_nodes:
              if h["node"] not in node_names:
                cc["hosts"].append({"name" : h["node"]})
                node_names.add(h["node"])

            # fill-in defaults value for required attributes on
            # all hosts
            for host_config in cc["hosts"]:
              if "images_path" not in host_config:
                host_config["images_path"] = "/home/guests_images"

    def _apply_jinja(self, contents):
        def worker_number(a):
            self._ensure_clusters_loaded()
            name = self._clusters[self._current_host].workers[a]
            return re.sub("[^0-9]", "", name)

        def worker_name(a):
            self._ensure_clusters_loaded()
            return self._clusters[self._current_host].workers[a]

        format_string = contents

        template = jinja2.Template(format_string)
        template.globals['worker_number'] = worker_number
        template.globals['worker_name'] = worker_name

        kwargs = {}
        kwargs["cluster_name"] = self.fullConfig["clusters"][0]["name"]

        t = template.render(**kwargs)
        return t

    def _ensure_clusters_loaded(self):
        if self._clusters is not None:
            return
        self._clusters = []

        cluster = None
        print("loading cluster information")
        for e in read_sheet():
            if e[0].startswith("Cluster"):
                if cluster is not None:
                    self._clusters.append(cluster)
                cluster = ClusterInfo(e[0])
            if cluster is None:
                continue
            if e[0].startswith("BF2"):
                continue
            if e[7] == "yes":
                cluster.provision_host = e[0]
            elif e[7] == "no":
                cluster.workers.append(e[0])
        self._clusters = {x.provision_host : x for x in self._clusters}

    def print(self) -> None:
        print(safe_dump(self.fullConfig))


def main():
    pass

if __name__ == "__main__":
    main()

