from os import path, getcwd
import os
import io
import sys
import re
from typing import List
from typing import Dict
import jinja2
from yaml import safe_load
import gspread
from oauth2client.service_account import ServiceAccountCredentials
import host
from logger import logger


class ClusterInfo:
    def __init__(self, name: str):
        self.name = name
        self.provision_host = ""
        self.network_api_port = ""
        self.workers = []  # type: List[str]


def read_sheet() -> list:
    logger.info("Downloading sheet from Google")
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
        logger.info("Missing credentials.json while using templated config file")
        sys.exit(-1)
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
    def __init__(self, yamlPath: str):
        self._clusters = {}  # type: Dict[str, ClusterInfo]

        lh = host.LocalHost()
        # Run the hostname command and only take the first part. For example
        # "my-host.test.redhat.com" would return "my-host" here.
        # This is only required if we are using the Google sheets integration
        # to match the node name syntax in the spreadsheet.
        self._current_host = lh.run("hostname").out.strip().split(".")[0]

        if not path.exists(yamlPath):
            logger.error(f"could not find config in path: '{yamlPath}'")
            sys.exit(1)

        with open(yamlPath, 'r') as f:
            contents = f.read()
            # load it twice, so that self-reference becomes possible
            self.fullConfig = safe_load(io.StringIO(contents))
            contents = self._apply_jinja(contents)
            self.fullConfig = safe_load(io.StringIO(contents))

        # Some config may be left out from the yaml. Try to provide defaults.
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
                cc["version"] = "4.13.0-ec.3"
            if "external_port" not in cc:
                cc["external_port"] = "auto"
            if "network_api_port" not in cc:
                cc["network_api_port"] = "auto"

            if "hosts" not in cc:
                cc["hosts"] = []

            # creates hosts entries for each referenced node name
            all_nodes = cc["masters"] + cc["workers"]
            for n in all_nodes:
                if "disk_size" not in n:
                    n["disk_size"] = 48
                if "preallocated" not in n:
                    n["preallocated"] = True
                if "os_variant" not in n:
                    n["os_variant"] = "rhel8.6"

            node_names = set(x["name"] for x in cc["hosts"])
            for h in all_nodes:
                if h["node"] not in node_names:
                    cc["hosts"].append({"name": h["node"]})
                    node_names.add(h["node"])

            # Set default value for optional parameters for workers.
            for node in all_nodes:
                if "bmc_ip" not in node:
                    node["bmc_ip"] = None
                if "bmc_user" not in node:
                    node["bmc_user"] = "root"
                if "bmc_password" not in node:
                    node["bmc_password"] = "calvin"
                if "image_path" not in node:
                    base_path = f'/home/{cc["name"]}_guests_images'
                    qemu_img_name = f'{node["name"]}.qcow2'
                    node["image_path"] = os.path.join(base_path, qemu_img_name)
            for host_config in cc["hosts"]:
                if "network_api_port" not in host_config:
                    host_config["network_api_port"] = cc["network_api_port"]
                if "username" not in host_config:
                    host_config["username"] = "core"
                if "password" not in host_config:
                    host_config["password"] = None
                if "pre_installed" not in host_config:
                    host_config["pre_installed"] = "True"

    def autodetect_external_port(self):
        lh = host.LocalHost()
        self.__setitem__("external_port", lh.port_from_route("default"))

    def prepare_external_port(self):
        if self.__getitem__("external_port") == "auto":
            self.autodetect_external_port()

    def validate_external_port(self):
        extif = self.__getitem__("external_port")
        return host.LocalHost().port_exists(extif)

    def _apply_jinja(self, contents: str) -> str:
        def worker_number(a):
            self._ensure_clusters_loaded()
            name = self._clusters[self._current_host].workers[a]
            return re.sub("[^0-9]", "", name)

        def worker_name(a):
            self._ensure_clusters_loaded()
            return self._clusters[self._current_host].workers[a]

        def api_network():
            self._ensure_clusters_loaded()
            return self._clusters[self._current_host].network_api_port

        format_string = contents

        template = jinja2.Template(format_string)
        template.globals['worker_number'] = worker_number
        template.globals['worker_name'] = worker_name
        template.globals['api_network'] = api_network

        kwargs = {}
        kwargs["cluster_name"] = self.fullConfig["clusters"][0]["name"]

        t = template.render(**kwargs)
        return t

    def _ensure_clusters_loaded(self) -> None:
        if self._clusters:
            return
        self._clusters = self._load_clusters()
        self._validate_clusters()

    def _load_clusters(self) -> Dict[str, ClusterInfo]:
        cluster = None
        ret = []
        logger.info("loading cluster information")
        for e in read_sheet():
            if e[0].startswith("Cluster"):
                if cluster is not None:
                    ret.append(cluster)
                cluster = ClusterInfo(e[0])
            if cluster is None:
                continue
            if e[0].startswith("BF2"):
                continue
            if e[7] == "yes":
                cluster.provision_host = e[0]
                cluster.network_api_port = e[3]
            elif e[7] == "no":
                cluster.workers.append(e[0])
        ret.append(cluster)
        return {x.provision_host: x for x in ret}

    def _validate_clusters(self) -> None:
        for _, v in self._clusters.items():
            if v.provision_host == "":
                logger.info(f"Provision host missing for cluster {v.name}")
                sys.exit(-1)
            if v.network_api_port == "":
                logger.info(f"Network api port missing for cluster {v.name}")
                sys.exit(-1)
            for e in v.workers:
                if e == "":
                    logger.info("Unnamed worker found for cluster {c.name}")
                    sys.exit(-1)

    def __getitem__(self, key):
        return self.fullConfig["clusters"][0][key]

    def __setitem__(self, key, value) -> None:
        self.fullConfig["clusters"][0][key] = value

    def all_nodes(self) -> list:
        return self["masters"] + self["workers"]

    def all_hosts(self) -> list:
        return self["hosts"]

    def all_vms(self) -> list:
        return [x for x in self.all_nodes() if x["type"] == "vm"]

    def worker_vms(self) -> list:
        return [x for x in self["workers"] if x["type"] == "vm"]

    def master_vms(self) -> list:
        return [x for x in self["masters"] if x["type"] == "vm"]

    def local_vms(self) -> list:
        return [x for x in self.all_vms() if x["node"] == "localhost"]

    def is_sno(self) -> bool:
        return len(self["masters"]) == 1 and len(self["workers"]) == 0


def main():
    pass


if __name__ == "__main__":
    main()
