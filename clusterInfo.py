from typing import List
from typing import Dict
import sys
import os
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from logger import logger


class ClusterInfo:
    def __init__(self, name: str):
        self.name = name
        self.provision_host = ""
        self.network_api_port = ""
        self.workers = []  # type: List[str]
        self.bmcs = []  # type: List[str]


def read_sheet() -> List[List[str]]:
    logger.info("Downloading sheet from Google")
    scopes = ['https://www.googleapis.com/auth/spreadsheets', 'https://www.googleapis.com/auth/drive']
    cred_paths = [os.path.join(os.getcwd(), "credentials.json"), os.path.join(os.environ["HOME"], "credentials.json")]
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

    return [list(e.values()) for e in sheet.get_all_records()]


def load_all_cluster_info() -> Dict[str, ClusterInfo]:
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
            if "https://" in e[1]:
                cluster.bmcs.append(e[1][8:])
            else:
                cluster.bmcs.append(e[1])

    if cluster is not None:
        ret.append(cluster)
    return {x.provision_host: x for x in ret}


def validate_cluster_info(cluster_info: ClusterInfo) -> None:
    if cluster_info.provision_host == "":
        logger.info(f"Provision host missing for cluster {cluster_info.name}")
        sys.exit(-1)
    if cluster_info.network_api_port == "":
        logger.info(f"Network api port missing for cluster {cluster_info.name}")
        sys.exit(-1)
    for e in cluster_info.workers:
        if e == "":
            logger.info("Unnamed worker found for cluster {cluster_info.name}")
            sys.exit(-1)
    for e in cluster_info.bmcs:
        if e == "":
            logger.info("Unfilled IMPI address found for cluster {cluster_info.name}")
            sys.exit(-1)


def load_cluster_info(provision_host: str) -> ClusterInfo:
    all_cluster_info = load_all_cluster_info()
    for ci in all_cluster_info.values():
        validate_cluster_info(ci)
    return all_cluster_info[provision_host]
