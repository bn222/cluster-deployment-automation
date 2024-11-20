import sys
import os
import gspread
import typing
import threading
from oauth2client.service_account import ServiceAccountCredentials
from logger import logger


class ClusterInfo:
    def __init__(self, name: str):
        self.name = name
        self.provision_host = ""
        self.network_api_port = ""
        self.iso_server = ""
        self.organization_id = ""
        self.activation_key = ""
        self.bmc_imc_hostnames = []  # type: list[str]
        self.ipu_mac_addresses = []  # type: list[str]
        self.workers = []  # type: list[str]
        self.bmcs = []  # type: list[str]


def read_sheet() -> list[dict[str, str]]:
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
    file = gspread.auth.authorize(credentials)
    sheet = file.open("ANL lab HW enablement clusters and connections")
    sheet1 = sheet.sheet1
    return [{k: str(v) for k, v in record.items()} for record in sheet1.get_all_records()]


def load_all_cluster_info() -> dict[str, ClusterInfo]:
    cluster = None
    ret = []
    logger.info("loading cluster information")
    for row in read_sheet():
        if row["Name"].startswith("Cluster"):
            if cluster is not None:
                ret.append(cluster)
            cluster = ClusterInfo(row["Name"])
        if cluster is None:
            continue
        if "BF2" in row["Name"]:
            continue
        if row["Card type"] == "IPU-Cluster":
            cluster.bmc_imc_hostnames.append(row["BMC/IMC hostname"])
            cluster.ipu_mac_addresses.append(row["MAC"])
            cluster.iso_server = row["ISO server"]
            cluster.activation_key = row["Activation Key"]
            cluster.organization_id = row["Organization ID"]
        if row["Provision host"] == "yes":
            cluster.provision_host = row["Name"]
            cluster.network_api_port = row["Ports"]
        elif row["Provision host"] == "no":
            cluster.workers.append(row["Name"])
            bmc_host = row["BMC/IMC hostname"][8:] if "https://" in row["BMC/IMC hostname"] else row["BMC/IMC hostname"]
            cluster.bmcs.append(bmc_host)
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


class ClusterInfoLoader:
    def __init__(self, all_cluster_info: typing.Optional[dict[str, ClusterInfo]] = None) -> None:
        self._lock = threading.Lock()
        self._all_cluster_info = all_cluster_info

    def get_all(self) -> dict[str, ClusterInfo]:
        with self._lock:
            if self._all_cluster_info is None:
                self._all_cluster_info = load_all_cluster_info()
                logger.debug(f"all-cluster-info: {repr(self._all_cluster_info)}")
            return self._all_cluster_info

    @typing.overload
    def get(
        self,
        hostname: str,
        *,
        try_hostname: bool = True,
        required: typing.Literal[True],
    ) -> ClusterInfo:
        pass

    @typing.overload
    def get(
        self,
        hostname: str,
        *,
        try_hostname: bool = True,
        required: bool = False,
    ) -> typing.Optional[ClusterInfo]:
        pass

    def get(
        self,
        hostname: str,
        *,
        try_hostname: bool = True,
        required: bool = False,
    ) -> typing.Optional[ClusterInfo]:
        all_cluster_info = self.get_all()

        ci = all_cluster_info.get(hostname)
        if ci is None and try_hostname:
            # Also try without the FQDN.
            if "." in hostname:
                ci = all_cluster_info.get(hostname.split(".")[0])

        if ci is not None:
            return ci

        if required:
            raise ValueError(f"Cannot find cluster info for host {repr(hostname)}")

        return None
