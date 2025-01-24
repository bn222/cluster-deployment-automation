import dataclasses
import os
import gspread
import tenacity
from oauth2client.service_account import ServiceAccountCredentials
from logger import logger


SHEET = "ANL lab HW enablement clusters and connections"
URL = "https://docs.google.com/spreadsheets/d/1lXvcodJ8dmc_hcp0hzbPDU8t6-hCnAlEWFRdM2r_n0Q"


@dataclasses.dataclass(kw_only=True)
class ClusterInfo:
    name: str
    provision_host: str = ""
    network_api_port: str = ""
    iso_server: str = ""
    organization_id: str = ""
    activation_key: str = ""
    bmc_hostname: list[str] = dataclasses.field(default_factory=list)
    dpu_mac_addresses: list[str] = dataclasses.field(default_factory=list)
    workers: list[str] = dataclasses.field(default_factory=list)
    bmcs: list[str] = dataclasses.field(default_factory=list)


def _default_cred_paths() -> list[str]:
    paths = []
    cwd = os.getcwd()
    if cwd:
        paths.append(os.path.join(cwd, "credentials.json"))
    homedir = os.environ["HOME"]
    if homedir:
        paths.append(os.path.join(os.environ["HOME"], "credentials.json"))
        paths.append(os.path.join(os.environ["HOME"], ".config/gspread/credentials.json"))
    return paths


@tenacity.retry(wait=tenacity.wait_fixed(10), stop=tenacity.stop_after_attempt(5))
def read_sheet() -> list[dict[str, str]]:
    logger.info(f"Reading cluster information from sheet {repr(SHEET)} ( {URL} )")
    scopes = ['https://www.googleapis.com/auth/spreadsheets', 'https://www.googleapis.com/auth/drive']
    cred_paths = _default_cred_paths()
    cred_path = None
    for e in cred_paths:
        if os.path.exists(e):
            cred_path = e
            break
    try:
        if cred_path is None:
            raise ValueError(f"Credentials not found in {cred_paths}")
        credentials = ServiceAccountCredentials.from_json_keyfile_name(cred_path, scopes)
        file = gspread.auth.authorize(credentials)
        sheet = file.open(SHEET)
    except Exception as e:
        raise ValueError(f"Failure accessing google sheet: {e}. See https://docs.gspread.org/en/latest/oauth2.html#for-bots-using-service-account and share {repr(SHEET)} sheet ( {URL} )")
    sheet1 = sheet.sheet1
    return [{k: str(v) for k, v in record.items()} for record in sheet1.get_all_records()]


def load_all_cluster_info() -> dict[str, ClusterInfo]:
    cluster = None
    ret = []
    for row in read_sheet():
        if row["Name"].startswith("Cluster"):
            if cluster is not None:
                ret.append(cluster)
            cluster = ClusterInfo(name=row["Name"])
        if cluster is None:
            continue
        if row["Name"] == "Other servers":
            break
        if "BF2" in row["Name"]:
            continue
        if row["Card type"] == "IPU-Cluster":
            cluster.bmc_hostname.append(row["BMC/IMC hostname"])
            cluster.dpu_mac_addresses.append(row["MAC"])
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
        raise ValueError(f"Provision host missing for cluster {cluster_info.name}")
    if cluster_info.network_api_port == "":
        raise ValueError(f"Network api port missing for cluster {cluster_info.name}")
    for e in cluster_info.workers:
        if e == "":
            raise ValueError(f"Unnamed worker found for cluster {cluster_info.name}")
    for e in cluster_info.bmcs:
        if e == "":
            raise ValueError(f"Unfilled IMPI address found for cluster {cluster_info.name}")


def load_cluster_info(provision_host: str) -> ClusterInfo:
    all_cluster_info = load_all_cluster_info()
    for ci in all_cluster_info.values():
        validate_cluster_info(ci)
    return all_cluster_info[provision_host]
