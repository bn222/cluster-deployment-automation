import dataclasses
import re
import os
import gspread
import tenacity
import typing
from typing import Optional
from collections.abc import Iterable
from collections.abc import Mapping
from oauth2client.service_account import ServiceAccountCredentials
from logger import logger
import common


SHEET = "ANL lab HW enablement clusters and connections"
URL = "https://docs.google.com/spreadsheets/d/1lXvcodJ8dmc_hcp0hzbPDU8t6-hCnAlEWFRdM2r_n0Q"
SCOPES = ("https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive")


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


def _read_gspread_sheet(cred_path: str) -> gspread.spreadsheet.Spreadsheet:
    try:
        credentials = ServiceAccountCredentials.from_json_keyfile_name(cred_path, SCOPES)
        file = gspread.auth.authorize(credentials)
        sheet = file.open(SHEET)
    except Exception as e:
        raise ValueError(f"Failure accessing google sheet: {e}. See https://docs.gspread.org/en/latest/oauth2.html#for-bots-using-service-account and share {repr(SHEET)} sheet ( {URL} )")
    return sheet


@tenacity.retry(wait=tenacity.wait_fixed(10), stop=tenacity.stop_after_attempt(5))
def _read_gspread_sheet_with_retry(cred_path: str) -> gspread.spreadsheet.Spreadsheet:
    return _read_gspread_sheet(cred_path)


def read_sheet(
    *,
    credentials: Optional[str | Iterable[str]] = None,
) -> list[dict[str, str]]:
    logger.info(f"Reading cluster information from sheet {repr(SHEET)} ( {URL} )")
    if credentials is None:
        cred_paths = _default_cred_paths()
    elif isinstance(credentials, str):
        cred_paths = [credentials]
    else:
        cred_paths = list(credentials)
    cred_path = None
    for e in cred_paths:
        if os.path.exists(e):
            cred_path = e
            break
    if cred_path is None:
        raise ValueError(f"Credentials not found in {cred_paths}")
    sheet = _read_gspread_sheet_with_retry(cred_path)
    sheet1 = sheet.sheet1
    return [{k: str(v) for k, v in record.items()} for record in sheet1.get_all_records()]


def load_all_cluster_info(
    *,
    credentials: Optional[str | Iterable[str]] = None,
    sheet: Optional[Iterable[Mapping[str, str]]] = None,
) -> dict[str, ClusterInfo]:
    if sheet is None:
        sheet = read_sheet(credentials=credentials)
    cluster = None
    ret = []
    for row in sheet:
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


def _get_cluster_info_desc(
    *,
    match_hostname: Optional[str] = None,
    match_name: Optional[str | re.Pattern[str]] = None,
) -> str:
    msg_selector = ""
    if match_hostname is not None:
        msg_selector += f" for host {repr(match_hostname)}"
    if match_name is not None:
        if msg_selector:
            msg_selector += " or"
        if isinstance(match_name, str):
            s = f"{repr(match_name)}"
        else:
            s = f" matching {repr(match_name.pattern)}"
        msg_selector += f" for cluster {s}"
    return f"cluster info{msg_selector}"


@typing.overload
def load_cluster_info(
    *,
    match_hostname: Optional[str] = None,
    try_plain_hostname: bool = True,
    match_name: Optional[str | re.Pattern[str]] = None,
    credentials: Optional[str | Iterable[str]] = None,
    cluster_infos: Optional[Mapping[str, ClusterInfo]] = None,
    validate: bool = True,
    required: typing.Literal[True],
) -> ClusterInfo:
    pass


@typing.overload
def load_cluster_info(
    *,
    match_hostname: Optional[str] = None,
    try_plain_hostname: bool = True,
    match_name: Optional[str | re.Pattern[str]] = None,
    credentials: Optional[str | Iterable[str]] = None,
    cluster_infos: Optional[Mapping[str, ClusterInfo]] = None,
    validate: bool = True,
    required: bool = True,
) -> Optional[ClusterInfo]:
    pass


def load_cluster_info(
    *,
    match_hostname: Optional[str] = None,
    try_plain_hostname: bool = True,
    match_name: Optional[str | re.Pattern[str]] = None,
    credentials: Optional[str | Iterable[str]] = None,
    cluster_infos: Optional[Mapping[str, ClusterInfo]] = None,
    validate: bool = True,
    required: bool = True,
) -> Optional[ClusterInfo]:
    if match_hostname is None and match_name is None:
        match_hostname = common.current_host()
    if cluster_infos is None:
        cluster_infos = load_all_cluster_info(credentials=credentials)

    cluster_info: Optional[ClusterInfo] = None

    if match_hostname:
        cluster_info = cluster_infos.get(match_hostname, None)

    if cluster_info is None:
        result_list: list[ClusterInfo] = []
        if try_plain_hostname and match_hostname is not None:
            if "." in match_hostname:
                hostname_part = match_hostname.split(".")[0]
            else:
                hostname_part = match_hostname

            def _match_hostname(ci_hostname: str) -> bool:
                if "." in ci_hostname and "." in match_hostname:
                    # Both hostnames are FQDN. We don't match by hostname alone.
                    return False
                return ci_hostname.startswith(hostname_part) and (len(ci_hostname) == len(hostname_part) or ci_hostname[len(hostname_part)] == ".")

            result_list.extend(ci for ci in cluster_infos.values() if _match_hostname(ci.provision_host))
        if match_name:

            def _match_name(name: str) -> bool:
                if isinstance(match_name, str):
                    return name == match_name
                return bool(match_name.search(name))

            result_list.extend(ci for ci in cluster_infos.values() if _match_name(ci.name))
        if len({ci.provision_host for ci in result_list}) == 1:
            cluster_info = result_list[0]

    if cluster_info is None:
        if required:
            msg = _get_cluster_info_desc(
                match_hostname=match_hostname,
                match_name=match_name,
            )
            raise RuntimeError(f"No {msg} found")
        return None

    if validate:
        validate_cluster_info(cluster_info)

    return cluster_info
