import json


def first(ll, x):
    return next(filter(ll, x))


def extract_ip(jsonipa: str, port_name: str) -> str:
    ipa = json.loads(jsonipa)
    interface = first(lambda x: x["ifname"] == port_name, ipa)
    inet = first(lambda x: x["family"] == "inet", interface["addr_info"])
    return inet["local"]
