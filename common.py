import json


def first(ll, x):
    return next(filter(ll, x))

def extract_ip(ipa: dict, port_name: str) -> str:
    interface = first(lambda x: x["ifname"] == port_name, ipa)
    inet = first(lambda x: x["family"] == "inet", interface["addr_info"])
    return inet["local"]

def extract_port(ipr: dict, route: str) -> str:
   rt = first(lambda x: x["dst"] == route, ipr)
   return rt["dev"]
