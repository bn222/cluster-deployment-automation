from ailib import AssistedClient
import time
import os
import json
import ipaddress

def ip_in_subnet(addr, subnet) -> bool:
    return ipaddress.ip_address(addr) in ipaddress.ip_network(subnet)

class AssistedClientAutomation(AssistedClient):
    def __init__(self, url):
        super().__init__(url, quiet=True)

    def cluster_exists(self, name: str) -> bool:
        return any(name == x["name"] for x in self.list_clusters())

    def ensure_cluster_deleted(self, name: str):
        while self.cluster_exists(name):
            try:
                self.delete_cluster(name)
            except Exception:
                print("failed to delete cluster, will retry..")
                pass
            time.sleep(5)

    def ensure_infraenv_deleted(self, name: str):
        if name in map(lambda x: x["name"], self.list_infra_envs()):
            self.delete_infra_env(name)

    def download_iso_with_retry(self, infra_env: str):
        print(self.info_iso(infra_env, {}))
        print("Downloading iso (will retry if not ready)...")
        while True:
            try:
                self.download_iso(infra_env, os.getcwd())
                break
            except Exception:
                time.sleep(30)

    def start_until_success(self, cluster_name: str):
        print(f"Starting cluster {cluster_name} (will retry until success)")
        tries = 0
        while True:
            try:
                tries += 1
                self.start_cluster(cluster_name)
            except Exception:
                pass

            cluster = list(filter(lambda e: e["name"] == cluster_name, self.list_clusters()))
            status = cluster[0]["status"]

            if status == "installing":
                print(f"Cluster {cluster_name} is in state installing")
                break
            else:
                time.sleep(10)
        print(f"Took {tries} tries to start cluster {cluster_name}")

    def get_ai_host(self, name: str):
        for h in filter(lambda x: "inventory" in x, self.list_hosts()):
            rhn = h["requested_hostname"]
            if rhn == name:
                return h
        return None

    def get_ai_ip(self, name: str):
        ai_host = self.get_ai_host(name)
        if ai_host:
            inventory = json.loads(ai_host["inventory"])
            routes = inventory["routes"]

            default_nics = [x['interface'] for x in routes if x['destination'] == '0.0.0.0']
            for default_nic in default_nics:
                nic_info = next(nic for nic in inventory.get('interfaces') if nic["name"] == default_nic)
                addr = nic_info['ipv4_addresses'][0].split('/')[0]
                if ip_in_subnet(addr, "192.168.122.0/24"):
                    return addr
        return None

