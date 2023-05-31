import time
import os
import json
from ailib import AssistedClient
import requests
import common

class AssistedClientAutomation(AssistedClient):
    def __init__(self, url):
        super().__init__(url, quiet=True, debug=False)

    def cluster_exists(self, name: str) -> bool:
        return any(name == x["name"] for x in self.list_clusters())

    def ensure_cluster_deleted(self, name: str):
        print(f"Ensuring that cluster {name} is not present")
        while self.cluster_exists(name):
            try:
                self.delete_cluster(name)
            except Exception:
                print("failed to delete cluster, will retry..")
            time.sleep(5)

    def ensure_infraenv_created(self, name: str, cfg):
        if name not in map(lambda x: x["name"], self.list_infra_envs()):
            print(f"Creating infraenv {name}")
            self.create_infra_env(name, cfg)


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

    def wait_cluster_ready(self, cluster_name: str):
        print("Waiting for cluster state to be ready")
        cur_state = None
        while True:
            new_state = self.cluster_state(cluster_name)
            if new_state != cur_state:
                print(f"Cluster state schanged to {new_state}")
            cur_state = new_state
            if cur_state == "ready":
                break
            time.sleep(10)

    def cluster_state(self, cluster_name: str):
        cluster = list(filter(lambda e: e["name"] == cluster_name, self.list_clusters()))
        return cluster[0]["status"]

    def start_until_success(self, cluster_name: str):
        self.wait_cluster_ready(cluster_name)
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
                if common.ip_in_subnet(addr, "192.168.122.0/24"):
                    return addr
        return None

    def allow_add_workers(self, cluster_name: str) -> None:
        uuid = self.info_cluster(cluster_name).to_dict()["id"]
        requests.post(f"http://{self.url}/api/assisted-install/v2/clusters/{uuid}/actions/allow-add-workers")
