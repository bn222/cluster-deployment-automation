import json
import subprocess

def establish_ssh_connectivity():
    node_ip_address_list = []
    command = ["oc", "get", "nodes", "-o", "json"]
    node_output=subprocess.check_output(command)

    node_map=json.loads(node_output)
    for item in node_map["items"]:
        if "node-role.kubernetes.io/control-plane" in item["metadata"]["labels"]:
            node_ip_address_list.append(item["status"]["addresses"][0]["address"])

    for node_ip_address in node_ip_address_list:
        command = ["ssh", "-o", "StrictHostKeyChecking=no", f"core@{node_ip_address}", "true"]
        print(subprocess.run(command))


def get_cp_names():
    node_name_list = []
    command = ["oc", "get", "nodes", "-o", "json"]
    node_output=subprocess.check_output(command)

    node_map=json.loads(node_output)
    for item in node_map["items"]:
        if "node-role.kubernetes.io/control-plane" in item["metadata"]["labels"]:
            node_name_list.append(item["metadata"]["name"])
    return node_name_list

def backup_cluster(true_master_node):
    try:
        command = ["oc", "debug", f"node/{true_master_node}", "--", "chroot", "/host", "/bin/bash", "/usr/local/bin/cluster-backup.sh","/home/core/assets/backup"]
        print(subprocess.run(command))
    except:
        print("backup failed")

establish_ssh_connectivity()
node_list=get_cp_names()
backup_cluster(node_list[0])

with open("backup_output.metadata", "w") as metadata_file:
    for node in node_list:
        metadata_file.write(f"{node}\n")

