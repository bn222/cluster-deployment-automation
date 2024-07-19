import json
import subprocess
import time

TIMEOUT_DURATION = 600
max_retries = 300
retry_delay = 10

def get_cp_ip_addresses(get_only_master: bool):
    ip_list = []
    with open("backup_output.metadata", "r") as metadata_file:
        list_of_nodes = metadata_file.read().splitlines()
        true_master_node = list_of_nodes[0]
    
    command = ["oc", "get", "nodes", "-o", "json"]
    node_output=subprocess.check_output(command)

    node_map=json.loads(node_output)
    for item in node_map["items"]:
        should_get_result = False
        if get_only_master:
            should_get_result = item["metadata"]["name"] == true_master_node
        else:
            should_get_result = item["metadata"]["name"] != true_master_node
        if should_get_result:
            if "node-role.kubernetes.io/control-plane" in item["metadata"]["labels"]:
                control_plane_addresses= item["status"]["addresses"]
                for address in control_plane_addresses:
                    if address["type"] == "InternalIP":
                        cp_address= address["address"]
                        ip_list.append(cp_address)
    return list_of_nodes, ip_list

def mv_remote(ip_address, file_name):
    try:
        command = ["ssh","-o", "StrictHostKeyChecking=no", f"core@{ip_address}", "--", "sudo", "rm", "-rf", "/tmp/etcd/*"]
        print(subprocess.check_output(command))
    except: 
        print("etcd folder does not exist")
    try:
        command = ["ssh","-o", "StrictHostKeyChecking=no", f"core@{ip_address}", "--", "sudo", "mv", "-v", f"{file_name}", "/tmp"]
        print(subprocess.check_output(command))
    except:
        print("file does not exist")


def stop_kubectl_pods_node(ip_address):
    stop = True
    mv_remote(ip_address, "/etc/kubernetes/manifests/etcd-pod.yaml")
    check_pods_on_node(ip_address, stop, "etcd")
    mv_remote(ip_address, "/etc/kubernetes/manifests/kube-apiserver-pod.yaml")
    check_pods_on_node(ip_address, stop, "kube-apiserver")
    mv_remote(ip_address, "/var/lib/etcd/")

def restore_from_backup(ip_address_to_true_master):
    print("trying to restore from recovery node")
    try:
        command = ["ssh","-o", "StrictHostKeyChecking=no" ,f"core@{ip_address_to_true_master}", "--", "sudo", "-E", "/usr/local/bin/cluster-restore.sh", "/home/core/assets/backup"]
        print(subprocess.check_output(command))
    except:
        print("backup failed")

def check_nodes():
    try:
        result = subprocess.run(['oc', 'get', 'nodes'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode == 0:
            return True
        else:
            return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False


def wait_for_cluster(timeout_duration):
    start_time = time.time()
    while True:
        if check_nodes():
            break
        elif time.time() - start_time > timeout_duration:
            raise TimeoutError("The command timed out. The cluster is not ready.")
        else:
            print("Retrying in 10 seconds...")
            time.sleep(10)

def check_pods_on_node(ip_address, stop, type_of_pod):    
    command = ["ssh",  "-o", "StrictHostKeyChecking=no", f"core@{ip_address}","--", "sudo", "crictl", "ps"]

    output = subprocess.check_output(command).splitlines()
    reconstructed_string = ''

    for line in output:
        line = line.decode('utf-8')
        if f"{type_of_pod}" in line and "operator" not in line and f"{type_of_pod}-guard" not in line:
            reconstructed_string += f"{line.rstrip()}\n"
    if stop:
        print(f"checking to see if {type_of_pod} is stopped for {ip_address}")
        while reconstructed_string:
            output = subprocess.check_output(command).splitlines()
            reconstructed_string = ''

            for line in output:
                line = line.decode('utf-8')
                if f"{type_of_pod}" in line and "operator" not in line and f"{type_of_pod}-guard" not in line:
                    reconstructed_string += f"{line.rstrip()}\n"
            print(reconstructed_string)
            print(f"{type_of_pod} pods have not stopped for {ip_address}. Checking again")
            time.sleep(20)
    else:
        print("checking to see if {type_of_pod} is stopped for {ip_address}")
        while not reconstructed_string:
            output = subprocess.check_output(command).splitlines()
            reconstructed_string = ''

            for line in output:
                line = line.decode('utf-8')
                if f"{type_of_pod}" in line and "operator" not in line and f"{type_of_pod}-guard" not in line:
                    reconstructed_string += f"{line.rstrip()}\n"
            print(reconstructed_string)
            print(f"{type_of_pod} pods have not restarted for {ip_address}. Checking again")

def restart_kubelet(list_ssh_ip_addresses_non_true, ip_address_to_master):
    command = ["ssh","-o", "StrictHostKeyChecking=no", f"core@{ip_address_to_master}","--", "sudo", "systemctl", "restart", "kubelet.service"]
    print(subprocess.check_output(command))

    for ip_address_non_true in list_ssh_ip_addresses_non_true:
        command = ["ssh",  "-o", "StrictHostKeyChecking=no",f"core@{ip_address_non_true}","--", "sudo", "systemctl", "restart", "kubelet.service"]
        print(subprocess.check_output(command))

def get_pod_output():
    command = ["oc", "-n", "openshift-ovn-kubernetes", "get", "pod", "-l", "app=ovnkube-control-plane"]
    try:
        output = subprocess.check_output(command, text=True)
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error getting pod status: {e.output}")
        return None

def check_pod_status(output):
    lines = output.strip().split("\n")
    headers = lines[0].split()
    pod_lines = lines[1:]

    all_running = True

    for line in pod_lines:
        parts = line.split()
        pod_name = parts[0]
        ready_status = parts[1]
        status = parts[2]

        if ready_status != "2/2" or status != "Running":
            print(f"Pod {pod_name} is not in the correct state: READY={ready_status}, STATUS={status}")
            all_running = False

    return all_running


def ovn_k_master_restart():
    command = ["oc", "-n", "openshift-ovn-kubernetes", "delete", "pod", "-l", "app=ovnkube-control-plane"]
    print(subprocess.check_output(command))

    time.sleep(60)

    while True:
        pod_output = get_pod_output()
        if pod_output is not None:
            if check_pod_status(pod_output):
                print("All pods are in the 2/2 and Running state.")
                break
            else:
                print("Not all pods are in the 2/2 and Running state. Checking again...")
        else:
            print("Failed to get pod output. Retrying...")

        time.sleep(5)  # Wait for 5 seconds before checking again

def get_ovnk_pod_output(node):
    command = ["oc", "-n", "openshift-ovn-kubernetes", "get", "pod", "-l", "app=ovnkube-node", f"--field-selector=spec.nodeName=={node}"]

    try:
        output = subprocess.check_output(command, text=True)
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error getting pod status: {e.output}")
        return None

def ovnk_check_pod_status(pod_status):
    lines = pod_status.strip().split("\n")
    headers = lines[0].split()
    pod_lines = lines[1:]

    all_running = True

    for line in pod_lines:
        parts = line.split()
        pod_name = parts[0]
        ready_status = parts[1]
        status = parts[2]

        if ready_status != "8/8" or status != "Running":
            print(f"Pod {pod_name} is not in the correct state: READY={ready_status}, STATUS={status}")
            all_running = False

    return all_running

    

def check_ovn_k_pod(node_name):
    while True:
        pod_output = get_ovnk_pod_output(node_name)
        if pod_output is not None:
            if ovnk_check_pod_status(pod_output):
                print(f"All pods are in the 8/8 and Running state for {node_name}.")
                break
            else:
                print(f"Not all pods are in the 8/8 and Running state for {node_name}. Checking again...")
        else:
            print("Failed to get pod output. Retrying...")

        time.sleep(5)  # Wait for 5 seconds before checking again

    

def ovn_k_restart(node_map):
    for node, ip_address in node_map.items(): 
        command = ["ssh","-o", "StrictHostKeyChecking=no", f"core@{ip_address}","--", "sudo", "rm", "-f", "/var/lib/ovn-ic/etc/*.db"]
        print(subprocess.check_output(command))

        command = ["ssh","-o", "StrictHostKeyChecking=no", f"core@{ip_address}","--", "sudo", "systemctl", "restart", "ovs-vswitchd ovsdb-server"]
        print(subprocess.check_output(command))


        command = ["oc", "-n", "openshift-ovn-kubernetes", "delete", "pod", "-l", "app=ovnkube-node", f"--field-selector=spec.nodeName=={node}"]
        print(subprocess.check_output(command))

        time.sleep(60)

        check_ovn_k_pod(node)

def turning_quorum_guard_off():
    command = ["oc", "patch", "etcd/cluster", "--type", "merge", "-p", '{"spec": {"unsupportedConfigOverrides": {"useUnsupportedUnsafeNonHANonProductionUnstableEtcd": true}}}']
    print(subprocess.check_output(command))

def patching_etcd_cluster():
    list_of_components = ["kubecontrollermanager", "kubeapiserver", "kubescheduler"]
    
    for component in list_of_components:
        command = ["oc", "patch", f"{component}", "cluster", "-p", '{"spec": {"forceRedeploymentReason": "recovery-'"$( date --rfc-3339=ns )"'"}}', "--type", "merge"]
        print(subprocess.check_output(command))

def get_co_output(component):
    command = ["oc", "get", "co", f"{component}"]
    try:
        output = subprocess.check_output(command, text=True)
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error getting cluster operator status: {e.output}")
        return None

def check_component(co_output, component):
    lines = co_output.strip().split('\n')
    
    for line in lines[1:]:
        columns = list(filter(bool, line.strip().split(" ")))

        name = columns[0]
        available = columns[2] == 'True'
        progressing = columns[3] == 'False'
        degraded = columns[4] == 'False'

        if name == component:
            in_desired_state = available and progressing and degraded
            return in_desired_state
    
    return False

def check_components_status(components, timeout):
    for component in components:
        while True:
            start_time = time.time()
            co_output = get_co_output(component)
            if check_component(co_output, component):
                print(f"Component {component} are in the desired state.")
                break
            else:
                print(f"Component {component} is not in the desired state")

            if time.time() - start_time > timeout:
                print("Timeout reached. Components did not reach the desired state.")
                break

            time.sleep(5)

get_only_master = False
list_of_nodes, list_ssh_ip_addresses_non_true= get_cp_ip_addresses(get_only_master)
get_only_master = True
list_of_nodes, list_ssh_ip_addresses_true= get_cp_ip_addresses(get_only_master)

node_name_to_ip = {f'{list_of_nodes[0]}': f'{list_ssh_ip_addresses_true[0]}'}

for node, ssh_ip_address_non_true in zip(list_of_nodes[1:], list_ssh_ip_addresses_non_true):
    node_name_to_ip[f'{node}'] = ssh_ip_address_non_true

for ip_address in list_ssh_ip_addresses_non_true:
    stop_kubectl_pods_node(ip_address)

restore_from_backup(list_ssh_ip_addresses_true[0])

try:
    wait_for_cluster(TIMEOUT_DURATION)
    print("The cluster is up and running. The command completed successfully.")
except TimeoutError as e:
    print(e)
except Exception as e:
    print(f"An unexpected error occurred: {e}")

restart_kubelet(list_ssh_ip_addresses_non_true, list_ssh_ip_addresses_true[0])
ovn_k_master_restart()

ovn_k_restart(node_name_to_ip)

restart_kubelet(list_ssh_ip_addresses_non_true, list_ssh_ip_addresses_true[0])
turning_quorum_guard_off()

patching_etcd_cluster()

components_to_check = ['etcd', "kube-apiserver", "kube-controller-manager", "kube-scheduler"]
timeout = 600
check_components_status(components_to_check, timeout)

print("cluster restored")

