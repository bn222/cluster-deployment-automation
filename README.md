# Cluster Deployment Automation
Automate deployment of OpenShift clusters in different configurations.
The main functionality is showcased below.  The distribution specific
steps assume a RHEL/Fedora based distribution is used.  Also, the
instructions below make the assumption that everything is run as root
from the repository root directory.

## Generate a ssh key
NOTE: starting with Fedora 33 RSA keys are considered not secure enough; use
ed25519 instead.

```bash
ssh-keygen -t ed25519 -a 64 -N '' -f ~/.ssh/id_ed25519
```

## Install required software and Python packages by starting a Python virtual environment
NOTE: Requires Python3.11 or higher (run `dnf install -y python3.11`)
```bash
python3.11 -m venv ocp-venv
source ocp-venv/bin/activate
./dependencies.sh
systemctl enable libvirtd
usermod -a -G root qemu
```

## Activate and deactivate Python virtual environment
```bash
source ocp-venv/bin/activate
...
deactivate
```

## Generate a baremetal worker cluster configuration file (1)
```yaml
cat > cluster.yaml << EOF
clusters:
  - name : "mycluster"
    api_vip: "192.168.122.99"
    ingress_vip: "192.168.122.101"
    masters:
    - name: "mycluster-master-1"
      kind: "vm"
      node: "localhost"
      ip: "192.168.122.41"
    - name: "mycluster-master-2"
      kind: "vm"
      node: "localhost"
      ip: "192.168.122.42"
    - name: "mycluster-master-3"
      kind: "vm"
      node: "localhost"
      ip: "192.168.122.43"
    workers:
    - name: "mycluster-worker-1"
      kind: "physical"
      node: "..."
      bmc_user: "root"
      bmc_password: "..."
EOF
```

## Generate a vm worker cluster configuration file (2)
```yaml
cat > cluster.yaml << EOF
clusters:
  - name : "vm"
    api_vip: "192.168.122.99"
    ingress_vip: "192.168.122.101"
    kubeconfig: "/root/kubeconfig.vm"
    masters:
    - name: "vm-master-1"
      kind: "vm"
      node: "localhost"
      ip: "192.168.122.141"
    - name: "vm-master-2"
      kind: "vm"
      node: "localhost"
      ip: "192.168.122.142"
    - name: "vm-master-3"
      kind: "vm"
      node: "localhost"
      ip: "192.168.122.143"
    workers:
    - name: "vm-worker-1"
      kind: "vm"
      node: "localhost"
      ip: "192.168.122.144"
    - name: "vm-worker-2"
      kind: "vm"
      node: "localhost"
      ip: "192.168.122.145"
EOF
```

## Generate a cluster configuration file that uses OVN rebuilt from source (3)
```yaml
cat > cluster.yaml << EOF
clusters:
  - name : "vm"
    api_vip: "192.168.122.99"
    ingress_ip: "192.168.122.101"
    kubeconfig: "/root/kubeconfig.vm"
    masters:
    - name: "vm-master-1"
      kind: "vm"
      node: "localhost"
      ip: "192.168.122.141"
    - name: "vm-master-2"
      kind: "vm"
      node: "localhost"
      ip: "192.168.122.142"
    - name: "vm-master-3"
      kind: "vm"
      node: "localhost"
      ip: "192.168.122.143"
    workers:
    - name: "vm-worker-1"
      kind: "vm"
      node: "localhost"
      ip: "192.168.122.144"
    - name: "vm-worker-2"
      kind: "vm"
      node: "localhost"
      ip: "192.168.122.145"
    postconfig:
    - name: "ovn_custom"   # Rebuilds OVN from upstream ovn-org/ovn code.
    - name: "ovnk8s"       # Rolls out the ovn-k daemonset using the new image.
      image: "localhost/ovnk-custom-image:dev"
EOF
```

## Generate a vm Single Node OpenShift (SNO) cluster configuration file (4)
```yaml
cat > cluster.yaml << EOF
clusters:
  - name : "vm-sno"
    masters:
    - name: "sno-master"
      kind: "vm"
      node: "localhost"
      ip: "192.168.122.41"
EOF
```

## Start the installation
```bash
source ocp-venv/bin/activate
python cda.py cluster.yaml deploy
deactivate
```

## Install the latest 4.x openshift-client (optional)
The scripts don't rely on the OpenShift Client (oc) being installed locally.
For a better user experience it might still be a good idea to install the
latest 4.x version:
```bash
pushd /tmp/
wget https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/openshift-client-linux.tar.gz
tar xf openshift-client-linux.tar.gz oc
rm openshift-client-linux.tar.gz
mv oc /usr/bin/oc
popd
```

## Set the kubeconfig after a successful installation
```bash
export KUBECONFIG=/root/kubeconfig.vm
```

We can now access the cluster, e.g.:

```bash
# oc get nodes
NAME          STATUS   ROLES                         AGE    VERSION
vm-master-1   Ready    control-plane,master,worker   4d1h   v1.25.4+77bec7a
vm-master-2   Ready    control-plane,master,worker   4d1h   v1.25.4+77bec7a
vm-master-3   Ready    control-plane,master,worker   4d1h   v1.25.4+77bec7a
vm-worker-1   Ready    worker                        4d1h   v1.25.4+77bec7a
vm-worker-2   Ready    worker                        4d1h   v1.25.4+77bec7a
```
