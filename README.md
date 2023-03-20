# Cluster Deployment Automation
Automate deployment of OpenShift clusters in different configurations.
The main functionality is showcased below.  The distribution specific
steps assume a RHEL/Fedora based distribution is used.  Also, the
instructions below make the assumption that everything is run as root
from the repository root directory.

## Generate a ssh key
NOTE: starting with Fedora 33 RSA keys are considered not secure enough; use
ed25519 instead.

```
ssh-keygen -t ed25519 -a 64 -N '' -f ~/.ssh/id_ed25519
```

## Install required software and Python packages by starting a Python virtual environment
```
python -m venv ocp-venv
source ocp-venv/bin/activate
./dependencies.sh
systemctl enable libvirtd
```

## Configure qemu user an group to be root
```
sed -e 's/#\(user\|group\) = ".*"$/\1 = "root"/' -i /etc/libvirt/qemu.conf
systemctl restart libvirtd
```

## Activate and deactivate Python virtual environment
```
source ocp-venv/bin/activate
...
deactivate
```

## Generate a baremetal worker cluster configuration file (1)
```
cat > cluster.yaml << EOF
clusters:
  - name : "mycluster"
    api_ip: "192.168.122.99"
    ingress_ip: "192.168.122.101"
    masters:
    - name: "mycluster-master-1"
      type: "vm"
      node: "localhost"
      ip: "192.168.122.41"
    - name: "mycluster-master-2"
      type: "vm"
      node: "localhost"
      ip: "192.168.122.42"
    - name: "mycluster-master-3"
      type: "vm"
      node: "localhost"
      ip: "192.168.122.43"
    workers:
    - name: "mycluster-worker-1"
      type: "physical"
      node: "..."
      bmc_user: "root"
      bmc_password: "..."
EOF
```

## Generate a vm worker cluster configuration file (2)
```
cat > cluster.yaml << EOF
clusters:
  - name : "vm"
    api_ip: "192.168.122.99"
    ingress_ip: "192.168.122.101"
    kubeconfig: "/root/kubeconfig.vm"
    masters:
    - name: "vm-master-1"
      type: "vm"
      node: "localhost"
      ip: "192.168.122.141"
    - name: "vm-master-2"
      type: "vm"
      node: "localhost"
      ip: "192.168.122.142"
    - name: "vm-master-3"
      type: "vm"
      node: "localhost"
      ip: "192.168.122.143"
    workers:
    - name: "vm-worker-1"
      type: "vm"
      node: "localhost"
      ip: "192.168.122.144"
    - name: "vm-worker-2"
      type: "vm"
      node: "localhost"
      ip: "192.168.122.145"
EOF
```

## Generate a vm Single Node OpenShift (SNO) cluster configuration file (3)
```
cat > cluster.yaml << EOF
clusters:
  - name : "vm-sno"
    masters:
    - name: "sno-master"
      type: "vm"
      node: "localhost"
      ip: "192.168.122.41"
EOF
```

## Start the installation
```
source ocp-venv/bin/activate
python main.py cluster.yaml
deactivate
```

## Install the latest 4.x openshift-client (optional)
The scripts don't rely on the OpenShift Client (oc) being installed locally.
For a better user experience it might still be a good idea to install the
latest 4.x version:
```
pushd /tmp/
wget https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/openshift-client-linux.tar.gz
tar xf openshift-client-linux.tar.gz oc
rm openshift-client-linux.tar.gz
mv oc /usr/bin/oc
popd
```

## Set the kubeconfig after a successful installation
```
export KUBECONFIG=/root/kubeconfig.vm
```

We can now access the cluster, e.g.:

```
# oc get nodes
NAME          STATUS   ROLES                         AGE    VERSION
vm-master-1   Ready    control-plane,master,worker   4d1h   v1.25.4+77bec7a
vm-master-2   Ready    control-plane,master,worker   4d1h   v1.25.4+77bec7a
vm-master-3   Ready    control-plane,master,worker   4d1h   v1.25.4+77bec7a
vm-worker-1   Ready    worker                        4d1h   v1.25.4+77bec7a
vm-worker-2   Ready    worker                        4d1h   v1.25.4+77bec7a
```
