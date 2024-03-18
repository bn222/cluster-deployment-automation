#!/bin/bash

set -e

if [ -n "$PYTHON_CMD" ] ; then
    :
elif [ "$(which python)" = "$(pwd)/ocp-venv/bin/python" ]; then
    PYTHON_CMD="python"
else
    PYTHON_CMD="python3.11"
    # Install Python 3.11 if not using the virtual environment interpreter
    sudo dnf install -y python3.11
fi

$PYTHON_CMD -m ensurepip --upgrade
$PYTHON_CMD -m pip install PyYAML --ignore-installed

cat <<EOF | sudo tee /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://pkgs.k8s.io/core:/stable:/v1.29/rpm/
enabled=1
gpgcheck=1
gpgkey=https://pkgs.k8s.io/core:/stable:/v1.29/rpm/repodata/repomd.xml.key
#exclude=kubelet kubeadm kubectl cri-tools kubernetes-cni
EOF

dnf install -y wget rust coreos-installer kubectl libvirt podman qemu-img qemu-kvm virt-install make git golang-bin virt-viewer osbuild-composer composer-cli cockpit-composer bash-completion firewalld lorax

systemctl enable osbuild-composer.socket cockpit.socket --now

if ! command -v -- oc; then
    export OPENSHIFT_CLIENT_TOOLS_URL=https://mirror.openshift.com/pub/openshift-v4/$(uname -m)/clients/ocp/stable/openshift-client-linux.tar.gz
    curl $OPENSHIFT_CLIENT_TOOLS_URL | sudo tar -U -C /usr/local/bin -xzf -
fi

cat requirements.txt  | xargs -n1 $PYTHON_CMD -m pip install

sudo activate-global-python-argcomplete
