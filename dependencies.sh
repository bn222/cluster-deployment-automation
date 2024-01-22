#!/bin/bash

if [ "$(which python)" = "$(pwd)/ocp-venv/bin/python" ]; then
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
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-\$basearch
enabled=1
gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOF

dnf install -y wget rust coreos-installer kubectl libvirt podman qemu-img qemu-kvm virt-install make git golang-bin virt-viewer

if ! command -v -- oc; then
    export OPENSHIFT_CLIENT_TOOLS_URL=https://mirror.openshift.com/pub/openshift-v4/$(uname -m)/clients/ocp/stable/openshift-client-linux.tar.gz
    curl $OPENSHIFT_CLIENT_TOOLS_URL | sudo tar -U -C /usr/local/bin -xzf -
fi

cat requirements.txt  | xargs -n1 $PYTHON_CMD -m pip install
