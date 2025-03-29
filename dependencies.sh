#!/bin/bash

set -e

if [ "$(which python)" = "$(pwd)/ocp-venv/bin/python" ]; then
    PYTHON_CMD="python"
else
    PYTHON_CMD="python3.11"
    # Install Python 3.11 if not using the virtual environment interpreter
    sudo dnf install -y python3.11
fi

$PYTHON_CMD -m ensurepip --upgrade
$PYTHON_CMD -m pip install PyYAML --ignore-installed

dnf install -y \
        bash-completion \
        cockpit-composer \
        composer-cli \
        coreos-installer \
        dhcp-server \
        dnsmasq \
        firewalld \
        git \
        golang-bin \
        libvirt \
        lorax \
        make \
        osbuild-composer \
        podman \
        qemu-img \
        qemu-kvm \
        rust \
        virt-install \
        virt-viewer \
        wget

systemctl enable osbuild-composer.socket cockpit.socket --now

cat requirements.txt  | xargs -n1 $PYTHON_CMD -m pip install

export PYTHON_CMD_FULL=$(which $PYTHON_CMD)
sudo -E $PYTHON_CMD_FULL $(which activate-global-python-argcomplete)
