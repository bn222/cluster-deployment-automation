# assumes venv was created with `python3.11 -m venv ocp-venv`
python -m ensurepip --upgrade
python -m pip install PyYAML --ignore-installed
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

cat requirements.txt  | xargs -n1 python -m pip install
