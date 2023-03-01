pip3 install --upgrade pip
cat <<EOF | sudo tee /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-\$basearch
enabled=1
gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOF
dnf install -y rust coreos-installer kubectl libvirt podman qemu virt-install
cat requirements.txt  | xargs -n1 pip3 install
