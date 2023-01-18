pip3 install --upgrade pip
dnf install -y rust coreos-installer
cat requirements.txt  | xargs -n1 pip3 install
