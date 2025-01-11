from concurrent.futures import Future
from typing import Optional, Any, Dict
from k8sClient import K8sClient
from logger import logger
from clustersConfig import ClustersConfig
from clustersConfig import ExtraConfigArgs
import host
import yaml
import time
import sys


def early_access_microshift() -> str:
    return """[microshift-latest-4.16]
name=MicroShift latest-4.16 EarlyAccess EC or RC RPMs
baseurl=https://mirror.openshift.com/pub/openshift-v4/aarch64/microshift/ocp-dev-preview/latest-4.16/el9/os/
enabled=1
gpgcheck=0
skip_if_unavailable=0


[microshift-latest-4.16-dependencies]
name=OpenShift Dependencies
baseurl=https://mirror.openshift.com/pub/openshift-v4/aarch64/dependencies/rpms/4.16-el9-beta/
enabled=1
gpgcheck=0
skip_if_unavailable=0

[microshift-4.13-dependencies]
name=Openshift 4.13 Dependencies
baseurl=https://mirror.openshift.com/pub/openshift-v4/aarch64/dependencies/rpms/4.13-el9-beta/
enabled=1
gpgcheck=0
skip_if_unavailable=0
"""


def read_prep_microshift_kubeconfig(acc: host.Host) -> str:
    kubeconfig_path = "/var/lib/microshift/resources/kubeadmin/kubeconfig"
    kubeconfig: Dict[str, Any] = yaml.safe_load(acc.read_file(kubeconfig_path))
    kubeconfig["clusters"][0]["cluster"]["insecure-skip-tls-verify"] = True
    kubeconfig["clusters"][0]["cluster"]["server"] = f"https://{acc.hostname()}:6443"
    to_write: str = yaml.dump(kubeconfig)
    key = "certificate-authority-data"
    to_write = to_write.replace(f"{key}:", f"# {key}:")
    return to_write


def write_microshift_kubeconfig(contents: str, rh: host.Host) -> str:
    path = "/root/kubeconfig.microshift"
    rh.write(path, contents)
    return path


def masquarade(rsh: host.Host, cc: ClustersConfig) -> None:
    wan_interface = cc.get_external_port()
    lan_interface = cc.network_api_port
    ip_tables = "/sbin/iptables"
    logger.info(f"Setting up ip forwarding on {rsh.hostname()} from {lan_interface} to {wan_interface}")
    rsh.run_or_die("sysctl -w net.ipv4.ip_forward=1")
    rsh.run_or_die(f"{ip_tables} -t nat -A POSTROUTING -o {lan_interface} -j MASQUERADE")
    rsh.run_or_die(f"{ip_tables} -A FORWARD -i {lan_interface} -o {wan_interface} -m state --state RELATED,ESTABLISHED -j ACCEPT ")
    rsh.run_or_die(f"{ip_tables} -A FORWARD -i {wan_interface} -o {lan_interface} -j ACCEPT")
    rsh.run_or_die(f"{ip_tables} -t nat -A POSTROUTING -o {wan_interface} -j MASQUERADE")
    rsh.run_or_die(f"{ip_tables} -A FORWARD -i {wan_interface} -o {lan_interface} -m state --state RELATED,ESTABLISHED -j ACCEPT")
    rsh.run_or_die(f"{ip_tables} -A FORWARD -i {lan_interface} -o {wan_interface} -j ACCEPT")


def ExtraConfigMicroshift(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to start Microshift on the IPU")

    # Enable NAT / IP forwarding on host to provide internet connectivity to ACC
    lh = host.LocalHost()
    masquarade(lh, cc)

    dpu_node = cc.masters[0]
    assert dpu_node.ip is not None
    acc = host.Host(dpu_node.ip)
    acc.ssh_connect("root", "redhat")

    # Set up pull secret
    logger.info(f"Copying pull secret to {acc.hostname()}:/etc/crio/openshift-pull-secret")
    acc.run("mkdir -p /etc/crio")
    acc.copy_to(cc.secrets_path, "/etc/crio/openshift-pull-secret")
    acc.run_or_die("chown root:root /etc/crio/openshift-pull-secret")
    acc.run_or_die("chmod 600 /etc/crio/openshift-pull-secret")

    # Configure firewalld for microshift
    logger.info("Configuring firewall for microshift")
    acc.run("systemctl disable firewalld")
    acc.run("systemctl stop firewalld")

    # Adjust the timeout for microshift service to ensure it starts successfully
    acc.run_or_die("mkdir -p /etc/systemd/system/microshift.service.d/")
    acc.write("/etc/systemd/system/microshift.service.d/override.conf", "[Service]\nTimeoutStartSec=15m")

    # Check on the status of the cluster
    acc.write("/etc/yum.repos.d/microshift-canidate.repo", early_access_microshift())
    time.sleep(1)
    logger.info("Checking if time is set properly to avoid OCSR errors")
    logger.info(acc.run("systemctl status chronyd --no-pager -l"))
    lh_date = host.LocalHost().run("date").out
    acc_date = host.LocalHost().run("date").out
    logger.info(f"LocalHost date: {lh_date}")
    logger.info(f"ACC date: {acc_date}")
    logger.info("Manually synchronizing time")
    host.sync_time(lh, acc)
    lh_date = host.LocalHost().run("date").out
    acc_date = host.LocalHost().run("date").out
    logger.info(f"LocalHost date: {lh_date}")
    logger.info(f"ACC date: {acc_date}")

    logger.info("Installing microshift 4.16")
    acc.run_or_die("dnf install -y microshift microshift-multus")
    ret = acc.run(r"grep '\[crio.runtime.runtimes.crun\]' /etc/crio/crio.conf")
    if not ret.success():
        crun_conf_lines = ['[crio.runtime.runtimes.crun]', 'runtime_path = "/usr/bin/crun"', 'runtime_type = "oci"', 'runtime_root = "/run/crun"']
        for line in crun_conf_lines:
            acc.run(f'echo \'{line}\' >> /etc/crio/crio.conf')
    acc.run("systemctl restart crio.service")
    logger.info("Starting microshift")
    acc.run("systemctl restart microshift")
    acc.run("systemctl enable microshift")

    contents = read_prep_microshift_kubeconfig(acc)
    kubeconfig = write_microshift_kubeconfig(contents, host.LocalHost())

    acc.run("systemctl stop firewalld")
    acc.run("systemctl disable firewalld")

    def cb() -> None:
        acc.run("ip r del default via 192.168.0.1")

    logger.info("Connecting and waiting for all nodes to be ready")
    for _ in range(3):
        try:
            K8sClient(kubeconfig).wait_ready_all(cb)
            break
        except Exception:
            time.sleep(30)
            pass


def main() -> None:
    ip = sys.argv[1]
    acc = host.Host(ip)
    acc.ssh_connect("root", "redhat")
    write_microshift_kubeconfig(read_prep_microshift_kubeconfig(acc), host.LocalHost())


if __name__ == "__main__":
    main()
