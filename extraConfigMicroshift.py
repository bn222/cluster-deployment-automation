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
    return """[microshift-latest-4.19]
name=MicroShift latest-4.19 EarlyAccess EC or RC RPMs
baseurl=https://mirror.openshift.com/pub/openshift-v4/aarch64/microshift/ocp-dev-preview/latest-4.19/el9/os/
enabled=1
gpgcheck=0
skip_if_unavailable=0


[microshift-latest-4.19-dependencies]
name=OpenShift Dependencies
baseurl=https://mirror.openshift.com/pub/openshift-v4/aarch64/dependencies/rpms/4.19-el9-beta/
enabled=1
gpgcheck=0
skip_if_unavailable=0

[openshift-4.13-dependencies]
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
    fw_active = acc.run("systemctl is-active firewalld")
    fw_enabled = acc.run("systemctl is-enabled firewalld")

    if fw_active.success() and "active" in fw_active.out:
        logger.info("Stopping firewalld service")
        acc.run("systemctl stop firewalld")

    if fw_enabled.success() and "enabled" in fw_enabled.out:
        logger.info("Disabling firewalld service")
        acc.run("systemctl disable firewalld")

    # Adjust the timeout for microshift service to ensure it starts successfully
    acc.run("mkdir -p /etc/systemd/system/microshift.service.d/")
    override_content = "[Service]\nTimeoutStartSec=15m"
    existing_override = acc.run("cat /etc/systemd/system/microshift.service.d/override.conf 2>/dev/null")
    service_override_changed = False
    if not existing_override.success() or override_content not in existing_override.out:
        logger.info("Writing microshift service timeout override")
        acc.write("/etc/systemd/system/microshift.service.d/override.conf", override_content)
        acc.run("systemctl daemon-reload")
        service_override_changed = True

    # Check if microshift is already installed
    ms_installed = acc.run("rpm -q microshift")
    multus_installed = acc.run("rpm -q microshift-multus")
    microshift_already_installed = ms_installed.success() and multus_installed.success()

    # Only add early access repo if microshift is not already installed
    if not microshift_already_installed:
        repo_exists = acc.run("test -f /etc/yum.repos.d/microshift-canidate.repo")
        if not repo_exists.success():
            logger.info("Writing microshift candidate repository")
            acc.write("/etc/yum.repos.d/microshift-canidate.repo", early_access_microshift())
    else:
        logger.info("Microshift already installed, skipping early access repository setup")

    time.sleep(1)
    logger.info("Checking if time is set properly to avoid OCSR errors")
    logger.info(acc.run("systemctl status chronyd --no-pager -l"))
    lh_date = host.LocalHost().run("date").out.strip()
    acc_date = acc.run("date").out.strip()
    logger.info(f"LocalHost date: {lh_date}")
    logger.info(f"ACC date: {acc_date}")
    logger.info("Manually synchronizing time")
    host.sync_time(lh, acc)
    lh_date = host.LocalHost().run("date").out.strip()
    acc_date = acc.run("date").out.strip()
    logger.info(f"LocalHost date: {lh_date}")
    logger.info(f"ACC date: {acc_date}")

    # Install microshift packages (idempotent)
    config_changed = service_override_changed

    if not microshift_already_installed:
        logger.info("Installing microshift")
        acc.run_or_die("dnf install -y microshift microshift-multus", retry=60)
        config_changed = True
    else:
        logger.info("Microshift packages already installed")

    # Configure crio runtime (idempotent)
    ret = acc.run(r"grep '\[crio.runtime.runtimes.crun\]' /etc/crio/crio.conf")
    if not ret.success():
        logger.info("Adding crun configuration to crio.conf")
        crun_conf_lines = ['[crio.runtime.runtimes.crun]', 'runtime_path = "/usr/bin/crun"', 'runtime_type = "oci"', 'runtime_root = "/run/crun"']
        for line in crun_conf_lines:
            acc.run(f'echo \'{line}\' >> /etc/crio/crio.conf')
        acc.run("systemctl restart crio.service")
        config_changed = True
    else:
        logger.info("crun configuration already present in crio.conf")

    # Start and enable microshift (idempotent)
    logger.info("Managing microshift service")
    ms_enabled = acc.run("systemctl is-enabled microshift")
    if not ms_enabled.success() or "enabled" not in ms_enabled.out:
        logger.info("Enabling microshift service")
        acc.run("systemctl enable microshift")
        config_changed = True

    ms_active = acc.run("systemctl is-active microshift")
    if not ms_active.success() or "active" not in ms_active.out:
        logger.info("Starting microshift service")
        acc.run("systemctl restart microshift")
    elif config_changed:
        logger.info("Configuration changed, restarting microshift service")
        acc.run("systemctl restart microshift")

    contents = read_prep_microshift_kubeconfig(acc)
    kubeconfig = write_microshift_kubeconfig(contents, host.LocalHost())

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
