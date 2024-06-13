import time
from concurrent.futures import Future
from typing import Optional
from logger import logger
from clustersConfig import ClustersConfig
from clustersConfig import ExtraConfigArgs
import host


def wait_for_microshift(acc: host.Host, kubeconfig: str) -> None:
    logger.info("Waiting for microshift service to start")
    for attempt in range(1, 21):
        ret = acc.run(f"""oc get nodes --kubeconfig {kubeconfig} -o jsonpath="{{.items[*].status.conditions[?(@.type=='Ready')].status}}" """)
        if ret.returncode == 0:
            if "False" not in ret.out:
                logger.info("Verified microshift node is ready")
                break
        else:
            logger.info(f"Microshift endpoint is not yet available, retrying, {ret.err}")
        logger.info(f"Microshift node not yet ready, attempt {attempt}")
        time.sleep(60)
    else:
        logger.error_and_exit(f"Node failed to reach ready state {ret.returncode}: {ret.out} {ret.err}")


def ExtraConfigMicroshift(cc: ClustersConfig, cfg: ExtraConfigArgs, futures: dict[str, Future[Optional[host.Result]]]) -> None:
    [f.result() for (_, f) in futures.items()]
    logger.info("Running post config step to start Microshift on the IPU")

    # Validate args
    dpu_node = cc.masters[0]

    # Enable NAT / IP forwarding on host to provide internet connectivity to ACC
    lh = host.LocalHost()
    cc.prepare_external_port()
    wan_interface = cc.external_port
    lan_interface = cc.network_api_port
    ip_tables = "/sbin/iptables"

    logger.info(f"Setting up ip forwarding on {lh.hostname()} from {lan_interface} to {wan_interface}")

    lh.run_or_die("/bin/echo 1 > /proc/sys/net/ipv4/ip_forward")
    lh.run_or_die(f"{ip_tables} -t nat -A POSTROUTING -o {lan_interface} -j MASQUERADE")
    lh.run_or_die(f"{ip_tables} -A FORWARD -i {lan_interface} -o {wan_interface} -m state --state RELATED,ESTABLISHED -j ACCEPT ")
    lh.run_or_die(f"{ip_tables} -A FORWARD -i {wan_interface} -o {lan_interface} -j ACCEPT")
    lh.run_or_die(f"{ip_tables} -t nat -A POSTROUTING -o {wan_interface} -j MASQUERADE")
    lh.run_or_die(f"{ip_tables} -A FORWARD -i {wan_interface} -o {lan_interface} -m state --state RELATED,ESTABLISHED -j ACCEPT")
    lh.run_or_die(f"{ip_tables} -A FORWARD -i {lan_interface} -o {wan_interface} -j ACCEPT")

    assert dpu_node.ip is not None
    acc = host.Host(dpu_node.ip)
    acc.ssh_connect("root", "redhat")

    # Set up pull secret
    logger.info(f"Copying pull secret to {acc.hostname()}:/etc/crio/openshift-pull-secret")
    acc.copy_to("pull_secret.json", "/etc/crio/openshift-pull-secret")
    acc.run_or_die("chown root:root /etc/crio/openshift-pull-secret")
    acc.run_or_die("chmod 600 /etc/crio/openshift-pull-secret")

    # Configure firewalld for microshift
    logger.info("Configuring firewall for microshift")
    acc.run_or_die("firewall-cmd --permanent --zone=trusted --add-source=10.42.0.0/16")
    acc.run_or_die("firewall-cmd --permanent --zone=trusted --add-source=169.254.169.1")
    acc.run_or_die("firewall-cmd --reload")

    # Adjust the timeout for microshift service to ensure it starts successfully
    acc.run_or_die("mkdir -p /etc/systemd/system/microshift.service.d/")
    acc.write("/etc/systemd/system/microshift.service.d/override.conf", "[Service]\nTimeoutStartSec=15m")

    # Check on the status of the cluster
    kubeconfig = "/var/lib/microshift/resources/kubeadmin/kubeconfig"

    # Add microshift early access repo for 4.16
    repo = """[microshift-latest-4.16]
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
skip_if_unavailable=0"""

    acc.write("/etc/yum.repos.d/microshift-canidate.repo", repo)

    logger.info("Installing microshift 4.16")
    acc.run_or_die("dnf install -y microshift microshift-multus")
    acc.run_or_die("systemctl restart crio.service")
    logger.info("Starting microshift")
    acc.run("systemctl restart microshift")

    wait_for_microshift(acc, kubeconfig)
