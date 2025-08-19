import logging
import host

TRUSTED_CIDRS = ['169.254.169.0/24', '192.168.0.0/24']
SSH_INTERFACES = ['enp0s1f0d1']
PORT_RULES = {
    ('internal', 'tcp'): ['8080', '443'],
    ('public', 'tcp'): ['22', '6443', '8445', '10250-10259'],
    ('public', 'udp'): ['53', '67-68'],
}

logger = logging.getLogger("firewall")


def enable_firewall(rh: host.Host):
    logger.info("Enabling and configuring firewall...")
    rh.run("systemctl enable firewalld")
    rh.run("systemctl start firewalld")
    rh.run("firewall-cmd --set-default-zone=drop")
    rh.run("firewall-cmd --permanent --new-zone=internal || true")

    for cidr in TRUSTED_CIDRS:
        rh.run(f"firewall-cmd --permanent --zone=internal --add-source={cidr}")
        rh.run(f"firewall-cmd --permanent --zone=internal --add-rich-rule=rule family='ipv4' destination address='{cidr}' accept")

    for (zone, proto), ports in PORT_RULES.items():
        for port in ports:
            rh.run(f"firewall-cmd --permanent --zone={zone} --add-port={port}/{proto}")

    for iface in SSH_INTERFACES:
        rh.run(f"firewall-cmd --permanent --zone=public --add-interface={iface}")

    rh.run("firewall-cmd --permanent --zone=drop --add-port=6443/tcp")
    rh.run("firewall-cmd --permanent --zone=public --remove-service=mdns")
    rh.run("firewall-cmd --set-log-denied=all")
    rh.run("firewall-cmd --reload")
    logger.info("Firewall enabled and configured.")


def disable_firewall(rh: host.Host):
    logger.info("Disabling firewall rules and cleaning up...")
    rh.run("systemctl enable firewalld")
    rh.run("systemctl start firewalld")
    rh.run("firewall-cmd --set-default-zone=public")

    for cidr in TRUSTED_CIDRS:
        rh.run(f"firewall-cmd --permanent --zone=internal --remove-source={cidr}")
        rh.run(f"firewall-cmd --permanent --zone=internal --remove-rich-rule=rule family='ipv4' destination address='{cidr}' accept")

    for (zone, proto), ports in PORT_RULES.items():
        for port in ports:
            rh.run(f"firewall-cmd --permanent --zone={zone} --remove-port={port}/{proto}")

    for i, iface in enumerate(SSH_INTERFACES):
        if i == 0:
            continue
        rh.run(f"firewall-cmd --permanent --zone=public --remove-interface={iface}")

    rh.run("firewall-cmd --permanent --zone=drop --remove-port=6443/tcp")
    rh.run("firewall-cmd --permanent --zone=public --add-service=mdns")
    rh.run("firewall-cmd --set-log-denied=off")
    rh.run("firewall-cmd --permanent --delete-zone=internal || true")
    rh.run("firewall-cmd --reload")
    logger.info("Firewall rules cleaned up and disabled.")
