import logging

class Firewall:
    # Hardcoded values from firewall.sh
    TRUSTED_CIDRS = ['169.254.169.0/24', '192.168.0.0/24']
    SSH_INTERFACES = ['enp0s1f0d1']
    PORT_RULES = {
        ('internal', 'tcp'): ['9559', '8080', '443'],
        ('public', 'tcp'): ['22', '6443', '8445', '10250-10259'],
        ('public', 'udp'): ['53', '67-68'],
    }
    # Placeholder for API server IP. Replace or parameterize as needed.
    #API_SERVER_IP = 'API_SERVER_IP_PLACEHOLDER'  # TODO: Replace with actual value or parameterize

    def __init__(self, host):
        """
        host: an object (like host.Host) that provides a .run(cmd) method to execute commands on the target node.
        """
        self.host = host
        self.logger = logging.getLogger("firewall")

    def enable(self):
        self.logger.info("Enabling and configuring firewall...")
        self.host.run("systemctl enable firewalld")
        self.host.run("systemctl start firewalld")
        self.host.run("firewall-cmd --set-default-zone=drop")
        self.host.run("firewall-cmd --permanent --new-zone=internal || true")

        # Trusted CIDRs (add as source and rich-rule to internal zone)
        for cidr in self.TRUSTED_CIDRS:
            self.host.run(f"firewall-cmd --permanent --zone=internal --add-source={cidr}")
            self.host.run(f"firewall-cmd --permanent --zone=internal --add-rich-rule=rule family=\'ipv4\' destination address=\'{cidr}\' accept")

        # API Server IP (add as source and rich-rule to internal zone)
        #api_ip = self.API_SERVER_IP
        #self.host.run(f"firewall-cmd --permanent --zone=internal --add-source={api_ip}/32")
        #self.host.run(f"firewall-cmd --permanent --zone=internal --add-rich-rule=rule family=\'ipv4\' destination address=\'{api_ip}\' accept")

        # Port rules
        for (zone, proto), ports in self.PORT_RULES.items():
            for port in ports:
                self.host.run(f"firewall-cmd --permanent --zone={zone} --add-port={port}/{proto}")

        # SSH interfaces (add all to public zone)
        for iface in self.SSH_INTERFACES:
            self.host.run(f"firewall-cmd --permanent --zone=public --add-interface={iface}")

        # Always open 6443/tcp on drop zone
        self.host.run("firewall-cmd --permanent --zone=drop --add-port=6443/tcp")

        # Remove mDNS from public zone and set log-denied=all
        self.host.run("firewall-cmd --permanent --zone=public --remove-service=mdns")
        self.host.run("firewall-cmd --set-log-denied=all")

        self.host.run("firewall-cmd --reload")
        self.logger.info("Firewall enabled and configured.")

    def disable(self):
        self.logger.info("Disabling firewall rules and cleaning up...")
        self.host.run("systemctl enable firewalld")
        self.host.run("systemctl start firewalld")
        self.host.run("firewall-cmd --set-default-zone=public")

        # Trusted CIDRs (remove as source and rich-rule from internal zone)
        for cidr in self.TRUSTED_CIDRS:
            self.host.run(f"firewall-cmd --permanent --zone=internal --remove-source={cidr}")
            self.host.run(f"firewall-cmd --permanent --zone=internal --remove-rich-rule=rule family=\'ipv4\' destination address=\'{cidr}\' accept")

        # API Server IP (remove as source and rich-rule from internal zone)
        #api_ip = self.API_SERVER_IP
        #self.host.run(f"firewall-cmd --permanent --zone=internal --remove-source={api_ip}/32")
        #self.host.run(f"firewall-cmd --permanent --zone=internal --remove-rich-rule=rule family=\'ipv4\' destination address=\'{api_ip}\' accept")

        # Port rules (remove)
        for (zone, proto), ports in self.PORT_RULES.items():
            for port in ports:
                self.host.run(f"firewall-cmd --permanent --zone={zone} --remove-port={port}/{proto}")

        # SSH interfaces (remove all except the first/primary)
        for i, iface in enumerate(self.SSH_INTERFACES):
            if i == 0:
                continue  # preserve primary interface on cleanup
            self.host.run(f"firewall-cmd --permanent --zone=public --remove-interface={iface}")

        # Remove 6443/tcp from drop zone
        self.host.run("firewall-cmd --permanent --zone=drop --remove-port=6443/tcp")

        # Add mDNS back to public zone and set log-denied=off
        self.host.run("firewall-cmd --permanent --zone=public --add-service=mdns")
        self.host.run("firewall-cmd --set-log-denied=off")

        # Delete internal zone
        self.host.run("firewall-cmd --permanent --delete-zone=internal || true")

        self.host.run("firewall-cmd --reload")
        self.logger.info("Firewall rules cleaned up and disabled.")

