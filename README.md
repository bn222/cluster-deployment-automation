# Cluster Deployment Automation
Automate deployment of clusters in different configurations. An example configuration below showcases the main functionality:

```
clusters:
  - name : "mycluster"
    api_ip: "192.168.122.99"
    ingress_ip: "192.168.122.101"
    masters:
    - name: "mycluster-master-1"
      type: "vm"
      node: "localhost"
      ip: "192.168.122.41"
    - name: "mycluster-master-2"
      type: "vm"
      node: "localhost"
      ip: "192.168.122.42"
    - name: "mycluster-master-3"
      type: "vm"
      node: "localhost"
      ip: "192.168.122.43"
    workers:
    - name: "mycluster-worker-1"
      type: "physical"
      node: "..."
      bmc_user: "root"
      bmc_password: "..."
```