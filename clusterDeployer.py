import os, sys
import time
import subprocess
from collections import namedtuple
from threading import Thread
import json
import xml.etree.ElementTree as et
from shutil import rmtree as rmdir
import shutil
from concurrent.futures import ThreadPoolExecutor
import host
import io
import yaml
import secrets
import re
import nfs
import requests
import socket
from git import Repo
from coreosBuilder import CoreosBuilder
import ipaddress

def run(cmd):
  if not isinstance(cmd, list):
    cmd = cmd.split()
  Result = namedtuple("Result", "out err")
  with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
    return Result(proc.stdout.read().decode("utf-8"), proc.stderr.read().decode("utf-8"))

def first(l, x):
  return next(filter(l, x))

def extract_ip(jsonipa, port_name):
  ipa = json.loads(jsonipa)
  interface = first(lambda x: x["ifname"] == port_name, ipa)
  inet = first(lambda x: x["family"] == "inet", interface["addr_info"])
  return inet["local"]

def setup_vms(masters, iso_path) -> None:
  # cmd = aicli()
  print(run(f"virsh pool-define-as guest_images dir - - - - /guest_images"))
  print(run(f"mkdir -p /guest_images"))
  print(run(f"chmod a+rw /guest_images"))
  print(run(f"virsh pool-start guest_images"))

  pre = "virsh net-update default add ip-dhcp-host".split()

  virsh_procs = []
  for e in masters:
    name = e["name"]
    ip = e["ip"]
    mac = "52:54:"+":".join(re.findall("..", secrets.token_hex()[:8]))
    cmd = pre + [f"<host mac='{mac}' name='{name}' ip='{ip}'/>", "--live", "--config"]
    print(cmd)
    print(run(cmd))

    OS_VARIANT="rhel8.5"
    RAM_MB="32784"
    DISK_GB="50"
    CPU_CORE="8"
    RHCOS_ISO=iso_path
    network="default"
    DISK_IMAGES="guest_images"

    cmd = f"""
    virt-install
      --connect qemu:///system
      -n {name}
      -r {RAM_MB}
      --vcpus {CPU_CORE}
      --os-variant={OS_VARIANT}
      --import
      --network=network:{network},mac={mac}
      --events on_reboot=restart
      --cdrom {RHCOS_ISO}
      --disk pool={DISK_IMAGES},size={DISK_GB}
      --wait=-1
"""
    print(f"starting virsh {cmd}")

    t1 = Thread(target=run, args=(cmd,))
    t1.start()
    virsh_procs.append(t1)
    time.sleep(3)

  return virsh_procs

def ip_in_subnet(addr, subnet):
  return ipaddress.ip_address(addr) in ipaddress.ip_network(subnet)

class ClusterDeployer():
    def __init__(self, cc, ai, args, secrets_path):
      self.args = args
      self._cc = cc
      self._ai = ai
      self._secrets_path = secrets_path
      self._iso_path = "/root/iso"
      os.makedirs(self._iso_path, exist_ok=True)

    def teardown(self):
      cluster_name = self._cc["name"]
      print(f"Tearing down {cluster_name}")
      if self._cc["name"] in map(lambda x: x["name"], self._ai.list_clusters()):
        print("cluster found, deleting it")
        while True:
          try:
            self._ai.delete_cluster(cluster_name)
            break
          except:
            print("failed to delete cluster, will retry..")
            time.sleep(1)

      local_vms = []
      if "masters" in self._cc and self._cc["masters"]:
        local_vms.extend(self._cc["masters"])
      if "workers" in self._cc and self._cc["workers"]:
        local_vms.extend(self._cc["workers"])

      lh = host.LocalHost()
      for m in local_vms:
        if m["type"] == "vm":
            assert(m["node"] == "localhost")
            name = m["name"]
            image = f"/guest_images/{name}.qcow2"
            if os.path.exists(image):
              os.remove(image)
            r = lh.run(f"virsh destroy {name}")
            print(r.err if r.err else r.out)
            r = lh.run(f"virsh undefine {name}")
            print(r.err if r.err else r.out)

      infra_name = f"{cluster_name}-x86"
      if infra_name in map(lambda x: x["name"], self._ai.list_infra_envs()):
        self._ai.delete_infra_env(infra_name)

      infra_name = f"{cluster_name}-arm"
      if (any(x["type"] == "bf" for x in self._cc["workers"]) and
         infra_name in map(lambda x: x["name"], self._ai.list_infra_envs())):
        self._ai.delete_infra_env(infra_name)

      xml_str = lh.run("virsh net-dumpxml default").out
      q = et.fromstring(xml_str)
      nodes = self._cc["masters"]
      removed_macs = []
      for e in q[-1][0][1:]:
        if (e.attrib["name"] in [x["name"] for x in nodes] or
            e.attrib["ip"] in [ x["ip"] for x in  nodes]):
          mac = e.attrib["mac"]
          name = e.attrib["name"]
          ip = e.attrib["ip"]
          pre = "virsh net-update default delete ip-dhcp-host".split()
          cmd = pre + [f"<host mac='{mac}' name='{name}' ip='{ip}'/>", "--live", "--config"]
          print(lh.run(cmd))
          removed_macs.append(mac)

      fn = "/var/lib/libvirt/dnsmasq/virbr0.status"
      with open(fn) as f:
        contents = f.read()

      if contents:
        j = json.loads(contents)
        names = [x["name"] for x in self._cc["masters"]]
        print(f'Cleaning up {fn}')
        print(f'removing hosts with mac in {removed_macs} or name in {names}')
        filtered = []
        for entry in j:
          if entry["mac-address"] in removed_macs:
            print(f'Removed host with mac {entry["mac-address"]}')
            continue
          if "hostname" in entry and entry["hostname"] in names:
            print(f'Removed host with name {entry["hostname"]}')
            continue
          else:
            print(f'Kept entry {entry}')
          filtered.append(entry)

        print(lh.run("virsh net-destroy default"))
        with open(fn, "w") as f:
          f.write(json.dumps(filtered, indent=4))
        print(lh.run("virsh net-start default"))
        print(lh.run("systemctl restart libvirtd"))

      print(lh.run(f"ip link set eno1 nomaster"))


    def deploy(self):
      if self._cc["preconfig"] == "bf_bfb_image":
        self.bf_bfb_image()

      if not self.args.skipmasters and self._cc["masters"]:
        self.teardown()
        self.create_cluster()
        self.create_masters()

      print(self._cc["kubeconfig"])
      if self._cc["workers"]:
        self.create_workers()

    def create_cluster(self):
        cluster_name = self._cc["name"]
        cfg = {}
        cfg["openshift_version"] = self._cc["version"]
        cfg["cpu_architecture"] = "multi"
        cfg["pull_secret"] = self._secrets_path
        cfg["infraenv"] = "false"

        cfg["api_ip"] = self._cc["api_ip"]
        cfg["ingress_ip"] = self._cc["ingress_ip"]
        cfg["vip_dhcp_allocation"] = False
        cfg["additional_ntp_source"] = "clock.redhat.com"
        cfg["base_dns_domain"] = "redhat.com"

        print("Creating cluster")
        self._ai.create_cluster(cluster_name, cfg)

    def create_masters(self):
        cluster_name = self._cc["name"]
        infra_env = f"{cluster_name}-x86"
        print(f"Creating infraenv {infra_env}")

        cfg = {}
        cfg["cluster"] = cluster_name
        cfg["pull_secret"] = self._secrets_path
        cfg["cpu_architecture"] = "x86_64"
        self._ai.create_infra_env(infra_env, cfg)

        print(self._ai.info_iso(infra_env, {}))

        while True:
          try:
            self._ai.download_iso(infra_env, os.getcwd())
            break
          except:
            print("iso not ready, retrying...")
            time.sleep(1)

        procs = setup_vms(self._cc["masters"], os.path.join(os.getcwd(), f"{infra_env}.iso"))

        print("Waiting for all hosts to be in \'known\' state")
        self._wait_known_state(e["name"] for e in self._cc["masters"])
        print("starting cluster")
        while True:
          try:
            self._ai.start_cluster(cluster_name)
            break
          except:
            time.sleep(1)

          cluster = list(filter(lambda e: e["name"] == cluster_name, self._ai.list_clusters()))
          if cluster[0]["status"] == "ready":
            break
          else:
            print(f"Retrying to start cluster {cluster_name}")

        self._ai.wait_cluster(cluster_name)
        for p in procs:
          p.join()
        print("link eno1 to virbr0")
        run(f"ip link set eno1 master virbr0")
        print(f'downloading kubeconfig to {self._cc["kubeconfig"]}')
        self._ai.download_kubeconfig(self._cc["name"], os.path.dirname(self._cc["kubeconfig"]))
        self._update_etc_hosts()

    def _get_ai_host(self, name):
      for h in filter(lambda x: "inventory" in x, self._ai.list_hosts()):
        rhn = h["requested_hostname"]
        if rhn == name:
          return h
      return None

    def _wait_known_state(self, names):
      status = {}
      for e in names:
        status[e] = ""
      while True:
        for h in filter(lambda x: "inventory" in x, self._ai.list_hosts()):
          rhn = h["requested_hostname"]
          if rhn in status:
            status[rhn] = h["status"]
        print(status)
        if all(v == "known" for (k, v) in status.items()):
          break
        time.sleep(1)

    def create_workers(self):
      is_bf = (x["type"] == "bf" for x in self._cc["workers"])
      is_physical = (x["type"] == "physical" for x in self._cc["workers"])

      if any(is_bf):
        if not all(is_bf):
          print("Not yet supported to have mixed BF and non-bf workers")
        else:
          self._create_bf_workers()
      else:
        if not all(is_physical):
          print(f"Not supported yet {list(is_physical)}")
        else:
          self._create_x86_workers()

    def _allow_add_workers(self, cluster_name):
      uuid = self._ai.info_cluster(cluster_name).to_dict()["id"]
      requests.post(f"http://{self._ai.url}/api/assisted-install/v2/clusters/{uuid}/actions/allow-add-workers")

    def _create_x86_workers(self):
      print("Setting up x86 workers")
      cluster_name = self._cc["name"]
      infra_env_name = f"{cluster_name}-x86"

      self._allow_add_workers(cluster_name)

      cfg = {}
      cfg["cluster"] = cluster_name
      cfg["pull_secret"] = self._secrets_path
      cfg["cpu_architecture"] = "x86_64"

      if all(map(lambda x: x["name"] != infra_env_name, self._ai.list_infra_envs())):
          print(f"Creating infraenv {infra_env_name}")
          self._ai.create_infra_env(infra_env_name, cfg)

      os.makedirs(self._iso_path, exist_ok = True)
      self._download_iso(infra_env_name, self._iso_path)

      def boot_helper(worker, iso):
        return self.boot_iso_x86(worker, iso)

      executor = ThreadPoolExecutor(max_workers=len(self._cc["workers"]))
      futures = []

      for h in self._cc["workers"]:
        futures.append(executor.submit(boot_helper, h, f"{infra_env_name}.iso"))

      for f in futures:
        print(f.result())

      for w in self._cc["workers"]:
        w["ip"] = socket.gethostbyname(w["node"])

      print("renaming workers")
      self._rename_workers(infra_env_name)
      print("waiting for workers to be on 'known' state before starting infraenv")
      self._wait_known_state(e["name"] for e in self._cc["workers"])
      print("starting infra env")
      self._ai.start_infraenv(infra_env_name)
      print("waiting for workers to be ready")
      self.wait_for_workers()

    def _rename_workers(self, infra_env_name):
      while True:
        renamed = self._try_rename_workers(infra_env_name)
        expected = len(self._cc["workers"])
        if renamed == expected:
          print(f"Found and renamed {renamed} workers")
          break
        elif renamed:
          print(f"Found and renamed {renamed} workers, but waiting for {expected}, retrying")
        time.sleep(1)

    def _try_rename_workers(self, infra_env_name):
      infra_env_id = self._ai.get_infra_env_id(infra_env_name)
      renamed = 0

      for w in self._cc["workers"]:
        ip = w["ip"]
        print(f"looking for worker with ip {ip}")
        for h in filter(lambda x: x["infra_env_id"] == infra_env_id, self._ai.list_hosts()):
          if not "inventory" in h:
            continue
          nics = json.loads(h["inventory"]).get("interfaces")
          addresses = sum((nic["ipv4_addresses"] for nic in nics), [])
          addresses = list(a.split("/")[0] for a in addresses)

          if w["ip"] in addresses:
            name = w["name"]
            self._ai.update_host(h["id"], {"name" : name})
            print(f"renamed {name}")
            renamed += 1
      return renamed

    def boot_iso_x86(self, worker, iso):
      host_name = worker["node"]
      print(f"trying to boot {host_name}")

      lh = host.LocalHost()
      nfs_server = extract_ip(lh.run("ip -json a").out, "eno3")

      h = host.RemoteHostWithBF2(host_name, worker["bmc_user"], worker["bmc_password"])

      h.boot_iso_redfish(f"{nfs_server}:/root/iso/{iso}")
      h.ssh_connect("core")
      print("connected")
      print(h.run("hostname"))

    def _ensure_fcos_exists(self):
      print("ensuring that fcos exists")
      dst = os.path.join(self._iso_path, "fedora-coreos.iso")
      if os.path.exists(dst):
        print("fcos found, not rebuilding it")
      else:
        print("fcos not found, building it now")
        builder = CoreosBuilder("/tmp/build")
        builder.build(dst)

    def _create_bf_workers(self):
      cluster_name = self._cc["name"]
      infra_env_name = f"{cluster_name}-arm"

      self._allow_add_workers(cluster_name)

      cfg = {}
      cfg["cluster"] = cluster_name
      cfg["pull_secret"] = self._secrets_path
      cfg["cpu_architecture"] = "arm64"

      if all(map(lambda x: x["name"] != infra_env_name, self._ai.list_infra_envs())):
          print(f"Creating infraenv {infra_env_name}")
          self._ai.create_infra_env(infra_env_name, cfg)

      infra_env_id = next(x["id"] for x in self._ai.list_infra_envs() if x["name"] == infra_env_name)

      self._download_iso(infra_env_name, self._iso_path)

      id_rsa_file = "/root/.ssh/id_rsa"
      self._ensure_fcos_exists()
      nfs.export(self._iso_path)
      shutil.copyfile(id_rsa_file, os.path.join(self._iso_path, "id_rsa"))

      def boot_iso_bf_helper(worker, iso):
        return self.boot_iso_bf(worker, iso)

      executor = ThreadPoolExecutor(max_workers=len(self._cc["workers"]))
      futures = []
      for h in self._cc["workers"]:
        f = executor.submit(boot_iso_bf_helper, h, f"{infra_env_name}.iso")
        futures.append(f)

      for (h, f) in zip(self._cc["workers"], futures):
        h["ip"] = f.result()

      self._rename_workers(infra_env_name)
      print("waiting for workers to be on 'known' state before starting infraenv")
      self._wait_known_state(e["name"] for e in self._cc["workers"])
      self._ai.start_infraenv(infra_env_name)
      self.wait_for_workers()

    def _download_iso(self, infra_env_name, iso_path):
      while True:
        try:
          print(f"trying to download iso from {infra_env_name} to {iso_path}")
          self._ai.download_iso(infra_env_name, iso_path)
          print(f"iso for {infra_env_name} downloaded to {iso_path}")
          break
        except:
          print("iso not ready, retrying ...")
          time.sleep(1)

    def is_ready(self, node_name, kubeconfig):
      lh = host.LocalHost()

      if not os.path.exists(kubeconfig):
        print(f"Missing kubeconfig at {kubeconfig}")
        sys.exit(-1)

      result = lh.run(f"oc get node -o yaml --kubeconfig {kubeconfig}")
      if result.err:
        print(result.err)
        sys.exit(-1)

      y = yaml.safe_load(result.out)
      for it in y["items"]:
        if "metadata" not in it:
          continue
        if "name" not in it["metadata"]:
          continue

        if it["metadata"]["name"] != node_name:
          continue

        if "status" not in it:
          continue
        if "conditions" not in it["status"]:
          continue
        for e in it["status"]["conditions"]:
          if e["type"] == "Ready":
             return e["status"] == "True"
      return False

    def approve_csr(self, kubeconfig):
      lh = host.LocalHost()
      result = lh.run(f"oc get csr -o yaml --kubeconfig {kubeconfig}").out
      for e in yaml.safe_load(io.StringIO(result))["items"]:
        if not e["status"]:
          name = e["metadata"]["name"]
          print(f"approving csr {name}")
          lh.run(f"oc adm certificate approve {name} --kubeconfig {kubeconfig}")

    def _update_etc_hosts(self):
      cluster_name = self._cc["name"]
      api_name = f"api.{cluster_name}.redhat.com"
      api_ip = self._cc["api_ip"]
      found = False
      etchost = ""
      with open("/etc/hosts", "r") as f:
        etchost = f.read()
      for e in etchost.split("\n"):
        if e and e.split()[1] == api_name:
          found = True
          break
      if not found:
        with open("/etc/hosts", "a") as f:
          f.write(f"{api_ip} {api_name}\n")

    def boot_iso_bf(self, worker, iso):
      lh = host.LocalHost()
      nfs_server = extract_ip(lh.run("ip -json a").out, "eno3")

      host_name = worker["node"]
      print(f"Preparing BF on host {host_name}")
      h = host.RemoteHostWithBF2(host_name, worker["bmc_user"], worker["bmc_password"])
      h.boot_iso_redfish(f"{nfs_server}:/root/iso/fedora-coreos.iso")
      h.ssh_connect("core")

      output = h.bf_pxeboot(iso, nfs_server)
      ipa_json = output[-1]
      bf_interface = "enp3s0f0"
      try:
        ip = extract_ip(ipa_json, bf_interface)
        print(ip)
      except:
        ip = None
        print(f"Failed to find ip on {bf_interface}, output was {ipa_json}")
      return ip

    def wait_for_workers(self):
      cluster_name = self._cc["name"]

      print(f'waiting for {self._cc["workers"]} workers')
      while True:
        workers = [w["name"] for w in self._cc["workers"]]
        if all(self.is_ready(w, self._cc["kubeconfig"]) for w in workers):
          break

        self.approve_csr(self._cc["kubeconfig"])

        lh = host.LocalHost()
        d = lh.run("date").out
        # Workaround: Time is not set and consequently HTTPS
        for w in filter(lambda x: x["type"] == "bf", self._cc["workers"]):
          ai_ip = self._get_ai_ip(w["name"])
          if ai_ip is None:
            continue
          h = host.RemoteHost(ai_ip, None, None)
          h.ssh_connect("core")
          h.run(f"sudo date -s '{d}'")
          h.run("date")[0]

        time.sleep(5)

    def _get_ai_ip(self, name):
      ai_host = self._get_ai_host(name)
      if ai_host:
        inventory = json.loads(ai_host["inventory"])
        routes = inventory["routes"]

        default_nics = [x['interface'] for x in routes if x['destination'] == '0.0.0.0']
        for default_nic in default_nics:
          nic_info = next(nic for nic in inventory.get('interfaces') if nic["name"] == default_nic)
          addr = nic_info['ipv4_addresses'][0].split('/')[0]
          if ip_in_subnet(addr, "192.168.122.0/24"):
            return addr
      return None

    def bf_bfb_image(self):
      self._ensure_fcos_exists()
      print("Loading BF-2 with BFB image on all workers")
      lh = host.LocalHost()
      nfs_server = extract_ip(lh.run("ip -json a").out, "eno3")
      iso_url = f"{nfs_server}:/root/iso/fedora-coreos.iso"

      def helper(e):
        h = host.RemoteHostWithBF2(e["node"], e["bmc_user"], e["bmc_password"])
        h.boot_iso_redfish(iso_url)
        h.ssh_connect("core")
        h.prep_container()
        print("updating firmware")
        h.bf_firmware_upgrade()
        print("setting firmware config to defaults")
        h.bf_firmware_defaults()
        h.cold_boot()
        h.boot_iso_redfish(iso_url)
        h.ssh_connect("core")
        h.prep_container()
        print("loading bfb image")
        h.bf_load_bfb()

      executor = ThreadPoolExecutor(max_workers=len(self._cc["workers"]))
      futures = []
      # Assuming that all workers have BF that need to reset to bfb image in dpu mode
      for e in self._cc["workers"]:
        f = executor.submit(helper, e)
        futures.append(f)
      [f.result() for f in futures]
