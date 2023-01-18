import kubernetes
import yaml
import time
import host

class K8sClient():
  def __init__(self, kubeconfig):
    self._kubeconfig = kubeconfig
    with open(kubeconfig) as f:
      kubeconfig = yaml.safe_load(f)
    self._api_client = kubernetes.config.new_client_from_config_dict(kubeconfig)
    self._client = kubernetes.client.CoreV1Api(self._api_client)

  def is_ready(self, name):
    for e in self._client.list_node().items:
      for con in e.status.conditions:
        if con.type == "Ready":
          if name == e.metadata.name:
            return con.status == "True"
    return None

  def wait_ready(self, name):
    print(f"waiting for {name} to be ready")
    while True:
      if self.is_ready(name):
        break
      else:
        time.sleep(1)

  def approve_csr(self):
    certs_api = kubernetes.client.CertificatesV1Api(self._api_client)
    for e in certs_api.list_certificate_signing_request().items:
      if e.status.conditions is None:
        # body = kubernetes.client.V1CertificateSigningRequest()
        # certs_api.replace_certificate_signing_request_approval(e.metadata.name, body)
        name = e.name
        lh = host.LocalHost()
        lh.run(f"oc adm certificate approve {name} --kubeconfig {self._kubeconfig}")

  def get_ip(self, name):
    for e in self._client.list_node().items:
      if name == e.metadata.name:
        for addr in e.status.addresses:
          if addr.type == "InternalIP":
            return addr.address

  def oc(self, cmd):
    lh = host.LocalHost()
    return lh.run(f"oc {cmd} --kubeconfig {self._kubeconfig}")


    # print(dir(self._client))
    # for e in self._client.V1CertificateSigningRequest().items:
    #   print(e)


    # for e in yaml.safe_load(io.StringIO(result))["items"]:
    #   if not e["status"]:
    #     name = e["metadata"]["name"]
    #       print(f"approving csr {name}")
    #       lh.run(f"oc adm certificate approve {name} --kubeconfig {kubeconfig}")


# for e in api_client.sanitize_for_serialization(client.list_node())["items"]:
#     for con in e["status"]["conditions"]:
#         if con["type"] == "Ready":
#             name = e["metadata"]["name"]
#             print(name, con["status"] == "True")

# print(client.corev1api().list_node())
# print('OpenShift client version: {}'.format(oc.get_client_version()))
# print('OpenShift server version: {}'.format(oc.get_server_version()))
