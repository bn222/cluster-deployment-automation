import argparse
from assistedInstallerService import AssistedInstallerService
from ailib import AssistedClient
from clustersConfig import ClustersConfig
from clusterDeployer import ClusterDeployer
import os, sys

def main():
  parser = argparse.ArgumentParser(description='Set up or tear down a (set of) clusters.')
  parser.add_argument('config', metavar='config', type=str, help='Yaml file with config')
  parser.add_argument('-t', '--teardown', dest='teardown', action='store_true', help='Remove anything that would be created by setting up the cluster(s)')
  parser.add_argument('-s', '--skip-masters', dest='skipmasters', action='store_true', help='Don\'t deploy masters. Assume they have already been deployed')
  parser.add_argument('--assisted-installer-url', dest='url', default='192.168.122.1', action='store', type=str, help='If set to 0.0.0.0 (the default), Assisted Installer will be started locally')
  parser.add_argument('--secret', dest='secrets_path', default='', action='store', type=str, help='pull_secret.json path (default is in cwd)')

  args = parser.parse_args()

  if not args.secrets_path:
    args.secrets_path = os.path.join(os.getcwd(), "pull_secret.json")

  if not os.path.exists(args.secrets_path):
    url = "https://console.redhat.com/openshift/install/pull-secret"
    print(f"Missing secrets file at {args.secrets_path}, get it from {url}")
    sys.exit(-1)

  if args.url == "192.168.122.1":
    ais = AssistedInstallerService(args.url)
    ais.start()
  else:
    print(f"Will use Assisted Installer running at {args.url}")


  ai = AssistedClient(f"{args.url}:8090")
  cc = ClustersConfig(args.config)
  cd = ClusterDeployer(cc.fullConfig["clusters"][0], ai, args, args.secrets_path)

  if args.teardown:
    cd.teardown()
  else:
    cd.deploy()

if __name__ == "__main__":
  main()

