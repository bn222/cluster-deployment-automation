from assistedInstallerService import AssistedInstallerService
from ailib import AssistedClient
from clustersConfig import ClustersConfig
from clusterDeployer import ClusterDeployer
from arguments import parse_args

def main():
  args = parse_args()
  cc = ClustersConfig(args.config)

  if args.url == "192.168.122.1":
    ais = AssistedInstallerService(args.url)
    ais.start()
  else:
    print(f"Will use Assisted Installer running at {args.url}")

  ai = AssistedClient(f"{args.url}:8090")
  cd = ClusterDeployer(cc.fullConfig["clusters"][0], ai, args, args.secrets_path)

  if args.teardown:
    cd.teardown()
  else:
    cd.deploy()

if __name__ == "__main__":
  main()

