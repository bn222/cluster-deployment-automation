from assistedInstaller import AssistedClientAutomation
from assistedInstallerService import AssistedInstallerService
from clustersConfig import ClustersConfig
from clusterDeployer import ClusterDeployer
from arguments import parse_args

def main():

    args = parse_args()
    cc = ClustersConfig(args.config)

    if args.url == "192.168.122.1":
        ais = AssistedInstallerService(args.url)
        ais.start(cc["version"])
        # workaround, this will still install 4.14, but AI will think
        # it is 4.13 (see also workaround when setting up versions)
        if cc["version"] == "4.14.0-nightly":
            print("Applying workaround for assisted installer issue")
            print("Will pretend to install 4.13, but using 4.14 pullsec")
            print("Ignore all output from Assisted that mentions 4.13")
            cc["version"] = "4.13.0-nightly"
    else:
        print(f"Will use Assisted Installer running at {args.url}")

    """
    Here we will use the AssistedClient from the aicli package from:
        https://github.com/karmab/aicli
    The usage details are here:
        https://aicli.readthedocs.io/en/latest/
    """
    ai = AssistedClientAutomation(f"{args.url}:8090")
    cd = ClusterDeployer(cc, ai, args, args.secrets_path)

    if args.teardown:
        cd.teardown()
        ais.stop()
    else:
        cd.deploy()

if __name__ == "__main__":
    main()
