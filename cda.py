from assistedInstaller import AssistedClientAutomation
from assistedInstallerService import AssistedInstallerService
from clustersConfig import ClustersConfig
from clusterDeployer import ClusterDeployer
from arguments import parse_args
from logger import logger
from clusterSnapshotter import ClusterSnapshotter


def main_deploy(args):
    cc = ClustersConfig(args.config)

    if args.url == "192.168.122.1":
        ais = AssistedInstallerService(cc["version"], args.url)
        ais.start()
        # workaround, this will still install 4.14, but AI will think
        # it is 4.13 (see also workaround when setting up versions)
        if cc["version"][:len("4.14")] == "4.14":
            logger.warn("Applying workaround for assisted installer issue")
            logger.warn("Will pretend to install 4.13, but using 4.14 pullsec")
            logger.warn("Ignore all output from Assisted that mentions 4.13")
            cc["version"] = "4.13.0-nightly"
    else:
        logger.info(f"Will use Assisted Installer running at {args.url}")
        ais = None

    """
    Here we will use the AssistedClient from the aicli package from:
        https://github.com/karmab/aicli
    The usage details are here:
        https://aicli.readthedocs.io/en/latest/
    """
    ai = AssistedClientAutomation(f"{args.url}:8090")
    cd = ClusterDeployer(cc, ai, args, args.secrets_path)

    if args.teardown or args.teardown_full:
        cd.teardown()
    else:
        cd.deploy()

    if args.teardown_full and ais:
        ais.stop()


def main_snapshot(args):
    args = parse_args()
    cc = ClustersConfig(args.config)

    ais = AssistedInstallerService(cc["version"], args.url)
    ai = AssistedClientAutomation(f"{args.url}:8090")

    name = cc["name"] if args.name is None else args.name
    cs = ClusterSnapshotter(cc, ais, ai, name)

    if args.loadsave == "load":
        cs.import_cluster()
    elif args.loadsave == "save":
        cs.export_cluster()
    else:
        logger.error(f"Unexpected action {args.actions}")


def main():
    args = parse_args()
    if args.subcommand == "deploy":
        main_deploy(args)
    elif args.subcommand == "snapshot":
        main_snapshot(args)


if __name__ == "__main__":
    main()
