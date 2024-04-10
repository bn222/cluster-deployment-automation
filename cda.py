#!/usr/bin/env python3

# PYTHON_ARGCOMPLETE_OK
from assistedInstaller import AssistedClientAutomation
from assistedInstallerService import AssistedInstallerService
from clustersConfig import ClustersConfig
from clusterDeployer import ClusterDeployer
from arguments import parse_args
import argparse
import host
from logger import logger
from clusterSnapshotter import ClusterSnapshotter
from virtualBridge import VirBridge


def main_deploy(args: argparse.Namespace) -> None:
    cc = ClustersConfig(args.config, args.worker_range)

    # Make sure the local virtual bridge base configuration is correct.
    local_bridge = VirBridge(host.LocalHost(), cc.local_bridge_config)
    local_bridge.configure(api_port=None)

    # microshift does not use assisted installer so we don't need this check
    if args.url == cc.ip_range[0] and not cc.kind == "microshift":
        ais = AssistedInstallerService(cc.version, args.url, cc.proxy, cc.noproxy)
        ais.start()
        # workaround, this will still install 4.14, but AI will think
        # it is 4.13 (see also workaround when setting up versions)
        if cc.version[: len("4.14")] == "4.14":
            logger.warning("Applying workaround for assisted installer issue")
            logger.warning("Will pretend to install 4.13, but using 4.14 pullsec")
            logger.warning("Ignore all output from Assisted that mentions 4.13")
            cc.version = "4.13.0-nightly"
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
    cd = ClusterDeployer(cc, ai, args.steps, args.secrets_path)

    if args.teardown or args.teardown_full:
        cd.teardown()
    else:
        cd.deploy()

    if args.teardown_full and ais:
        ais.stop()


def main_snapshot(args: argparse.Namespace) -> None:
    args = parse_args()
    cc = ClustersConfig(args.config, args.worker_range)

    ais = AssistedInstallerService(cc.version, args.url)
    ai = AssistedClientAutomation(f"{args.url}:8090")

    name = cc.name if args.name is None else args.name
    cs = ClusterSnapshotter(cc, ais, ai, name)

    if args.loadsave == "load":
        cs.import_cluster()
    elif args.loadsave == "save":
        cs.export_cluster()
    else:
        logger.error(f"Unexpected action {args.actions}")


def main() -> None:
    args = parse_args()

    if not (args.config.endswith('.yaml') or args.config.endswith('.yml')):
        print("Please specify a yaml configuration file")
        raise SystemExit(1)

    if args.subcommand == "deploy":
        main_deploy(args)
    elif args.subcommand == "snapshot":
        main_snapshot(args)


if __name__ == "__main__":
    main()
