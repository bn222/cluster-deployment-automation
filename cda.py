#!/usr/bin/env python3

# PYTHON_ARGCOMPLETE_OK
from assistedInstaller import AssistedClientAutomation
from assistedInstallerService import AssistedInstallerService
from clustersConfig import ClustersConfig
from clusterDeployer import ClusterDeployer
from isoDeployer import IsoDeployer
from arguments import parse_args
import argparse
import host
from logger import logger
from clusterSnapshotter import ClusterSnapshotter
from virtualBridge import VirBridge


def main_deploy_openshift(cc: ClustersConfig, args: argparse.Namespace) -> None:
    # Make sure the local virtual bridge base configuration is correct.
    local_bridge = VirBridge(host.LocalHost(), cc.local_bridge_config)
    local_bridge.configure(api_port=None)

    # microshift does not use assisted installer so we don't need this check
    if args.url == cc.ip_range[0]:
        ais = AssistedInstallerService(cc.version, args.url, cc.proxy, cc.noproxy)
        ais.start()
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
        cd.teardown_workers()
        cd.teardown_masters()
    else:
        cd.deploy()

    if args.teardown_full and ais:
        ais.stop()


def main_deploy_iso(cc: ClustersConfig, args: argparse.Namespace) -> None:
    id = IsoDeployer(cc, args.steps)
    id.deploy()


def main_deploy(args: argparse.Namespace) -> None:
    cc = ClustersConfig(
        args.config,
        secrets_path=args.secrets_path,
        worker_range=args.worker_range,
    )

    if cc.kind == "openshift":
        main_deploy_openshift(cc, args)
    else:
        main_deploy_iso(cc, args)


def main_snapshot(args: argparse.Namespace) -> None:
    args = parse_args()
    cc = ClustersConfig(
        args.config,
        worker_range=args.worker_range,
    )

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
