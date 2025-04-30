#!/usr/bin/env python3

# PYTHON_ARGCOMPLETE_OK
from assistedInstaller import AssistedClientAutomation
from assistedInstallerService import AssistedInstallerService
from clustersConfig import ClustersConfig, ExtraConfigArgs
from clusterDeployer import ClusterDeployer
from isoDeployer import IsoDeployer
from arguments import parse_args
import argparse
import host
from logger import logger
from clusterSnapshotter import ClusterSnapshotter
from virtualBridge import VirBridge
import configLoader
from cdaConfig import CdaConfig
import auth
import os
from state_file import StateFile


def check_and_cleanup_disk(threshold_gb: int = 10) -> None:
    h = host.LocalHost()
    _, _, free = h.disk_usage("/")
    if free < threshold_gb * 1024 * 1024 * 1024:
        logger.warning(f"image space is {free} which is less than 10GB treshold, pruning images")
        h.run("podman image prune -a -f")


def main_deploy_openshift(cc: ClustersConfig, args: argparse.Namespace, state_path: str) -> None:
    # Make sure the local virtual bridge base configuration is correct.
    local_bridge = VirBridge(host.LocalHost(), cc.local_bridge_config)
    local_bridge.configure(api_port=None)

    # microshift does not use assisted installer so we don't need this check
    if args.url == cc.ip_range[0]:
        resume_deployment = "master" not in args.steps
        ais = AssistedInstallerService(cc.version, args.url, resume_deployment, cc.proxy, cc.noproxy)
        ais.start()
    else:
        logger.info(f"Will use Assisted Installer running at {args.url}")
        ais = None

    sf = StateFile(state_path)
    """
    Here we will use the AssistedClient from the aicli package from:
        https://github.com/karmab/aicli
    The usage details are here:
        https://aicli.readthedocs.io/en/latest/
    """
    ai = AssistedClientAutomation(f"{args.url}:8090")
    cd = ClusterDeployer(cc, ai, args.steps, args.secrets_path, sf, args.resume)

    if args.additional_post_config:
        logger.info(f"Running additional post config: {args.additional_post_config}")
        ec = ExtraConfigArgs("", args.additional_post_config)
        cd._prepost_config(ec)
        return

    if args.teardown or args.teardown_full:
        cd.teardown_workers()
        cd.teardown_masters()
        sf.clear_state()
    else:
        cd.deploy()

    if args.teardown_full and ais:
        ais.stop()


def main_deploy_iso(cc: ClustersConfig, args: argparse.Namespace) -> None:
    id = IsoDeployer(cc, args.steps)
    id.deploy()


def main_deploy(args: argparse.Namespace, cc: ClustersConfig, state_path: str, token_user: str = "", token: str = "") -> None:
    if token_user != "" and token != "":
        auth.prep_auth(token_user, token)

    check_and_cleanup_disk(10)

    if cc.kind == "openshift":
        main_deploy_openshift(cc, args, state_path)
    else:
        main_deploy_iso(cc, args)


def main_snapshot(args: argparse.Namespace, cc: ClustersConfig, state_path: str) -> None:
    args = parse_args()

    ais = AssistedInstallerService(cc.version, args.url)
    ai = AssistedClientAutomation(f"{args.url}:8090")

    name = cc.name if args.name is None else args.name
    cs = ClusterSnapshotter(cc, ais, ai, name)
    sf = StateFile(state_path)

    if args.loadsave == "load":
        cs.import_cluster(sf)
    elif args.loadsave == "save":
        cs.export_cluster()
    else:
        logger.error(f"Unexpected action {args.actions}")


def main_state(args: argparse.Namespace, path: str) -> None:
    s = StateFile(path)
    print(s)
    return


def is_yaml(config: str) -> bool:
    return config.endswith('.yaml') or config.endswith('.yml')


def main() -> None:
    args = parse_args()

    if not is_yaml(args.config):
        logger.error_and_exit("Please specify a yaml configuration file")

    path: str = ""
    token_user: str = ""
    token: str = ""
    if os.path.exists(args.cda_config):
        conf = configLoader.load(args.cda_config, CdaConfig)
        token_user = conf.token_user
        token = conf.token
        path = conf.state_file_dir

    if not args.subcommand:
        logger.error_and_exit("No subcommand: select either deploy, state or snapshot ")
        return

    if args.subcommand == "state":
        cc = ClustersConfig(args.config)
        path += cc.name
        main_state(args, path)
        return

    cc = ClustersConfig(
        args.config,
        secrets_path=args.secrets_path,
        worker_range=args.worker_range,
    )

    path += cc.name

    if args.subcommand == "deploy":
        main_deploy(args, cc, path, token_user, token)
    elif args.subcommand == "snapshot":
        main_snapshot(args, cc, path)


if __name__ == "__main__":
    main()
