#!/usr/bin/env python3

# PYTHON_ARGCOMPLETE_OK
from assistedInstaller import AssistedClientAutomation
from assistedInstallerService import AssistedInstallerService
from clustersConfig import ClustersConfig, ExtraConfigArgs
from clusterDeployer import ClusterDeployer
from isoDeployer import IsoDeployer
from arguments import parse_args, DEFAULT_AI_URL
import argparse
import host
from logger import logger
from clusterSnapshotter import ClusterSnapshotter
from virtualBridge import VirBridge
import configLoader
from cdaConfig import CdaConfig
import auth
import common
import os
from state_file import StateFile


def check_and_cleanup_disk(threshold_gb: int = 10) -> None:
    h = host.LocalHost()
    _, _, free = h.disk_usage("/")
    if free < threshold_gb * 1024 * 1024 * 1024:
        logger.warning(f"image space is {free} which is less than 10GB treshold, pruning images")
        h.run("podman image prune -a -f")


def get_ai_url_for_bridge_mode(cc: ClustersConfig, args: argparse.Namespace) -> tuple[str, bool]:
    """Get the Assisted Installer URL, auto-detecting for bridge mode.

    In bridge mode, the default NAT URL (192.168.122.1) doesn't exist.
    We use the IP of the kernel bridge instead, so the AI is reachable from VMs.

    Returns:
        Tuple of (ai_url, start_locally) where start_locally indicates if AI should be started.
    """
    # If user explicitly specified a URL different from default, use it (external AI)
    if args.url != DEFAULT_AI_URL:
        return args.url, False

    # NAT mode: use the default, start AI locally
    if cc.network_mode != "bridge":
        return args.url, True

    # Bridge mode: get IP of the kernel bridge, start AI locally
    bridge_ip = common.port_to_ip(host.LocalHost(), cc.bridge_name)
    if bridge_ip is None:
        logger.error_and_exit(
            f"Bridge mode is enabled but could not get IP of bridge '{cc.bridge_name}'. "
            f"Make sure the bridge exists and has an IP address. "
            f"You can create it with: scripts/setup-bridge.sh <interface> {cc.bridge_name}"
        )

    logger.info(f"Bridge mode: using {bridge_ip} as Assisted Installer URL (from {cc.bridge_name})")
    return bridge_ip, True


def main_deploy_openshift(cc: ClustersConfig, args: argparse.Namespace, state_file: StateFile) -> None:
    # Make sure the local virtual bridge base configuration is correct.
    local_bridge = VirBridge(host.LocalHost(), cc.local_bridge_config)
    local_bridge.configure(api_port=None)

    # Get the appropriate AI URL (auto-detected for bridge mode)
    ai_url, start_ai_locally = get_ai_url_for_bridge_mode(cc, args)

    if start_ai_locally:
        resume_deployment = "master" not in args.steps
        # Use the appropriate bridge name based on network mode
        bridge_name = cc.bridge_name if cc.network_mode == "bridge" else "virbr0"
        ais = AssistedInstallerService(cc.version, ai_url, resume_deployment, cc.proxy, cc.noproxy, bridge_name=bridge_name)
        ais.start()
    else:
        logger.info(f"Will use Assisted Installer running at {ai_url}")
        ais = None

    """
    Here we will use the AssistedClient from the aicli package from:
        https://github.com/karmab/aicli
    The usage details are here:
        https://aicli.readthedocs.io/en/latest/
    """
    ai = AssistedClientAutomation(f"{ai_url}:8090", ais)
    cd = ClusterDeployer(cc, ai, args.steps, args.secrets_path, state_file, args.resume)

    if args.additional_post_config:
        logger.info(f"Running additional post config: {args.additional_post_config}")
        ec = ExtraConfigArgs("", args.additional_post_config)
        cd._prepost_config(ec)
        return

    if args.teardown or args.teardown_full:
        cd.teardown_workers()
        cd.teardown_masters()
        state_file.clear_state()
    else:
        cd.deploy()

    if args.teardown_full and ais:
        ais.stop()


def main_deploy_iso(cc: ClustersConfig, args: argparse.Namespace, state_file: StateFile) -> None:
    id = IsoDeployer(cc, args.steps, state_file, args.resume)
    id.deploy()


def main_deploy(args: argparse.Namespace, cc: ClustersConfig, conf: CdaConfig, state_file: StateFile) -> None:
    if conf.token_user != "" and conf.token != "":
        auth.RegistryInfo("registry.ci.openshift.org", conf.token_user, conf.token).inject_if_missing()

    check_and_cleanup_disk(10)

    if cc.kind == "openshift":
        main_deploy_openshift(cc, args, state_file)
    else:
        main_deploy_iso(cc, args, state_file)


def main_snapshot(args: argparse.Namespace, cc: ClustersConfig, state_file: StateFile) -> None:
    args = parse_args()

    ais = AssistedInstallerService(cc.version, args.url)
    ai = AssistedClientAutomation(f"{args.url}:8090", ais)

    name = cc.name if args.name is None else args.name
    cs = ClusterSnapshotter(cc, ais, ai, name)

    if args.loadsave == "load":
        cs.import_cluster(state_file)
    elif args.loadsave == "save":
        cs.export_cluster()
    else:
        logger.error(f"Unexpected action {args.actions}")


def is_yaml(config: str) -> bool:
    return config.endswith('.yaml') or config.endswith('.yml')


def main() -> None:
    args = parse_args()

    if not is_yaml(args.config):
        logger.error_and_exit("Please specify a yaml configuration file")

    if os.path.exists(args.cda_config):
        conf = configLoader.load(args.cda_config, CdaConfig)
    else:
        conf = CdaConfig()

    if not args.subcommand:
        logger.error_and_exit("No subcommand: select either deploy, state or snapshot ")

    if args.subcommand == "state":
        cc = ClustersConfig(args.config)
        print(StateFile(cc.name, conf.state_file_path))
        return

    cc = ClustersConfig(
        args.config,
        secrets_path=args.secrets_path,
        worker_range=args.worker_range,
    )

    sf = StateFile(cc.name, conf.state_file_path)

    if args.subcommand == "deploy":
        main_deploy(args, cc, conf, sf)
    elif args.subcommand == "snapshot":
        main_snapshot(args, cc, sf)


if __name__ == "__main__":
    main()
