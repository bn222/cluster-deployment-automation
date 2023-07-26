import os
import argparse
import sys
import logging
from logger import logger, configure_logger


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Cluster deployment automation')
    parser.add_argument('config', metavar='config', type=str, help='Yaml file with config')
    steps = "pre,masters,workers,post"
    parser.add_argument('-v', '--verbosity', choices=['debug', 'info', 'warning', 'error', 'critical'], default='info', help='Set the logging level (default: info)')
    parser.add_argument('--secret', dest='secrets_path', default='', action='store', type=str, help='pull_secret.json path (default is in cwd)')
    parser.add_argument('--assisted-installer-url', dest='url', default='192.168.122.1', action='store', type=str, help='If set to 0.0.0.0 (the default), Assisted Installer will be started locally')

    subparsers = parser.add_subparsers(title='subcommands', dest='subcommand')
    deploy_parser = subparsers.add_parser('deploy', help='Deploy clusters')
    deploy_parser.add_argument('-t', '--teardown', dest='teardown', action='store_true', help='Remove anything that would be created by setting up the cluster(s)')
    deploy_parser.add_argument('-f', '--teardown-full', dest='teardown_full', action='store_true', help='Remove anything that would be created by setting up the cluster(s), included ai')
    steps = "pre,masters,workers,post"
    deploy_parser.add_argument('-s', '--steps', dest='steps', type=str, default=steps, help=f'Comma-separated list of steps to run (by default: {steps})')
    deploy_parser.add_argument('-d', '--skip-steps', dest='skip_steps', type=str, default="", help=f"CommComma-separated list of steps to skip")

    snapshot_parser = subparsers.add_parser('snapshot', help='Take or restore snapshots')
    snapshot_parser.add_argument('loadsave', metavar='loadsave', type=str, help='Load or save a snapshot')
    snapshot_parser.add_argument('--name', type=str, default=None, help="Name of the snapshot (default is name of cluster)")

    args = parser.parse_args()
    if args.subcommand == "deploy":
        args.steps = args.steps.split(",")
        args.skip_steps = args.skip_steps.split(",")
        args.steps = [x for x in args.steps if x not in args.skip_steps]

    log_levels = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }
    args.verbosity = log_levels[args.verbosity]
    configure_logger(args.verbosity)

    if not args.secrets_path:
        args.secrets_path = os.path.join(os.getcwd(), "pull_secret.json")
    if not os.path.exists(args.secrets_path):
        url = "https://console.redhat.com/openshift/install/pull-secret"
        logger.info(f"Missing secrets file at {args.secrets_path}, get it from {url}")
        sys.exit(-1)
    return args
