import common
import os
import argparse
import sys
import logging
from argcomplete.completers import EnvironCompleter, ChoicesCompleter
import argcomplete
from logger import logger, configure_logger

VALID_STEPS = ["pre", "masters", "workers", "post"]


def yaml_completer(prefix, parsed_args, **kwargs):
    return (f for f in os.listdir('.') if (f.endswith(('.yaml', '.yml')) and f.startswith(prefix)))


def step_completer(prefix, parsed_args, **kwargs):
    if not prefix:
        return VALID_STEPS

    steps_entered = prefix.split(',')

    available_steps = list(set(VALID_STEPS) - set(steps_entered))

    suggestions = []
    for step in available_steps:
        if step.startswith(steps_entered[-1]):
            suggestion = ','.join(steps_entered[:-1] + [step])
            if len(steps_entered) < len(VALID_STEPS) - 1:
                suggestion += ','
            suggestions.append(suggestion)

    return suggestions


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Cluster deployment automation')
    parser.add_argument('config', metavar='config', type=str, help='Yaml file with config').completer = yaml_completer
    parser.add_argument('-v', '--verbosity', choices=['debug', 'info', 'warning', 'error', 'critical'], default='info', help='Set the logging level (default: info)').completer = ChoicesCompleter(['debug', 'info', 'warning', 'error', 'critical'])
    parser.add_argument('--secret', dest='secrets_path', default='', action='store', type=str, help='pull_secret.json path (default is in cwd)')
    parser.add_argument('--assisted-installer-url', dest='url', default='192.168.122.1', action='store', type=str, help='If set to 0.0.0.0 (the default), Assisted Installer will be started locally')

    subparsers = parser.add_subparsers(title='subcommands', dest='subcommand')
    deploy_parser = subparsers.add_parser('deploy', help='Deploy clusters')
    deploy_parser.add_argument('-t', '--teardown', dest='teardown', action='store_true', help='Remove anything that would be created by setting up the cluster(s)')
    deploy_parser.add_argument('-f', '--teardown-full', dest='teardown_full', action='store_true', help='Remove anything that would be created by setting up the cluster(s), included ai')

    deploy_parser.add_argument('-s', '--steps', dest='steps', type=str, default=','.join(VALID_STEPS), help=f'Comma-separated list of steps to run (by default: {",".join(VALID_STEPS)})').completer = step_completer
    deploy_parser.add_argument('-d', '--skip-steps', dest='skip_steps', type=str, default="", help=f"Comma-separated list of steps to skip").completer = step_completer
    deploy_parser.add_argument('-w', '--workers', dest='workers', type=common.str_to_list, nargs='?', help='Range and/or list of workers to include')
    deploy_parser.add_argument('-sw', '--skip-workers', dest='skip_workers', type=common.str_to_list, nargs='?', default=[], help='Range and/or list of workers to exclude')

    snapshot_parser = subparsers.add_parser('snapshot', help='Take or restore snapshots')
    snapshot_parser.add_argument('loadsave', metavar='loadsave', type=str, help='Load or save a snapshot').completer = ChoicesCompleter(["load", "save"])
    snapshot_parser.add_argument('--name', type=str, default=None, help="Name of the snapshot (default is name of cluster)")

    argcomplete.autocomplete(parser)

    args = parser.parse_args()
    if args.subcommand == "deploy":
        args.steps = list(filter(None, args.steps.split(",")))
        args.skip_steps = list(filter(None, args.skip_steps.split(",")))

        invalid_steps = [step for step in args.steps + args.skip_steps if step not in VALID_STEPS]
        if invalid_steps:
            logger.error(f"Invalid step(s): {','.join(invalid_steps)}.\n Remember to make them plural ('masters' not 'master')")
            sys.exit(-1)

        args.steps = [x for x in args.steps if x not in args.skip_steps]
        args.worker_range = common.RangeList(args.workers)
        args.worker_range.exclude(args.skip_workers)

    log_levels = {'debug': logging.DEBUG, 'info': logging.INFO, 'warning': logging.WARNING, 'error': logging.ERROR, 'critical': logging.CRITICAL}
    args.verbosity = log_levels[args.verbosity]
    configure_logger(args.verbosity)

    if not args.secrets_path:
        args.secrets_path = os.path.join(os.getcwd(), "pull_secret.json")
    if not os.path.exists(args.secrets_path):
        url = "https://console.redhat.com/openshift/install/pull-secret"
        logger.info(f"Missing secrets file at {args.secrets_path}, get it from {url}")
        sys.exit(-1)
    return args
