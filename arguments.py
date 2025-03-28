import common
import os
import argparse
import sys
import logging
import argcomplete
import difflib
import typing
from extraConfigRunner import extra_config
from logger import logger, configure_logger
from typing import Optional

PRE_STEP = "pre"
MASTERS_STEP = "masters"
WORKERS_STEP = "workers"
POST_STEP = "post"


def all_steps() -> list[str]:
    return [PRE_STEP, MASTERS_STEP, WORKERS_STEP, POST_STEP]


def fuzzy_match(step: str) -> Optional[str]:
    matches = difflib.get_close_matches(step, all_steps(), n=1, cutoff=0.5)
    return matches[0] if matches else None


def join_valid_steps() -> str:
    return ','.join(all_steps())


def yaml_completer(prefix: str, parsed_args: str, **kwargs: str) -> list[str]:
    return [f for f in os.listdir('.') if (f.endswith(('.yaml', '.yml')) and f.startswith(prefix))]


def step_completer(prefix: str, parsed_args: str, **kwargs: str) -> list[str]:
    if not prefix:
        return all_steps()

    steps_entered = prefix.split(',')

    available_steps = set(all_steps()) - set(steps_entered)

    suggestions = []
    for step in available_steps:
        if step.startswith(steps_entered[-1]):
            suggestion = ','.join(steps_entered[:-1] + [step])
            if len(steps_entered) < len(all_steps()) - 1:
                suggestion += ','
            suggestions.append(suggestion)

    return suggestions


def remove_empty_strings(comma_string: str) -> list[str]:
    return list(filter(None, comma_string.split(",")))


def parse_args() -> argparse.Namespace:
    class WorkersIncludeExcludeAction(argparse.Action):
        def __call__(
            self,
            parser: argparse.ArgumentParser,
            namespace: argparse.Namespace,
            values: Optional[str | typing.Sequence[typing.Any]],
            option_string: Optional[str] = None,
        ) -> None:

            range_list: Optional[common.RangeList] = getattr(namespace, 'worker_range_accumulator', None)
            if range_list is None:
                range_list = common.RangeList()
                setattr(namespace, 'worker_range_accumulator', range_list)

            if option_string in ('-w', "--workers"):
                is_include = True
            else:
                assert option_string in ('-sw', "--skip-workers")
                is_include = False

            try:
                range_list._accumulate(is_include, values)
            except Exception:
                raise argparse.ArgumentError(self, f"Invalid {option_string} value {repr(values)} is not a range")

    parser = argparse.ArgumentParser(description='Cluster deployment automation')
    parser.add_argument('config', metavar='config', type=str, help='Yaml file with config').completer = yaml_completer  # type: ignore
    parser.add_argument('-v', '--verbosity', choices=['debug', 'info', 'warning', 'error', 'critical'], default='info', help='Set the logging level (default: info)')
    parser.add_argument('--secret', dest='secrets_path', default='', action='store', type=str, help='pull_secret.json path (default is in cwd)')
    parser.add_argument('--cda-config', dest='cda_config', default='/root/cda-config.yaml', action='store', type=str, help='defaults to /rooot/cda-config.yaml')
    parser.add_argument('--assisted-installer-url', dest='url', default='192.168.122.1', action='store', type=str, help='If set to 0.0.0.0 (the default), Assisted Installer will be started locally')

    subparsers = parser.add_subparsers(title='subcommands', dest='subcommand')

    config_list = "List of available post-deployment configurations:\n" + "\n".join(extra_config.keys())

    deploy_parser = subparsers.add_parser('deploy', help='Deploy clusters', epilog=config_list, formatter_class=argparse.RawDescriptionHelpFormatter)
    deploy_parser.add_argument('-t', '--teardown', dest='teardown', action='store_true', help='Remove anything that would be created by setting up the cluster(s)')
    deploy_parser.add_argument('-f', '--teardown-full', dest='teardown_full', action='store_true', help='Remove anything that would be created by setting up the cluster(s), included ai')

    deploy_parser.add_argument('-s', '--steps', dest='steps', type=str, default=join_valid_steps(), help=f'Comma-separated list of steps to run (by default: {join_valid_steps()})').completer = step_completer  # type: ignore
    deploy_parser.add_argument('-a', '--additional-post-config', dest='additional_post_config', type=str, default=join_valid_steps(), help='Post-deployment configuration to run')
    deploy_parser.add_argument('-d', '--skip-steps', dest='skip_steps', type=str, default="", help="Comma-separated list of steps to skip").completer = step_completer  # type: ignore
    deploy_parser.add_argument('-w', '--workers', action=WorkersIncludeExcludeAction, help='Range and/or list of workers to include')
    deploy_parser.add_argument('-sw', '--skip-workers', action=WorkersIncludeExcludeAction, help='Range and/or list of workers to exclude')

    snapshot_parser = subparsers.add_parser('snapshot', help='Take or restore snapshots')
    snapshot_parser.add_argument('loadsave', metavar='loadsave', type=str, help='Load or save a snapshot', choices=(("load", "save")))
    snapshot_parser.add_argument('--name', type=str, default=None, help="Name of the snapshot (default is name of cluster)")

    argcomplete.autocomplete(parser)

    args = parser.parse_args()
    if args.subcommand == "deploy":
        args.steps = remove_empty_strings(args.steps)
        args.skip_steps = remove_empty_strings(args.skip_steps)

        invalid_steps = []
        for s in args.steps + args.skip_steps:
            if s not in all_steps():
                invalid_steps.append(s)

        if invalid_steps:
            for step in invalid_steps:
                suggested_step = fuzzy_match(step)
                error_message = f"Invalid step: '{step}'"
                error_message += f" Did you mean '{suggested_step}'?" if suggested_step else ""
                logger.error(error_message)

            sys.exit(-1)

        args.steps = [x for x in args.steps if x not in args.skip_steps]

        range_list: Optional[common.RangeList] = getattr(args, 'worker_range_accumulator', None)
        args.worker_range = range_list or common.RangeList.UNLIMITED

    configure_logger(getattr(logging, args.verbosity.upper()))

    if not args.secrets_path:
        args.secrets_path = os.path.join(os.getcwd(), "pull_secret.json")
    if not os.path.exists(args.secrets_path):
        url = "https://console.redhat.com/openshift/install/pull-secret"
        logger.info(f"Missing secrets file at {args.secrets_path}, get it from {url}")
        sys.exit(-1)
    return args
