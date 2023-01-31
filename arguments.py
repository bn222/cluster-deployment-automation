import os
import argparse
import sys

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Set up or tear down a (set of) clusters.')
    parser.add_argument('config', metavar='config', type=str, help='Yaml file with config')
    parser.add_argument('-t', '--teardown', dest='teardown', action='store_true', help='Remove anything that would be created by setting up the cluster(s)')
    parser.add_argument('--assisted-installer-url', dest='url', default='192.168.122.1', action='store', type=str, help='If set to 0.0.0.0 (the default), Assisted Installer will be started locally')
    parser.add_argument('--secret', dest='secrets_path', default='', action='store', type=str, help='pull_secret.json path (default is in cwd)')
    steps = "pre,masters,workers,post"
    parser.add_argument('-s', '--steps', dest='steps', type=str, default=steps, help=f'Comma-separated list of steps to run (by default: {steps}).')

    args = parser.parse_args()

    if not args.secrets_path:
        args.secrets_path = os.path.join(os.getcwd(), "pull_secret.json")

    if not os.path.exists(args.secrets_path):
        url = "https://console.redhat.com/openshift/install/pull-secret"
        print(f"Missing secrets file at {args.secrets_path}, get it from {url}")
        sys.exit(-1)
    return args
