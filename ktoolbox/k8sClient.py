import json
import logging
import os
import random
import shlex
import sys
import typing
import yaml

from collections.abc import Iterable
from typing import Union

from . import host


logger = logging.getLogger(__name__)


class K8sClient:
    def __init__(self, kubeconfig: typing.Optional[str] = None):
        if kubeconfig is None:
            kubeconfig = os.getenv("KUBECONFIG")
            if not kubeconfig:
                raise RuntimeError(
                    "KUBECONFIG environment variable not set and no kubeconfig argument specified"
                )

        if not os.path.exists(kubeconfig):
            raise RuntimeError(
                f"KUBECONFIG={shlex.quote(kubeconfig)} file does not exist"
            )
        # Load the file to check that it is valid YAML.
        with open(kubeconfig) as f:
            yaml.safe_load(f)

        self.kubeconfig = kubeconfig

    @staticmethod
    def _get_oc_cmd(cmd: Union[str, Iterable[str]]) -> list[str]:
        if isinstance(cmd, str):
            return shlex.split(cmd)
        return list(cmd)

    def _get_oc_cmd_full(
        self,
        *,
        cmd: Union[str, Iterable[str]],
        namespace: typing.Optional[str] = None,
    ) -> list[str]:
        namespace_args: tuple[str, ...]
        if namespace:
            namespace_args = ("-n", namespace)
        else:
            namespace_args = ()
        return [
            "kubectl",
            "--kubeconfig",
            self.kubeconfig,
            *namespace_args,
            *self._get_oc_cmd(cmd),
        ]

    def oc(
        self,
        cmd: Union[str, Iterable[str]],
        *,
        may_fail: bool = False,
        die_on_error: bool = False,
        check_success: typing.Optional[typing.Callable[[host.Result], bool]] = None,
        namespace: typing.Optional[str] = None,
    ) -> host.Result:
        return host.local.run(
            self._get_oc_cmd_full(cmd=cmd, namespace=namespace),
            die_on_error=die_on_error,
            check_success=check_success,
            log_level_fail=logging.DEBUG if may_fail else logging.ERROR,
        )

    def oc_exec(
        self,
        cmd: Union[str, Iterable[str]],
        *,
        pod_name: str,
        may_fail: bool = False,
        die_on_error: bool = False,
        namespace: typing.Optional[str] = None,
    ) -> host.Result:
        return self.oc(
            ["exec", pod_name, "--", *self._get_oc_cmd(cmd)],
            may_fail=may_fail,
            die_on_error=die_on_error,
            namespace=namespace,
        )

    def oc_get(
        self,
        what: str,
        *,
        may_fail: bool = False,
        die_on_error: bool = False,
        namespace: typing.Optional[str] = None,
    ) -> typing.Optional[dict[str, typing.Any]]:
        cmd = ["get", what, "-o", "json"]
        ret = self.oc(
            cmd,
            may_fail=may_fail,
            die_on_error=die_on_error,
            namespace=namespace,
        )

        if not ret.success:
            # No need for extra logging in this failure case. self.oc() already
            # did all the logging we want.
            return None

        try:
            data = json.loads(ret.out)
        except ValueError:
            data = None

        if not isinstance(data, dict):
            cmd_s = shlex.join(self._get_oc_cmd_full(cmd=cmd, namespace=namespace))
            if not may_fail or die_on_error:
                logger.error(
                    f"Command {cmd_s} did not return a JSON dictionary but {ret.debug_str()}"
                )
            else:
                logger.debug(f"Command {cmd_s} did not return a JSON dictionary")
            if die_on_error:
                sys.exit(-1)
            return None

        return data

    def oc_debug(
        self,
        cmd: Union[str, Iterable[str]],
        *,
        node_name: str,
        test_image: str,
        namespace: str,
        may_fail: bool = False,
        die_on_error: bool = False,
    ) -> host.Result:
        container_name = f"ocp-tft-debug-{node_name}-{random.randint(0, 2**64-1):016x}"
        # We use `kubectl debug` and not `oc debug`. There are thus some differences.
        #
        # Optimally, we would use "--profile=sysadmin". But that is too new, so
        # we cannot use it and have no CAP_SYS_CHROOT.  That means, `cmd`
        # cannot be `chroot /host crictl ...` but needs to be
        # `/host/usr/bin/crictl --runtime-endpoint=unix:///host/run/crio/crio.sock ...`.
        #
        # Also, unlike `oc debug`, we need an "--image", which the caller must specify.
        #
        # Also, we must specify a namespace. And the container will linger around afterwards,
        # so we need to delete it (below).
        result = self.oc(
            [
                "debug",
                "-q",
                "-ti",
                "--profile=general",
                f"--container={container_name}",
                f"--image={test_image}",
                f"node/{node_name}",
                "--",
                *self._get_oc_cmd(cmd),
            ],
            may_fail=may_fail,
            die_on_error=die_on_error,
            namespace=namespace,
        )

        # We have to find and delete the pods we just created. As we used
        # a unique {container_name}, we can search for that.
        pod_names = []
        pdict = self.oc_get(
            "pods",
            may_fail=True,
            namespace=namespace,
        )
        pdict_items = []
        if pdict is not None:
            try:
                pdict_items = list(pdict["items"])
            except Exception:
                pass
        for pdict_item in pdict_items:
            try:
                for c in pdict_item["spec"]["containers"]:
                    if c["name"] == container_name:
                        pod_names.append(pdict_item["metadata"]["name"])
                        break
            except Exception:
                pass
        for pod_name in pod_names:
            self.oc(
                ["delete", "--wait=false", f"pod/{pod_name}"],
                may_fail=True,
                namespace=namespace,
            )

        return result

    @staticmethod
    def check_success_delete_ignore_noexist(
        resource_type: str,
    ) -> typing.Callable[[host.Result], bool]:
        return lambda r: (
            r.returncode == 0
            or r.match(
                out="",
                err=f'error: the server doesn\'t have a resource type "{resource_type}"\n',
                returncode=1,
            )
        )
