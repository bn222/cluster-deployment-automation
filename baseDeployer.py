import abc
from extraConfigRunner import ExtraConfigRunner
from clustersConfig import ClustersConfig, ExtraConfigArgs
import host
from typing import Optional
from concurrent.futures import Future
import timer
import collections


class BaseDeployer(abc.ABC):
    def __init__(self, cc: ClustersConfig, steps: list[str]):
        self._cc = cc
        self._extra_config = ExtraConfigRunner(cc)
        self._futures: dict[str, Future[Optional[host.Result]]] = {}
        self.steps = tuple(steps)

    def _prepost_config(self, to_run: ExtraConfigArgs) -> None:
        self._extra_config.run(to_run, self._futures)

    def _preconfig(self) -> None:
        for e in self._cc.preconfig:
            self._prepost_config(e)

    def _postconfig(self) -> None:
        for e in self._cc.postconfig:
            self._prepost_config(e)

    def _empty_timers(self) -> dict[str, timer.Timer]:
        return collections.defaultdict(lambda: timer.Timer.EmptyTimer())
