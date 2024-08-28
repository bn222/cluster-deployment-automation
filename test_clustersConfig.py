import dataclasses
import os
import typing

import clustersConfig


@dataclasses.dataclass(frozen=True)
class TFileConfig:
    filename: str
    check: typing.Optional[
        typing.Callable[
            ["TFileConfig", clustersConfig.ClustersConfig],
            None,
        ]
    ] = None


def get_filepath(*components: str) -> str:
    return os.path.join(os.path.dirname(__file__), *components)


def _test_parse_1(tfile: TFileConfig) -> None:
    yamlpath = get_filepath(tfile.filename)
    cc = clustersConfig.ClustersConfig(
        yamlpath,
        secrets_path="/secrets/path",
        test_only=True,
    )
    assert isinstance(cc, clustersConfig.ClustersConfig)

    assert isinstance(cc.hosts, list)
    assert all(isinstance(host, clustersConfig.HostConfig) for host in cc.hosts)

    if tfile.check is not None:
        tfile.check(tfile, cc)


def check_test5(tfile: TFileConfig, cc: clustersConfig.ClustersConfig) -> None:
    assert sorted(h.name for h in cc.hosts) == [
        '...',
        'foo',
        'localhost',
        'mycluster-worker-1',
    ]


TFILES = (
    TFileConfig("tests/configs/test1.yaml"),
    TFileConfig("tests/configs/test2.yaml"),
    TFileConfig("tests/configs/test3.yaml"),
    TFileConfig("tests/configs/test4.yaml"),
    TFileConfig("tests/configs/test5.yaml", check_test5),
)


def test_parse_1() -> None:
    for tfile in TFILES:
        _test_parse_1(tfile)
