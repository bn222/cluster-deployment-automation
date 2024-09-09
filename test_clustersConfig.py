import dataclasses
import os
import pathlib
import pytest
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
    basedir = "/tmp"
    rnd_seed = f"rnd_seed:{tfile}"
    yamlpath = get_filepath(tfile.filename)

    cc = clustersConfig.ClustersConfig(
        yamlpath,
        secrets_path="/secrets/path",
        basedir=basedir,
        rnd_seed=rnd_seed,
        get_last_ip=lambda: None,
        test_only=True,
    )
    assert isinstance(cc, clustersConfig.ClustersConfig)

    assert isinstance(cc.hosts, dict)
    assert all(isinstance(host, clustersConfig.HostConfig) and host.name == name for name, host in cc.hosts.items())

    main_config = clustersConfig.MainConfig.load(
        yamlpath,
        basedir=basedir,
        rnd_seed=rnd_seed,
    )
    assert isinstance(main_config, clustersConfig.MainConfig)
    assert main_config == cc.main_config

    if tfile.check is not None:
        tfile.check(tfile, cc)

    assert cc.main_config.yamlpath == ""
    assert cc.main_config.clusters[0].yamlpath == ".clusters[0]"

    vdict = cc.cluster_config.serialize(show_secrets=True)
    cluster_config2 = clustersConfig.ClusterConfig.parse(
        0,
        ".clusters[0]",
        vdict,
        basedir=basedir,
    )
    assert cc.cluster_config == cluster_config2

    for yamlidx2, host in enumerate(cc.hosts.values()):
        vdict = host.serialize(show_secrets=True)
        if host.network_api_port_is_default:
            default_network_api_port = host.network_api_port
        else:
            default_network_api_port = None
        host2 = clustersConfig.HostConfig.parse(
            yamlidx2,
            f".clusters[0].hosts[{yamlidx2}]",
            vdict,
            default_network_api_port=default_network_api_port,
        )
        assert host == host2

    for yamlidx2, node in enumerate(cc.masters):
        vdict = node.serialize(show_secrets=True)
        node2 = clustersConfig.NodeConfig.parse(
            yamlidx2,
            f".clusters[0].masters[{yamlidx2}]",
            vdict,
            cluster_kind=cc.kind,
            cluster_name=cc.name,
            rnd_seed=rnd_seed,
        )
        assert node == node2

    for yamlidx2, node in enumerate(cc.cluster_config.workers.values()):
        vdict = node.serialize(show_secrets=True)
        node2 = clustersConfig.NodeConfig.parse(
            yamlidx2,
            f".clusters[0].workers[{yamlidx2}]",
            vdict,
            cluster_kind=cc.kind,
            cluster_name=cc.name,
            rnd_seed=rnd_seed,
        )
        assert node == node2


def check_test5(tfile: TFileConfig, cc: clustersConfig.ClustersConfig) -> None:
    assert tuple(cc.hosts.values()) == (
        clustersConfig.HostConfig(
            yamlpath=".clusters[0].hosts[0]",
            yamlidx=0,
            name="mycluster-worker-1",
            network_api_port=None,
            network_api_port_is_default=False,
            username="core",
            password=None,
            pre_installed=True,
        ),
        clustersConfig.HostConfig(
            yamlpath=".clusters[0].hosts[1]",
            yamlidx=1,
            name="foo",
            network_api_port="xxxx",
            network_api_port_is_default=False,
            username="core",
            password=None,
            pre_installed=True,
        ),
        clustersConfig.HostConfig(
            yamlpath=".clusters[0].hosts[2]",
            yamlidx=2,
            name="localhost",
            network_api_port=None,
            network_api_port_is_default=True,
            username="core",
            password=None,
            pre_installed=True,
        ),
        clustersConfig.HostConfig(
            yamlpath=".clusters[0].hosts[3]",
            yamlidx=3,
            name="...",
            network_api_port=None,
            network_api_port_is_default=True,
            username="core",
            password=None,
            pre_installed=True,
        ),
    )

    assert cc.masters[0] == clustersConfig.NodeConfig(
        yamlpath=".clusters[0].masters[0]",
        yamlidx=0,
        name="mycluster-master-1",
        kind="vm",
        node="localhost",
        ip="192.168.122.41",
        mac_explicit=None,
        mac_random=cc.masters[0].mac_random,
        image_path=cc.masters[0].image_path,
        bmc=None,
        bmc_user=None,
        bmc_password=None,
        os_variant=cc.masters[0].os_variant,
        preallocated=cc.masters[0].preallocated,
        disk_size=cc.masters[0].disk_size,
        ram=cc.masters[0].ram,
        cpu=cc.masters[0].cpu,
    )

    assert cc.cluster_config.postconfig[1].dpu_operator_path == "../"
    assert cc.cluster_config.postconfig[1].dpu_operator_path_abs == os.path.dirname(cc.cluster_config.main_config.yamldir)


TFILES = (
    TFileConfig("tests/configs/test1.yaml"),
    TFileConfig("tests/configs/test2.yaml"),
    TFileConfig("tests/configs/test3.yaml"),
    TFileConfig("tests/configs/test4.yaml"),
    TFileConfig("tests/configs/test5.yaml", check_test5),
    TFileConfig("tests/configs/test6.yaml"),
    TFileConfig("tests/configs/test7.yaml"),
    TFileConfig("tests/configs/test8.yaml"),
    TFileConfig("tests/configs/test9.yaml"),
    TFileConfig("tests/configs/test10.yaml"),
    TFileConfig("tests/configs/test11.yaml"),
    TFileConfig("microshift.yml"),
)


@pytest.mark.parametrize("tfile", TFILES)
def test_parse_1(tfile: TFileConfig) -> None:
    _test_parse_1(tfile)


def test_parse_2(tmp_path: pathlib.Path) -> None:
    def _load(yaml: str) -> clustersConfig.MainConfig:
        yamlpath = str(tmp_path / "testfile1")
        with open(yamlpath, "w") as f:
            f.write(yaml)
        return clustersConfig.MainConfig.load(
            yamlpath,
            basedir="/tmp",
            rnd_seed="rndseed:test_parse_2",
        )

    with pytest.raises(ValueError):
        _load("")

    with pytest.raises(ValueError):
        _load("clusters:\n")

    with pytest.raises(ValueError):
        _load("clusters: []")

    main_config = _load(
        """clusters:
    - name: mycluster1
      api_vip: "192.168.122.99"
      ingress_vip: "192.168.122.101"
"""
    )
    assert main_config
    assert main_config.clusters[0].name == "mycluster1"

    with pytest.raises(ValueError) as ex:
        _load(
            """clusters:
    - name: mycluster1
      api_vip: "192.168.122.99"
      ingress_vip: "192.168.122.101"
    - name: mycluster2
      api_vip: "192.168.122.99"
      ingress_vip: "192.168.122.101"
"""
        )
    assert "currently only one entry in the clusters list is supported" in str(ex.value)
