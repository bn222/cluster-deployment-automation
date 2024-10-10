import functools

from . import firewall
from . import host


@functools.cache
def has_nft_cmd() -> bool:
    return host.local.run("bash -c 'command -v nft'").success


def test_nft_cmd_masquerade() -> None:
    assert (
        firewall.nft_data_masquerade_down(table_name="foo")
        == """add table ip foo
delete table ip foo
"""
    )
    assert (
        firewall.nft_data_masquerade_up(
            table_name="foo",
            subnet="191.168.5.0/24",
            ifname="eno4",
        )
        == """add table ip foo
flush table ip foo
add chain ip foo nat_postrouting { type nat hook postrouting priority 100; policy accept; };
add rule ip foo nat_postrouting ip saddr 191.168.5.0/24 ip daddr != 191.168.5.0/24 masquerade;
add chain ip foo filter_forward { type filter hook forward priority 0; policy accept; };
add rule ip foo filter_forward ip daddr 191.168.5.0/24 oifname "eno4"  ct state { established, related } accept;
add rule ip foo filter_forward ip saddr 191.168.5.0/24 iifname "eno4" accept;
add rule ip foo filter_forward iifname "eno4" oifname "eno4" accept;
add rule ip foo filter_forward iifname "eno4" reject;
add rule ip foo filter_forward oifname "eno4" reject;
"""
    )


def test_nft_call() -> None:
    data = firewall.nft_data_masquerade_down(table_name="foo")
    res = firewall.nft_call(data, nft_cmd="cat")
    assert res == host.Result(data, "", 0)

    res = firewall.nft_call(data, nft_cmd="echo foo 1>&2; cat")
    assert res == host.Result(data, "foo\n", 0)

    data = firewall.nft_data_masquerade_up(
        table_name="foo",
        subnet="192.168.5.0/24",
        ifname="eth0",
    )
    res = firewall.nft_call(data, nft_cmd="bash -c 'echo hi; cat'")
    assert res == host.Result("hi\n" + data, "", 0)

    if has_nft_cmd():
        # Usually, nft requires CAP_NET_ADMIN, so it's unsuitable for unit
        # tests (unless we create a seprate netns). But if we pipe in nothing
        # it also does nothing. So let's call that.
        res = firewall.nft_call("")
        assert res == host.Result("", "", 0)
