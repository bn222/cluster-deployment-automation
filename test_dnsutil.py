import pathlib

from typing import Optional

import dnsutil


def test_resolv_conf_parse_file(tmp_path: pathlib.Path) -> None:
    def _rc(content: str | bytes) -> tuple[list[str], list[str]]:
        filename = str(tmp_path / "rcfile")
        if isinstance(content, str):
            content = content.encode('utf-8')
        with open(filename, "wb") as f:
            f.write(content)
        rcdata = dnsutil._resolvconf_parse_file(filename)
        return (rcdata.nameservers, rcdata.searches)

    assert _rc("nameserver  1.2.3.4") == (["1.2.3.4"], [])
    assert _rc("nameserver  1::04") == (["1::4"], [])
    assert _rc("nameserver 1::04") == (["1::4"], [])
    assert _rc("nameserver1::04") == ([], [])
    assert _rc("nameserver\t1::04") == (["1::4"], [])
    assert _rc("\n\tnameserver\t1::04\t\n") == (["1::4"], [])
    assert _rc(b"nameserver\t1::0\xca4") == ([], [])
    assert _rc(b"nameserver\t1::0\xca4\nnameserver 1.2.3.4  ") == (["1.2.3.4"], [])
    assert _rc("search foo.com bar.com\nnameserver  1.2.3.4\n") == (["1.2.3.4"], ["foo.com", "bar.com"])
    assert _rc("search foo.com bar.com\n\nsearch xxx\nnameserver  1.2.3.4\n") == (["1.2.3.4"], ["xxx"])


def test_dnsmasq_servers_parse() -> None:
    def _update(old_content: bytes, cluster_name: Optional[str], api_vip: Optional[str] = None) -> tuple[bytes, list[bytes]]:
        content, entries = dnsutil._dnsmasq_servers_content_update(old_content, cluster_name, api_vip)
        assert content
        assert isinstance(content, bytes)
        assert isinstance(entries, list)

        # Reimplement the parsing, and see that we get the same result
        found_entries = []
        for line in content.split(b'\n'):
            assert line == line.strip()
            if not line:
                continue
            if line.startswith(b'#'):
                assert line == b"#" or line.startswith(b"# ")
                continue
            assert line.startswith(b"server=/")
            found_entries.append(line)
        assert entries == found_entries

        # parsing the content again, should yield the same entries.
        entries2 = dnsutil._dnsmasq_servers_content_parse(content)
        assert isinstance(entries, list)
        assert entries == entries2

        # Calling update on the new content, must give the identical output.
        content3, entries3 = dnsutil._dnsmasq_servers_content_update(content, cluster_name, api_vip)
        assert content3
        assert isinstance(content3, bytes)
        assert isinstance(entries3, list)
        assert content3 == content
        assert entries3 == entries

        return content, entries

    content, entries = _update(b"", "cluster1", "192.168.122.2")
    assert content == (
        b'# Written by cluster-deployment-automation for resolving cluster names.\n'
        b'# This file is passed to dnsmasq via the --servers-file= option\n'
        b'#\n'
        b'# You can reload after changes with\n'
        b'#   systemctl restart dnsmasq.service\n'
        b'#   systemctl kill -s SIGHUP dnsmasq.service\n'
        b'server=/*.api.cluster1.redhat.com/*.api-int.cluster1.redhat.com/#\n'
        b'server=/apps.cluster1.redhat.com/api.cluster1.redhat.com/api-int.cluster1.redhat.com/192.168.122.2\n'
    )
    assert entries == [
        b'server=/*.api.cluster1.redhat.com/*.api-int.cluster1.redhat.com/#',
        b'server=/apps.cluster1.redhat.com/api.cluster1.redhat.com/api-int.cluster1.redhat.com/192.168.122.2',
    ]

    content2, entries2 = _update(content, "cluster2", "192.168.123.2")
    assert entries2 == [
        b'server=/*.api.cluster1.redhat.com/*.api-int.cluster1.redhat.com/#',
        b'server=/*.api.cluster2.redhat.com/*.api-int.cluster2.redhat.com/#',
        b'server=/apps.cluster1.redhat.com/api.cluster1.redhat.com/api-int.cluster1.redhat.com/192.168.122.2',
        b'server=/apps.cluster2.redhat.com/api.cluster2.redhat.com/api-int.cluster2.redhat.com/192.168.123.2',
    ]

    content, entries = _update(b"", "cluster1", None)
    assert entries == []
