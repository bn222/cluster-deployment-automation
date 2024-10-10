import shlex

from . import host


def _nft_cmd_table(*, up: bool, family: str, table_name: str) -> str:
    return (
        f"add table {family} {table_name}\n"
        f"{'flush' if up else 'delete'} table {family} {table_name}\n"
    )


def nft_data_delete_table(
    *,
    family: str,
    table_name: str,
) -> str:
    return _nft_cmd_table(up=False, family=family, table_name=table_name)


def nft_data_masquerade_down(
    table_name: str,
) -> str:
    return nft_data_delete_table(family="ip", table_name=table_name)


def nft_data_masquerade_up(
    *,
    table_name: str,
    subnet: str,
    ifname: str,
) -> str:
    """
    Generate the input for `nft -f -` to setup masquerading. It only creates
    a string. Pass this to nft_call().

    Args:
        table_name: the nft table to use. All changes are solely in this table, and you
          can discard the changes by deleting this table (see also, nft_data_masquerade_down()).
        subnet: the IPv4 subnet to masquerade. This is the range of the IP addresses of the clients that want
          to do SNAT.
        ifname: the interface to which the clients that want dynamic SNAT to be done. This is not the
          WAN interface, instead, masquerading detects the external IP address automatically.

    Example:

        nft_call(nft_data_masquerade_up(table_name="mytable", subnet="192.168.5.0/24", ifname="eth2"))
    """
    # Taken from NetworkManager:
    # https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/8488162d1069defada6be0666175ffd10f333f9d/src/core/nm-firewall-utils.c#L688
    return _nft_cmd_table(up=True, family="ip", table_name=table_name) + (
        f"add chain ip {table_name} nat_postrouting {{"
        " type nat hook postrouting priority 100; policy accept; "
        "};\n"
        f"add rule ip {table_name} nat_postrouting ip saddr {subnet} ip daddr != {subnet} masquerade;\n"
        f"add chain ip {table_name} filter_forward {{"
        " type filter hook forward priority 0; policy accept; "
        "};\n"
        f'add rule ip {table_name} filter_forward ip daddr {subnet} oifname "{ifname}" '
        " ct state { established, related } accept;\n"
        f'add rule ip {table_name} filter_forward ip saddr {subnet} iifname "{ifname}" accept;\n'
        f'add rule ip {table_name} filter_forward iifname "{ifname}" oifname "{ifname}" accept;\n'
        f'add rule ip {table_name} filter_forward iifname "{ifname}" reject;\n'
        f'add rule ip {table_name} filter_forward oifname "{ifname}" reject;\n'
    )


def nft_call(
    data: str,
    rsh: host.Host = host.local,
    *,
    nft_cmd: str = "nft -f -",
) -> host.Result:
    """
    Calls a subprocess (via rsh.run()) with `nft -f -`. Data is fed into
    stdin of the nft process.

    Args:
        data: the data for nft. Use for example nft_data_masquerade_up() to generate it.
        rsh: the Host instance one which to call nft.
        nft_cmd: defaults to "nft -f -". This is a shell script that receives data on stdin.
            Note that if you set this, you must make sure that this is the full shell script
            that does something similar as "nft -f -".
    """
    return rsh.run(f"printf '%s' {shlex.quote(data)} | {{ {nft_cmd} ; }}")
