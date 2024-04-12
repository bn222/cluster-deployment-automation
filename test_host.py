import functools
import os
import paramiko
import pathlib
import pytest
import random
from typing import Optional
from typing import Any

import host


def get_user() -> Optional[str]:
    return os.environ.get("USER")


def _host_create(ip: Optional[str] = None) -> host.Host:
    # host.Host gets cached and reused. We don't want that
    # for the test.
    host.host_instances.clear()
    if ip is None:
        lsh = host.LocalHost()
    else:
        lsh = host.RemoteHost(ip)
    host.host_instances.clear()
    return lsh


def skip_unless_ssh(host: str, user: str) -> None:
    @functools.lru_cache
    def check(host: str, user: str) -> bool:

        client = paramiko.client.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, username=user, password="")
        except Exception:
            pass
        else:
            _in, _out, _err = client.exec_command("echo -n hello")
            _in.close()
            s_out = _out.read()
            s_err = _err.read()
            rc = _out.channel.recv_exit_status()
            if rc == 0 and s_out == b"hello" and s_err == b"":
                return True
        return False

    if not check(host, user):
        pytest.skip(f"Skip ssh test. Ensure passwordless login to {user}@localhost works")


def _connect() -> tuple[str, host.Host]:
    user = get_user() or "root"
    skip_unless_ssh("127.0.0.1", user)

    rsh = _host_create("127.0.0.1")
    rsh.ssh_connect(user)
    return user, rsh


def _run(rsh: host.Host, *a: Any, compare_local: bool = True, **kw: Any) -> tuple[int, str, str]:
    xres = rsh.run(*a, **kw)
    res = (xres.returncode, xres.out, xres.err)

    if compare_local:
        lsh = _host_create()
        xres2 = lsh.run(*a, **kw)
        assert res == (xres2.returncode, xres2.out, xres2.err)

    return res


def test_remote() -> None:
    user, rsh = _connect()
    assert _run(rsh, ["echo", "he > llo", "<", "'", "foo"]) == (
        0,
        "he > llo < ' foo\n",
        "",
    )
    assert _run(rsh, "echo -n out ; echo -n outstderr 1>&2 ; exit 7") == (
        7,
        "out",
        "outstderr",
    )
    assert _run(rsh, 'echo out ; echo "$USER"; echo -n outstderr 1>&2 ; exit 7') == (
        7,
        f"out\n{user}\n",
        "outstderr",
    )
    assert _run(rsh, "echo out \n echo err 1>&2 \n exit 35") == (35, "out\n", "err\n")

    cmd = """
       echo hello \
            echo world
    """
    assert _run(rsh, cmd) == (0, "hello echo world\n", "")

    cmd = """
       echo hello \\
            echo world
    """
    assert _run(rsh, cmd) == (0, "hello echo world\n", "")

    cmd = """
       echo "hello \
            echo world"
    """
    assert _run(rsh, cmd) == (0, "hello             echo world\n", "")

    cmd = """
       echo "hello \\
            echo world"
    """
    assert _run(rsh, cmd) == (0, "hello             echo world\n", "")

    cmd = """
       echo "hello
            echo world"
    """
    assert _run(rsh, cmd) == (0, "hello\n            echo world\n", "")

    cmd = """
       echo hello
            echo world
    """
    assert _run(rsh, cmd) == (0, "hello\nworld\n", "")


def test_user_remote() -> None:
    user, rsh = _connect()
    assert _run(rsh, "whoami") == (0, f"{user}\n", "")


def test_cwd_remote() -> None:
    user, rsh = _connect()
    assert _run(
        rsh,
        'echo "$FOO";echo stderr 1>&2; pwd',
        compare_local=False,
        env={"FOO": "x1"},
        cwd="/tmp",
    ) == (0, "x1\n/tmp\n", "stderr\n")


def _test_binary(rsh: host.Host) -> None:
    with pytest.raises(UnicodeDecodeError):
        rsh.run(["bash", "-c", "printf $'\''<\\xff>'\''"])


def test_binary_local() -> None:
    _test_binary(_host_create())


def test_binary_remote() -> None:
    user, rsh = _connect()
    _test_binary(rsh)


def test_sudo_remote() -> None:
    user, rsh = _connect()

    r = _run(rsh, "sudo -n whoami")
    if r != (0, "root\n", ""):
        pytest.skip(f"sudo on {user}@localhost does not seem to work passwordless ({r})")

    rsh.need_sudo()

    assert _run(rsh, "echo -n out ; echo -n outstderr 1>&2 ; exit 7") == (
        7,
        "out",
        "outstderr",
    )
    assert _run(rsh, "whoami", compare_local=False) == (0, "root\n", "")
    assert _run(rsh, 'whoami;echo "$FOO"', compare_local=False, env={"FOO": "x1"}) == (0, "root\nx1\n", "")
    assert _run(
        rsh,
        'whoami;echo "$FOO";pwd',
        compare_local=False,
        env={"FOO": "x1"},
        cwd="/tmp",
    ) == (0, "root\nx1\n/tmp\n", "")


def test_sudo_local() -> None:
    lsh = host.LocalHost()

    r = _run(lsh, "sudo -n whoami")
    if r != (0, "root\n", ""):
        if os.environ.get("CDA_GITHUB_CI") is not None:
            pytest.fail(f"sudo on localhost does not seem to work passwordless ({r})")
        pytest.skip(f"sudo on localhost does not seem to work passwordless ({r})")

    lsh.need_sudo()

    assert _run(lsh, 'whoami;echo "$FOO"', compare_local=False, env={"FOO": "x1"}) == (0, "root\nx1\n", "")
    assert _run(
        lsh,
        'whoami;echo "$FOO"',
        compare_local=False,
        env={"XXXX": "hi", "FOO": "x1"},
    ) == (0, "root\nx1\n", "")
    assert _run(
        lsh,
        'whoami;echo "$FOO";pwd',
        compare_local=False,
        env={"XXXX": "hi", "FOO": "x1"},
        cwd="/tmp",
    ) == (0, "root\nx1\n/tmp\n", "")


def test_large_output_remote() -> None:
    user, rsh = _connect()

    # Write a large amount of data to stderr. See whether we block.
    mebibytes = 2048
    ret = rsh.run(
        """
        msg="0123456789abcdef"
        for i in $(seq 1 6) ; do
            msg="$msg$msg"
        done
        for i in $(seq 1 "$MEBIBYTES") ; do
            printf "%s" "$msg"
        done 1>&2
        printf stdout-done
        """,
        env={"MEBIBYTES": str(mebibytes)},
    )
    assert ret.returncode == 0
    assert ret.out == "stdout-done"
    assert ret.err.startswith("0123456789abcdef0123")
    assert len(ret.err) == mebibytes * 1024


def _test_write_one(tmp_path: pathlib.Path, rsh: host.Host, contents: str | bytes, *, recurse: bool = True) -> None:

    filename = str(tmp_path / "file1")

    # Test randomly to have or not have the file. The write should overwrite or
    # create the file.
    if random.randint(0, 1):
        if os.path.exists(filename):
            os.remove(filename)
    else:
        if not os.path.exists(filename):
            with open(filename, "wb") as f:
                f.write(b'')

    is_utf8 = True
    if isinstance(contents, str):
        b_contents = contents.encode('utf-8')
    else:
        b_contents = contents
        try:
            b_contents.decode('utf-8', errors='strict')
        except ValueError:
            is_utf8 = False

    rsh.write(filename, contents)

    if is_utf8:
        out = rsh.read_file(filename)

        assert isinstance(out, str)

        if isinstance(contents, str):
            assert out == contents

        b_out = out.encode('utf-8')
        assert b_out == b_contents
    else:
        try:
            out = rsh.read_file(filename)
        except UnicodeDecodeError:
            out = None
        else:
            pytest.fail("Did not get the expected unicode error writing binary data")

    with open(filename, "rb") as f:
        b_out2 = f.read()
    assert b_out2 == b_contents

    if recurse:
        # Also test whether the same check passes with binary.
        if isinstance(contents, str):
            _test_write_one(tmp_path, rsh, contents.encode('utf-8'), recurse=False)
        if isinstance(contents, bytes) and is_utf8:
            _test_write_one(tmp_path, rsh, contents.decode('utf-8'), recurse=False)


def _test_write(tmp_path: pathlib.Path, rsh: host.Host) -> None:
    _test_write_one(tmp_path, rsh, "")
    _test_write_one(tmp_path, rsh, "\n")
    _test_write_one(tmp_path, rsh, "\r\n")
    _test_write_one(tmp_path, rsh, "foo\r\n")
    for i in range(10):
        _test_write_one(tmp_path, rsh, random.randbytes(int(i % 10)))


def test_write_local(tmp_path: pathlib.Path) -> None:
    _test_write(tmp_path, host.LocalHost())


def test_write_remote(tmp_path: pathlib.Path) -> None:
    user, rsh = _connect()
    _test_write(tmp_path, rsh)
