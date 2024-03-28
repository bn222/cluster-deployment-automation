import pytest
import os
from typing import Optional
from typing import Any

import host


def get_user() -> Optional[str]:
    return os.environ.get("USER")


def skip_unless_ssh(host: str, user: str) -> None:
    import paramiko

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
            return

    pytest.skip(f"Skip ssh test. Ensure passwordless login to {user}@localhost works")


def _connect() -> tuple[str, host.Host]:
    user = get_user() or "root"
    skip_unless_ssh("127.0.0.1", user)

    rsh = host.RemoteHost("127.0.0.1")
    rsh.ssh_connect(user)

    return user, rsh


def _run(rsh: host.Host, *a: Any, compare_local: bool = True, **kw: Any) -> tuple[int, str, str]:
    xres = rsh.run(*a, **kw)
    res = (xres.returncode, xres.out, xres.err)

    if compare_local:
        lsh = host.LocalHost()
        xres2 = lsh.run(*a, **kw)
        res2 = (xres2.returncode, xres2.out, xres2.err)
        assert res == res2

    return res


def test_remote() -> None:
    user, rsh = _connect()
    assert _run(rsh, ["echo", "he > llo", "<", "'", "foo"]) == (0, "he > llo < ' foo\n", "")
    assert _run(rsh, "echo -n out ; echo -n outstderr 1>&2 ; exit 7") == (7, "out", "outstderr")
    assert _run(rsh, "echo out ; echo \"$USER\"; echo -n outstderr 1>&2 ; exit 7") == (7, f"out\n{user}\n", "outstderr")
    assert _run(rsh, "echo out \n echo err 1>&2 \n exit 35") == (35, "out\n", "err\n")

    cmd = """
       echo hello \
            echo world
    """
    assert _run(rsh, cmd) == (0, "hello echo world\n", "")

    cmd = """
       echo "hello \
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


def test_remote_user() -> None:
    user, rsh = _connect()
    assert _run(rsh, "whoami") == (0, f"{user}\n", "")


def test_remote_cwd() -> None:
    user, rsh = _connect()
    assert _run(rsh, "echo \"$FOO\";echo stderr 1>&2; pwd", compare_local=False, env_extra={"FOO": "x1"}, cwd="/tmp") == (0, "x1\n/tmp\n", "stderr\n")


def test_remote_sudo() -> None:
    user, rsh = _connect()

    r = _run(rsh, "sudo -n whoami")
    if r != (0, "root\n", ""):
        pytest.skip(f"sudo on {user}@localhost does not seem to work passwordless ({r})")

    rsh.need_sudo()

    assert _run(rsh, "echo -n out ; echo -n outstderr 1>&2 ; exit 7") == (7, "out", "outstderr")
    assert _run(rsh, "whoami", compare_local=False) == (0, "root\n", "")
    assert _run(rsh, "whoami;echo \"$FOO\"", compare_local=False, env_extra={"FOO": "x1"}) == (0, "root\nx1\n", "")
    assert _run(rsh, "whoami;echo \"$FOO\";pwd", compare_local=False, env_extra={"FOO": "x1"}, cwd="/tmp") == (0, "root\nx1\n/tmp\n", "")
