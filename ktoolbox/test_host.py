import functools
import logging
import os
import pathlib
import pytest
import random
import re
import sys

from collections.abc import Mapping
from typing import Any
from typing import Optional
from typing import Union

from . import host


def _rnd_log_lineoutput() -> dict[str, Any]:
    r = random.randint(0, 4)

    val: Optional[Union[int, bool]] = None
    if r <= 1:
        val = r == 0
    elif r == 2:
        val = -1
    elif r == 3:
        val = logging.DEBUG
    else:
        val = logging.ERROR

    if val is None:
        return {}
    return {
        "log_lineoutput": val,
    }


@functools.cache
def get_user() -> Optional[str]:
    return os.environ.get("USER")


@functools.cache
def has_sudo(rsh: host.Host) -> bool:
    r = rsh.run("sudo -n whoami")
    return r == host.Result("root\n", "", 0)


@functools.cache
def has_paramiko() -> bool:
    try:
        import paramiko

        assert paramiko.client
        return True
    except ModuleNotFoundError:
        return False


@functools.cache
def can_ssh_nopass(hostname: str, user: str) -> Optional[host.RemoteHost]:

    if not has_paramiko():
        return None

    import paramiko

    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname, username=user, password="")
    except Exception:
        pass
    else:
        _in, _out, _err = client.exec_command("echo -n hello")
        _in.close()
        s_out = _out.read()
        s_err = _err.read()
        rc = _out.channel.recv_exit_status()
        if rc == 0 and s_out == b"hello" and s_err == b"":
            rsh = host.RemoteHost(hostname, host.AutoLogin(user))
            assert rsh.run("whoami") == host.Result(f"{user}\n", "", 0)
            return rsh
    return None


def run_local(
    cmd: Union[str, list[str]],
    *,
    text: bool = True,
    env: Optional[Mapping[str, Optional[str]]] = None,
    cwd: Optional[str] = None,
) -> Union[host.Result, host.BinResult]:
    res = host.local.run(cmd, text=text, cwd=cwd, env=env)

    rsh = can_ssh_nopass("localhost", get_user())
    if rsh is not None:
        res2 = rsh.run(cmd, text=text, cwd=cwd, env=env)
        assert res == res2

    return res


def skip_without_paramiko() -> None:
    if not has_paramiko():
        pytest.skip("paramiko module is not available")


def skip_without_ssh_nopass(
    hostname: str = "localhost",
    user: Optional[str] = None,
) -> tuple[str, host.RemoteHost]:
    if user is None:
        user = get_user() or "root"
    skip_without_paramiko()
    rsh = can_ssh_nopass(hostname, user)
    if rsh is None:
        pytest.skip(f"cannot ssh to {user}@{hostname} without password")
    return user, rsh


def skip_without_sudo(rsh: host.Host) -> None:
    if not has_sudo(rsh):
        pytest.skip(f"sudo on {rsh.pretty_str()} does not seem to work passwordless")


def test_host_result_bin() -> None:
    res = run_local("echo -n out; echo -n err >&2", text=False)
    assert res == host.BinResult(b"out", b"err", 0)


def test_host_result_surrogateescape() -> None:
    res = host.local.run(
        "echo -n hi", decode_errors="surrogateescape", **_rnd_log_lineoutput()
    )
    assert res == host.Result("hi", "", 0)

    cmd = ["bash", "-c", "printf $'xx<\\325>'"]

    res_bin = host.local.run(cmd, text=False, **_rnd_log_lineoutput())
    assert res_bin == host.BinResult(b"xx<\325>", b"", 0)

    res = host.local.run(cmd, decode_errors="surrogateescape")
    assert res == host.Result("xx<\udcd5>", "", 0)
    with pytest.raises(UnicodeEncodeError):
        res.out.encode()
    assert res.out.encode(errors="surrogateescape") == b"xx<\325>"

    res_bin2 = run_local(["bash", "-c", 'printf "xx<\udcd5>"'], text=False)
    assert res_bin2 == host.BinResult(b"xx<\325>", b"", 0)

    res_bin = run_local(["echo", "-n", "xx<\udcd5>"], text=False)
    assert res_bin == host.BinResult(b"xx<\325>", b"", 0)

    cmd2 = b'echo -n "xx<\325>"'.decode(errors="surrogateescape")
    res_bin = host.local.run(cmd2, text=False)
    assert res_bin == host.BinResult(b"xx<\325>", b"", 0)

    t = False
    res_any = host.local.run(cmd2, text=t, **_rnd_log_lineoutput())
    assert isinstance(res_any, host.BinResult)
    assert res_any == host.BinResult(b"xx<\325>", b"", 0)

    res = host.local.run(cmd2)
    assert res == host.Result("xx<�>", "", 0)

    res = host.local.run(cmd2, decode_errors="surrogateescape")
    assert res == host.Result("xx<\udcd5>", "", 0)

    res_bin = host.local.run(["bash", "-c", cmd2], text=False)
    assert res_bin == host.BinResult(b"xx<\325>", b"", 0)


def test_host_result_str() -> None:
    res = host.local.run("echo -n out; echo -n err >&2", text=True)
    assert res == host.Result("out", "err", 0)

    res = host.local.run("echo -n out; echo -n err >&2", **_rnd_log_lineoutput())
    assert res == host.Result("out", "err", 0)


def test_host_result_match() -> None:
    res = host.Result("out", "err", 0)

    assert res.match()
    assert res.match(returncode=0)
    assert not res.match(returncode=4)

    assert res.match(out="out")
    assert res.match(out="out", err="err", returncode=0)
    assert res.match(out=re.compile("o"), err="err", returncode=0)
    assert not res.match(out=re.compile("xx"), err="err", returncode=0)

    assert res.match(out=re.compile("."))

    rx = re.compile(b".")
    with pytest.raises(TypeError):
        res.match(out=rx)  # type: ignore

    res_bin = host.BinResult(b"out", b"err", 0)
    assert res_bin.match(out=b"out")
    assert res_bin.match(err=b"err")
    assert res_bin.match(out=re.compile(b"out"))
    assert res_bin.match(out=re.compile(b"^out$"))
    assert res_bin.match(out=re.compile(b"u"))

    assert res_bin.match(out=re.compile(b"."))
    with pytest.raises(TypeError):
        res_bin.match(out=re.compile("."))  # type: ignore


def test_host_various_results() -> None:
    res = host.local.run('printf "foo:\\705x"')
    assert res == host.Result("foo:\ufffdx", "", 0)

    # The result with decode_errors="replace" is the same as if decode_errors
    # is left unspecified. However, the latter case will log an ERROR message
    # when seeing unexpected binary. If you set decode_errors, you expect
    # binary, and no error message is logged.
    res = host.local.run('printf "foo:\\705x"', decode_errors="replace")
    assert res == host.Result("foo:\ufffdx", "", 0)

    res = host.local.run('printf "foo:\\705x"', decode_errors="ignore")
    assert res == host.Result("foo:x", "", 0)

    with pytest.raises(UnicodeDecodeError):
        res = host.local.run('printf "foo:\\705x"', decode_errors="strict")

    res = host.local.run(
        'printf "foo:\\705x"', decode_errors="backslashreplace", **_rnd_log_lineoutput()
    )
    assert res == host.Result("foo:\\xc5x", "", 0)

    binres = host.local.run('printf "foo:\\705x"', text=False)
    assert binres == host.BinResult(b"foo:\xc5x", b"", 0)


def test_host_check_success() -> None:

    res = host.local.run("echo -n foo", check_success=lambda r: r.success)
    assert res == host.Result("foo", "", 0)
    assert res.success

    res = host.local.run("echo -n foo", check_success=lambda r: r.out != "foo")
    assert res == host.Result("foo", "", 0, forced_success=False)
    assert not res.success

    binres = host.local.run(
        "echo -n foo",
        text=False,
        check_success=lambda r: r.out != b"foo",
        **_rnd_log_lineoutput(),
    )
    assert binres == host.BinResult(b"foo", b"", 0, forced_success=False)
    assert not binres.success

    res = host.local.run("echo -n foo; exit 74", check_success=lambda r: r.success)
    assert res == host.Result("foo", "", 74)
    assert not res.success
    assert not res

    res = host.local.run("echo -n foo; exit 74", check_success=lambda r: r.out == "foo")
    assert res == host.Result("foo", "", 74, forced_success=True)
    assert res.success

    binres = host.local.run(
        "echo -n foo; exit 74", text=False, check_success=lambda r: r.out == b"foo"
    )
    assert binres == host.BinResult(b"foo", b"", 74, forced_success=True)
    assert binres.success
    assert binres


def test_host_file_exists() -> None:
    assert host.local.file_exists(__file__)
    assert host.Host.file_exists(host.local, __file__)
    assert host.local.file_exists(os.path.dirname(__file__))
    assert host.Host.file_exists(host.local, os.path.dirname(__file__))

    assert host.local.file_exists(pathlib.Path(__file__))
    assert host.Host.file_exists(host.local, pathlib.Path(__file__))


def test_result_typing() -> None:
    host.Result("out", "err", 0)
    host.Result("out", "err", 0, forced_success=True)
    host.BinResult(b"out", b"err", 0)
    host.BinResult(b"out", b"err", 0, forced_success=True)

    if sys.version_info >= (3, 10):
        with pytest.raises(TypeError):
            host.Result("out", "err", 0, True)
        with pytest.raises(TypeError):
            host.BinResult(b"out", b"err", 0, True)
    else:
        host.Result("out", "err", 0, True)
        host.BinResult(b"out", b"err", 0, True)


def test_env() -> None:
    res = host.local.run('echo ">>$FOO<<"', env={"FOO": "xx1"})
    assert res == host.Result(">>xx1<<\n", "", 0)

    res2 = run_local('echo ">>$FOO<<" 1>&2; exit 4', env={"FOO": "xx1"})
    assert res2 == host.Result("", ">>xx1<<\n", 4)


def test_cwd() -> None:
    res = run_local("pwd", cwd="/usr/bin")
    assert res == host.Result("/usr/bin\n", "", 0)

    res = run_local(["pwd"], cwd="/usr/bin")
    assert res == host.Result("/usr/bin\n", "", 0)

    res = host.local.run("pwd", cwd="/usr/bin/does/not/exist")
    assert res.out == ""
    assert res.returncode == 1
    assert "/usr/bin/does/not/exist" in res.err

    res = host.local.run("pwd", cwd="/root")
    if res == host.Result("/root\n", "", 0):
        # We have permissions to access the directory.
        pass
    else:
        assert res.out == ""
        assert res.returncode == 1
        assert "/root" in res.err


def test_sudo() -> None:
    skip_without_sudo(host.local)

    rsh = host.LocalHost(sudo=True)

    assert rsh.run("whoami") == host.Result("root\n", "", 0)

    assert rsh.run(["whoami"]) == host.Result("root\n", "", 0)

    res = rsh.run('echo ">>$FOO<"', env={"FOO": "xx1"})
    assert res == host.Result(">>xx1<\n", "", 0)

    res = rsh.run(
        ["bash", "-c", 'echo ">>$FOO2<" >&2; exit 55'], env={"FOO2": "xx1", "F1": None}
    )
    assert res == host.Result("", ">>xx1<\n", 55)

    res = rsh.run("pwd", cwd="/usr/bin")
    assert res == host.Result("/usr/bin\n", "", 0)

    res = rsh.run(["pwd"], cwd="/usr/bin")
    assert res == host.Result("/usr/bin\n", "", 0)

    res = rsh.run("echo hi; whoami >&2; pwd", cwd="/usr/bin")
    assert res == host.Result("hi\n/usr/bin\n", "root\n", 0)

    res = rsh.run(["bash", "-c", "echo hi; whoami >&2; pwd"], cwd="/usr/bin")
    assert res == host.Result("hi\n/usr/bin\n", "root\n", 0)

    res = rsh.run("pwd", cwd="/usr/bin/does/not/exist")
    assert res.out == ""
    assert res.returncode == 1
    assert "/usr/bin/does/not/exist" in res.err

    res = rsh.run("pwd", cwd="/root")
    assert res == host.Result("/root\n", "", 0)


def test_remotehost_userdoesnotexist() -> None:
    skip_without_paramiko()

    rsh = host.RemoteHost(
        "localhost", host.AutoLogin(user="userdoesnotexist"), login_retry_duration=0
    )
    res = rsh.run("whoami")
    assert res == host.Result(
        out="",
        err="Host.run(): failed to login to remote host localhost",
        returncode=1,
    )


def test_remotehost_1() -> None:
    user, rsh = skip_without_ssh_nopass()

    res = rsh.run("whoami", **_rnd_log_lineoutput())
    assert res == host.Result(f"{user}\n", "", 0)

    res = rsh.run(
        'whoami; pwd; echo ">>$FOO<"',
        cwd="/usr",
        env={"FOO": "hi"},
        **_rnd_log_lineoutput(),
    )
    assert res == host.Result(f"{user}\n/usr\n>>hi<\n", "", 0)


def test_remotehost_sudo() -> None:
    user, rsh = skip_without_ssh_nopass()

    res = rsh.run("whoami", sudo=True, **_rnd_log_lineoutput())
    if res.success:
        assert res == host.Result("root\n", "", 0)
    else:
        assert res.out == ""
        assert "sudo" in res.err
