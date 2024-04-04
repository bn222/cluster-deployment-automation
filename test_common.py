import pathlib
import pytest
import os

import common


def _read_file(filename: str) -> str:
    with open(filename) as f:
        return f.read()


def test_atomic_write(tmp_path: pathlib.Path) -> None:

    user = os.geteuid()
    group = os.getegid()

    filename = str(tmp_path / "file1")
    with common.atomic_write(filename) as f:
        f.write("hello1")
        f.flush()
        d = os.listdir(str(tmp_path))
        assert len(d) == 1
        (filename_tmp,) = d
        assert filename_tmp.startswith("file1.")
        filename_tmp = str(tmp_path / filename_tmp)
        assert _read_file(filename_tmp) == "hello1"
        assert not os.path.exists(filename)

        st = os.stat(filename_tmp)
        assert st.st_mode == 0o100600
        assert st.st_uid == user

    assert os.path.exists(filename)
    assert not os.path.exists(filename_tmp)
    assert _read_file(filename) == "hello1"
    st = os.stat(filename)
    assert st.st_mode == 0o100644

    with common.atomic_write(filename) as f:
        f.write("hello1.2")
        f.flush()
        d = os.listdir(str(tmp_path))
        assert len(d) == 2
        assert "file1" in d
        d.remove("file1")
        (filename_tmp,) = d
        assert filename_tmp.startswith("file1.")
        assert _read_file(str(tmp_path / filename_tmp)) == "hello1.2"
        assert os.path.exists(filename)
        assert _read_file(filename) == "hello1"

    assert os.path.exists(filename)
    assert not os.path.exists(filename_tmp)
    assert _read_file(filename) == "hello1.2"

    filename = str(tmp_path / "file2")
    with common.atomic_write(filename, mode=0o002) as f:
        f.write("hello2")
    assert os.path.exists(filename)
    with pytest.raises(PermissionError):
        # We took away permissions to read the file.
        open(filename)
    st = os.stat(filename)
    assert st.st_mode == 0o100002

    filename = str(tmp_path / "file3")
    with common.atomic_write(filename, owner=user, group=group, mode=0o644) as f:
        f.write("hello3")
    assert _read_file(filename) == "hello3"
