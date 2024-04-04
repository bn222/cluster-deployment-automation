import pathlib
import pytest
import os

import common


def test_atomic_write(tmp_path: pathlib.Path) -> None:
    fname = tmp_path / "file"
    with common.atomic_write(str(fname)) as f:
        f.write("hello")
    with open(str(fname)) as f:
        assert f.read() == "hello"

    fname = tmp_path / "file2"
    with common.atomic_write(str(fname), mode=0o000) as f:
        f.write("hello")
    assert os.path.exists(str(fname))
    with pytest.raises(PermissionError):
        open(str(fname))
