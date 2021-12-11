from pathlib import Path
from pytest import fixture

@fixture
def hello_path(tmpdir):
    path = Path(tmpdir) / 'hello'
    path.write_text('hello')
    return path

@fixture
def world_path(tmpdir):
    path = Path(tmpdir) / 'world'
    path.write_text('world')
    return path

@fixture
def multiline_path(tmpdir):
    path = Path(tmpdir) / 'multiline'
    path.write_text(
        'a,b,c\n'
        '1,2,3\n'
    )
    return path

