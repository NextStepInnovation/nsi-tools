import re
from pathlib import Path

from pkg_resources import resource_filename as _resource_filename

from ..toolz import *
from .. import logging

log = logging.new_log(__name__)

resource_filename = partial(_resource_filename, __name__)
resource_filename_f = compose_left(
    resource_filename,
    lambda n: Path(n).expanduser(),
)


@curry
def find_files(start, filename):
    start_path = Path(start).resolve()

    log.info(f'Finding image {filename}')
    if Path(start_path, filename).exists():
        path = Path(start_path, filename)
        log.info(f'   found: {path}')
        return [path]

    file_re = re.compile(
        filename.lower().replace('.', '\\.').replace('*', '.*')
    )
    log.info(f'   searching with re: {file_re.pattern}')

    paths = pipe(
        walk(start_path),
        filter(lambda p: file_re.search(p.name.lower())),
        partial(sorted, key=lambda p: p.name),
        tuple,
    )
    if not paths:
        log.error(
            f'Could not find any filenames meeting the search string'
            f' "{filename}" looking in directory: {start_path}'
        )
    return paths

