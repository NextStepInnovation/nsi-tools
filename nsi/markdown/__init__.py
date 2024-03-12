from pathlib import Path
import typing as T

import markdown as _markdown

from . import (
    meta_yaml, card, table, yaml_data, image_fig,
)
from ..toolz import (
    pipe, curry, concatv, merge, is_seq, compose_left, splitlines,
    map, filter, memoize
)
from ..toolz.text_processing import (make_table, ascii_table) # for backwards compat
from .. import logging


log = logging.new_log(__name__)

@memoize
def get_md(extensions: T.Sequence[str], extension_configs: T.Dict[str, dict], 
           base_path: str|Path = '.'):
    return _markdown.Markdown(
        extensions = pipe(
            concatv(
                [
                    'nsi.markdown.meta_yaml',
                    'nsi.markdown.yaml_data',
                    'nsi.markdown.card',
                    'nsi.markdown.image_fig',
                    'nsi.markdown.table'
                ],
                [
                    'extra', 
                    'codehilite', 
                    'toc', 
                    'admonition',
                    'pymdownx.b64'
                ],
                extensions or [],
            ),
            set,
            tuple,
        ),
        extension_configs = merge(
            {
                'extra': {},
                'admonition': {
                },
                'codehilite': {
                    'noclasses': True,
                    'guess_lang': False,
                },
                'pymdownx.b64': {
                    'base_path': base_path,
                },
            },
            extension_configs or {},
        ),
    )

@curry
def markdown(content: str, *, extensions: T.Sequence[str] = None, 
             extension_configs: T.Dict[str, dict] = None,
             base_path: T.Union[str, Path] = '.'):
    class HtmlWithMeta(str):
        meta = None

    md = get_md(
        extensions, extension_configs, base_path=base_path
    )
    output = HtmlWithMeta(md.convert(content))
    output.meta = md.meta or {}
    return output

def md_to_pandoc(text):
    '''Convert any NSI-specific markdown content to pandoc-friendly markdown
    '''
    return pipe(
        text,
        splitlines,
        # insert mods here,
        '\n'.join,
    )

