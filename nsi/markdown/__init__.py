from pathlib import Path
import typing as T

import markdown as _markdown

from . import (
    meta_yaml, card, table, yaml_data, image_fig,
)
from ..toolz import (
    pipe, curry, concatv, merge, is_seq, compose_left, splitlines,
    map, filter,
)
from .. import logging

log = logging.new_log(__name__)

@curry
def markdown(content: str, *, extensions: T.Sequence[str] = None, 
             extension_configs: T.Dict[str, dict] = None,
             base_path: T.Union[str, Path] = '.'):
    class HtmlWithMeta(str):
        meta = None

    md = _markdown.Markdown(
        extensions = pipe(
            concatv(
                ['nsi.markdown.meta_yaml',
                 'nsi.markdown.yaml_data',
                 'nsi.markdown.card',
                 'nsi.markdown.image_fig',
                 'nsi.markdown.table'],
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

    output = HtmlWithMeta(md.convert(content))
    output.meta = md.meta or {}
    return output

def make_table(columns=None, col_map=None, 
               columns_as_code: T.Sequence[int|str] = None):
    '''Functional markdown table maker. Given columns (i.e. row dict keys) and
    map from those keys to final header names, return table-making function that
    takes an iterable of rows and produces a markdown table.

    Examples:

    >>> pipe(
    ...    [{'a': 1, 'b': 2}, {'a': 3, 'b': 4}], 
    ...    make_table(['a', 'b'], {'a': 'ColA', 'b': 'ColB'}),
    ...    print,
    ... )
    | ColA | ColB |
    |:--|:--|
    | 1 | 2 |
    | 3 | 4 |
    '''
    def maker(rows):
        rows = tuple(rows)
        if not rows:
            return ''

        nonlocal columns, col_map
        if columns is None:
            columns = tuple(rows[0].keys())
        if col_map is None:
            header = columns
        else:
            header = [col_map[c] for c in columns]

        if is_seq(rows[0]):
            value_f = lambda r: [r[i] for i, _c in enumerate(columns)]
        else:
            value_f = lambda r: [r[c] for c in columns]
            
        yield '| ' + ' | '.join(header) + ' |'
        yield '|:--'*len(header) + '|'
        for row in rows:
            try:
                values = value_f(row)
            except:
                log.exception(row)
                raise
            yield '| ' + pipe(
                values,
                map(str),
                ' | '.join
            ) + ' |'

    return compose_left(maker, '\n'.join)

def md_to_pandoc(text):
    '''Convert any NSI-specific markdown content to pandoc-friendly markdown
    '''
    return pipe(
        text,
        splitlines,
        # insert mods here,
        '\n'.join,
    )

