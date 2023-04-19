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

def make_table(columns=None, col_map=None, 
               columns_as_code: T.Sequence[int|str] = None, 
               pad: bool = False):
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
            value_f = lambda _i, r: [r[i] for i, _c in enumerate(columns)]
        else:
            value_f = lambda _i, r: [r[c] for c in columns]

        if pad:
            max_col_widths = [0 for v in header]
            for row in [header] + [r for r in rows]:
                for j, value in enumerate(row):
                    width = len(str(value))
                    if width > max_col_widths[j]:
                        max_col_widths[j] = width

            header = [str(h).center(max_col_widths[j]) for j, h in enumerate(header)]
            old_value_f = value_f
            value_f = lambda i, row: [
                str(v).ljust(max_col_widths[j]) 
                for j, v in enumerate(old_value_f(i, row))
            ]
            
        yield '| ' + ' | '.join(header) + ' |'
        yield '|:' + pipe(
            header,
            map(lambda h: '-'*(len(h) + 1)),
            '|:'.join,
        )+ '|'
        # yield '|:--'*len(header) + '|'
        for i, row in enumerate(rows):
            try:
                values = value_f(i, row)
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

