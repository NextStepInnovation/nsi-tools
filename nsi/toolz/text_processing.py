import typing as T
from typing import Union, Iterable
import functools
import re
import pprint

import pyperclip

from .common import (
    is_dict, pipe, curry, map, filter, concatv, strip, vmap,
    is_seq, is_str, to_str, merge, compose_left,
)

from .. import logging

__all__ = [
    # text_processing
    'clipboard_copy', 'clipboard_paste', 'copy', 'paste',
    'difflines', 'escape_row', 'intlines',
    'lines_without_comments', 'output_rows_to_clipboard', 'remove_comments', 
    'strip_comments', 'strip_comments_from_line', 'pformat', 'pfint', 'noansi', 
    'clip_text', 'clip_lines', 'strip_comments_from_lines', 'xlsx_to_clipboard', 
    'xorlines', 'html_list', 'columns_as_code', 'markdown_row', 'code_if', 'join_lines', 
    'table_lines', 'make_table', 'ascii_table',
]

log = logging.new_log(__name__)

# ----------------------------------------------------------------------
#
# Comment handling functions
#
# ----------------------------------------------------------------------

@curry
def strip_comments_from_line(line: str, *, char='#'):
    '''
    '''
    return line[:line.index(char)] if char in line else line

@curry
def strip_comments_from_lines(lines: Iterable[str], *, char='#'):
    return pipe(
        lines,
        map(lambda l: strip_comments(l, char=char)),
        tuple,
    )

@curry
def strip_comments(data: Union[str, Iterable], *, char='#'):
    match data:
        case lines if is_seq(lines):
            return strip_comments_from_lines(lines, char=char)
        case line if is_str(line):
            return strip_comments_from_line(line, char=char)
    raise TypeError(
        'Must provide either string (one line) or Iterable'
        ' type (multiple lines)'
    )
remove_comments = strip_comments

# ----------------------------------------------------------------------
#
# Clipboard functions
#
# ----------------------------------------------------------------------

def clipboard_copy(content: str):
    pyperclip.copy(content)
copy = clipboard_copy

def clipboard_paste():
    return pyperclip.paste()
paste = clipboard_paste

def xlsx_to_clipboard(content: str):
    return pipe(
        content,
        to_str,
        lambda c: c if c.endswith('\n') else c + '\n',
        clipboard_copy,
    )

def escape_row(row: Iterable[str]):
    '''Prepare individual row for pasting as an Excel column
    '''
    return pipe(
        row,
        map(lambda v: v.replace('"', '""')),
        map(lambda v: f'"{v}"'),
        '\t'.join,
    )

def output_rows_to_clipboard(rows: Iterable[Iterable]):
    return pipe(
        rows,
        map(escape_row),
        '\n'.join,
        clipboard_copy,
    )

# ----------------------------------------------------------------------
#
# Line/content comparison functions
#
# ----------------------------------------------------------------------

def lines_without_comments(content: str):
    return pipe(
        content.splitlines(),
        strip_comments,
        filter(None),
        set,
    )

def difflines(A: str, B: str):
    linesA = lines_without_comments(A)
    linesB = lines_without_comments(B)
    return pipe(linesA - linesB, sorted)

def intlines(A: str, B: str):
    linesA = lines_without_comments(A)
    linesB = lines_without_comments(B)
    return pipe(linesA & linesB, sorted)

def xorlines(A: str, B: str):
    linesA = lines_without_comments(A)
    linesB = lines_without_comments(B)
    return pipe(linesA ^ linesB, sorted)


# ----------------------------------------------------------------------
#
# HTML conversion functions
#
# ----------------------------------------------------------------------

def html_list(items):
    items = pipe(
        items,
        map(strip()),
        filter(None),
        tuple,
    )

    if not items:
        return ''

    if len(items) == 1:
        return items[0]

    return pipe(
        concatv(
            ['<ul>'],
            [f'<li>{i}</li>' for i in items],
            ['</ul>'],
        ),
        ''.join
    )

# ----------------------------------------------------------------------
#
# Text formatting convenience functions
#
# ----------------------------------------------------------------------

@functools.wraps(pprint.pformat)
@curry
def pformat(obj: T.Any, **kw):
    return pprint.pformat(obj, **kw)
pfint = pformat(underscore_number=True)

def noansi(text: str):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)

@curry
def clip_text(length, text, buf=' [...] ') -> str:
    text = to_str(text)
    if len(text) > length * 2:
        if length % 2 == 0:
            l, r = (length // 2, length // 2)
        else:
            l, r = (length // 2, (length // 2 + 1))
        return text[:l] + buf + text[-r:]
    return text

@curry
def clip_lines(length: int, sequence: T.Sequence[str], *, 
               buffer_text:str = None,
               buffer_pad:str = None) -> T.Sequence[str]:
    sequence = tuple(sequence)
    if len(sequence) > length:
        if length % 2 == 0:
            l, r = (length // 2, length // 2)
        else:
            l, r = (length // 2, (length // 2 + 1))
        text = buffer_text or f'[{(len(sequence) - r)-l} items removed]'
        pad = buffer_pad or ''
        buffer_str = pad + text + pad
        return sequence[:l] + (buffer_str,) + sequence[-r:]
    return sequence

@curry
def columns_as_code(columns_as_code: T.Sequence[int|str], 
                    row: T.Dict[str, T.Any] | T.Sequence[T.Any]):
    columns = set(columns_as_code)
    if is_dict(row):
        return merge(
            row,
            {c: f'`{row[c]}`' if row[c] else '' for c in columns},
        )
    # assuming it's a sequence
    return tuple(
        (f'`{v}`' if v else '') if i in columns else v
        for i, v in enumerate(row)
    )

def markdown_row(row: T.Sequence[T.Any]):
    return (
        '| ' + pipe(
            row,
            map(str),
            ' | '.join,
        ) + ' |'
    )

def code_if(s: str):
    '''
    Return the string enclosed in backticks (markdown "code" symbol) only if it
    exists, otherwise empty string
    '''
    return f'`{s}`' if s else ''

def join_lines(sep: str, pre: str = None, post: str = None):
    '''
    Decorator that converts generators that yield lines of text into a function
    that returns a string where the lines are prefixed by `pre`, joined by
    `sep`, and `post` is added to the end of the final string.
    '''
    def wrapper(func):
        @functools.wraps(func)
        def joiner(*a, **kw):
            return (pre if pre else '') + pipe(
                func(*a, **kw),
                map(str),
                sep.join,
            ) + (post if post else '')
        return joiner
    return wrapper

def table_lines(columns: T.Sequence[str], align: str = None):
    pre = '| ' + pipe(columns, map(str), ' | '.join) + ' |\n'
    pre += (
        align if align else (('|:--' * len(columns)) + '|')
    ) + '\n'
    return join_lines('\n', pre=pre, post='\n')

@curry
def make_table(columns: T.Sequence[str], 
               col_map=None, columns_as_code: T.Sequence[int] = None, 
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
    |:-----|:-----|
    | 1 | 2 |
    | 3 | 4 |
    '''
    columns_as_code = columns_as_code or []
    def maker(rows):
        rows = tuple(rows)
        if not rows:
            return ''
        
        nonlocal columns, col_map
        if columns is None:
            columns = tuple(rows[0].keys())

        if col_map:
            header = [col_map[c] for c in columns]
        else:
            header = columns

        if is_seq(rows[0]):
            value_f = lambda _i, r: [(r[i] if i < len(r) else '') 
                                     for i, _c in enumerate(columns)]
            enum_row = lambda r: r
        else:
            enum_row = lambda r: [r.get(c, '') for c in columns]
            value_f = lambda _i, r: enum_row(r)

        if pad:
            max_col_widths = [0 for v in header]
            for row in [header] + [enum_row(row) for row in rows]:
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
                enumerate,
                vmap(lambda i, v: f'`{v}`' if i in columns_as_code else v),
                map(str),
                ' | '.join
            ) + ' |'

    return compose_left(maker, '\n'.join)
ascii_table = make_table(pad=True)
