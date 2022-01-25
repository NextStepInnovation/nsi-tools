from typing import Union, Iterable

import pyperclip

from .common import (
    pipe, curry, map, filter,
    is_seq, is_str, to_str,
)

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

def clipboard_paste():
    return pyperclip.paste()

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

