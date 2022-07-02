import csv
import io
from collections import OrderedDict
from typing import Union, Iterable, Sequence
from pathlib import Path

from .common import (
    pipe, curry, concatv, map, filter,
    is_seq, is_dict, new_log, call, cat_to_set,
)

log = new_log(__name__)

__all__ = [
    # csv
    'csv_rows', 'csv_rows_from_content', 'csv_rows_from_fp', 'csv_rows_from_path', 'csv_rows_to_content',
    'csv_rows_to_fp', 'csv_rows_to_path', 
]

# ----------------------------------------------------------------------
#
# CSV functions
#
# ----------------------------------------------------------------------

csv.field_size_limit(2147483647//100)

@curry
def csv_rows_from_path(path: Union[str, Path], *, header=True,
                       columns=None, **kw):
    '''Load CSV rows from file path

    '''
    return csv_rows_from_fp(
        Path(path).expanduser().open(), header=header,
        columns=columns, **kw
    )
csv_rows = csv_rows_from_path

@curry
def csv_rows_from_content(content: Union[str, bytes], *,
                          header=True, columns=None, **kw):
    r'''Load CSV rows from content (e.g. str or bytes)

    Args:
      content (str): string content

    Examples:
    
    >>> pipe(csv_rows_from_content('c1,c2,c3\n1,2,3'), list)
    [{'c1': '1', 'c2': '2', 'c3': '3'}]

    If header is False, then rows will be returned as lists.
    
    >>> pipe(csv_rows_from_content('1,2,3\n4,5,6', header=False), list)
    [['1', '2', '3'], ['4', '5', '6']]

    >>> pipe(csv_rows_from_content(
    ...   '1,2,3', header=False, columns=['c1', 'c2', 'c3']
    ... ), list)
    [{'c1': '1', 'c2': '2', 'c3': '3'}]

    If header is False and header row exists, the header row will be
    interpreted as a regular row.
    
    >>> pipe(csv_rows_from_content('c1,c2,c3\n1,2,3', header=False), list)
    [['c1', 'c2', 'c3'], ['1', '2', '3']]

    '''
    return csv_rows_from_fp(
        io.StringIO(content), header=header, columns=columns, **kw
    )

@curry
def csv_rows_from_fp(rfp, *, header=True, columns=None, **reader_kw):
    '''Load CSV rows from file-like object

    '''
    if header:
        column_row = next(csv.reader(rfp))
        columns = columns or column_row
        reader = csv.DictReader(rfp, columns, **reader_kw)
    elif is_seq(columns):
        reader = csv.DictReader(rfp, columns, **reader_kw)
    else:
        reader = csv.reader(rfp, **reader_kw)
    for row in pipe(reader, filter(None)):
        yield row
    
@curry
def csv_rows_to_fp(wfp, rows: Iterable[Union[dict, Sequence[str]]], *,
                   header: bool = True,
                   columns: Union[dict, Iterable[str]] = None,
                   **writer_kw):
    r'''Save CSV rows to file-like object

    Args:

      wfp (file-like): File-like object into which to write the CSV
        content

      rows (Iterable[Union[dict, Iterable]]): Row data to write to
        CSV.

        Iterable[dict], columns is None: If given as iterable of
        dictionaries and columns is None, columns will come from keys
        of row dictionaries. This means that __the row data will need
        to be exhausted__ to build column list. The final column
        sequence will be sorted.

        Iterable[dict], columns is dict: If given as iterable of
        dictionaries and columns is a dictionary, then it is assumed
        to be a mapping from row keys to the final columns. If final
        column ordering is important, then use a
        collections.OrderedDict to encode the columns.

        Iterable[dict], columns is Iterable[str]: If given as iterable
        of dictionaries and columns is an iterable, then it will be
        used as the final list of columns. It is __assumed that the
        iterable of columns contains all necessary columns__. Only the
        given columns will be provided in the final CSV data.

        Iterable[Sequence[str]], columns is None: If given as iterable
        of sequences and columns is None, then there will be no header
        in the final CSV.

        Iterable[Sequence[str]], columns is Iterable[str]: If given as
        iterable of sequences and columns is an iterable, then there
        will be a header in the final CSV if header is True.

      header (bool): Should there be a header in the final CSV?

      columns (Union[dict, Iterable[str]]): Columns to be used in
        final CSV

      **writer_kw: Keyword arguments to be passed to csv.writer (or
        csv.DictWriter)

    Examples:

    >>> import io
    >>> from pathlib import Path
    >>> wfp = io.StringIO()
    >>> pipe(
    ...     [{'a': 1, 'b': 2}, {'a': 3, 'b': 4}],
    ...     csv_rows_to_fp(wfp),
    ... )
    >>> wfp.getvalue() == 'a,b\r\n1,2\r\n3,4\r\n'
    True
    >>> wfp = io.StringIO()
    >>> pipe(
    ...     [{'a': 1, 'b': 2}, {'a': 3, 'b': 4}],
    ...     csv_rows_to_fp(wfp, columns={'b': 'B', 'a': 'A'}),
    ... )
    >>> assert wfp.getvalue() in {'A,B\r\n1,2\r\n3,4\r\n', 'B,A\r\n2,1\r\n4,3\r\n'}
    >>> wfp = io.StringIO()
    >>> pipe(
    ...     [(1, 2), (3, 4)],
    ...     csv_rows_to_fp(wfp, columns=['a', 'b']),
    ... )
    >>> assert wfp.getvalue() == 'a,b\r\n1,2\r\n3,4\r\n'
    >>> wfp = io.StringIO()
    >>> pipe(
    ...     [(1, 2), (3, 4)],
    ...     csv_rows_to_fp(wfp),
    ... )
    >>> assert wfp.getvalue() == '1,2\r\n3,4\r\n'

    >>> wfp = io.StringIO()
    >>> pipe([], csv_rows_to_fp(wfp))
    >>> assert wfp.getvalue() == ''
    '''
    
    row_iter = iter(rows)

    try:
        first_row = next(row_iter)
    except StopIteration:
        log.error('No rows in row iterator... stopping, no write made.')
        return

    # If rows are passed as iterable of sequences, each row must be an
    # in-memory sequence like a list, tuple, or pvector (i.e. not an
    # iter or generator), otherwise, this will have the
    # __side-effect__ of exhausting the first row.
    rows_are_dicts = is_dict(first_row)
    columns_is_dict = is_dict(columns)

    rows = concatv([first_row], row_iter)
    if rows_are_dicts:
        if columns_is_dict:
            items = tuple(columns.items())
            rows = pipe(
                rows,
                map(lambda r: OrderedDict([
                    (to_c, r[from_c]) for from_c, to_c in items
                ])),
            )
            columns = list(columns.values())
        elif columns is None:
            rows = tuple(rows)
            columns = pipe(
                rows,
                map(call('keys')),
                cat_to_set,
                sorted,
            )
        else:                   # assuming columns is Iterable
            columns = tuple(columns)
            rows = pipe(
                rows,
                map(lambda r: {
                    c: r[c] for c in columns
                }),
            )
        writer = csv.DictWriter(wfp, columns, **writer_kw)
        if header:
            writer.writeheader()
    else:                       # assuming rows are Iterable
        if columns is not None:  # assuming columns is Iterable
            columns = tuple(columns)
            rows = pipe(
                rows,
                map(lambda r: {
                    c: r[i] for i, c in enumerate(columns)
                }),
            )
            writer = csv.DictWriter(wfp, columns)
            if header:
                writer.writeheader()
        else:
            writer = csv.writer(wfp, **writer_kw)
            
    writer.writerows(rows)

@curry
def csv_rows_to_path(path: Union[str, Path],
                     rows: Iterable[Union[dict, Sequence[str]]], *,
                     header: bool = True,
                     columns: Union[dict, Iterable[str]] = None,
                     **writer_kw):
    '''Save CSV rows to file system path

    '''
    with Path(path).expanduser().open('w') as wfp:
        return csv_rows_to_fp(
            wfp, rows, header=header, columns=columns, **writer_kw
        )

@curry
def csv_rows_to_content(rows: Iterable[Union[dict, Sequence[str]]], *,
                        header: bool = True,
                        columns: Union[dict, Iterable[str]] = None,
                        **writer_kw):
    '''Save CSV rows to a string

    '''
    buf = io.StringIO()
    csv_rows_to_fp(
        buf, rows, header=header, columns=columns, **writer_kw
    )
    return buf.getvalue()

