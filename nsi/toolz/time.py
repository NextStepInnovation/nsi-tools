from pathlib import Path
from typing import Union
import datetime as _datetime
from datetime import datetime, date

from pymaybe import Nothing
import dateutil.parser
import dateutil.tz

from .common import pipe, curry

__all__ = [
    # time
    'maybe_dt', 'parse_dt', 'to_dt', 'date_to_datetime',
]

# ----------------------------------------------------------------------
#
# Time-oriented functions
#
# ----------------------------------------------------------------------

def date_to_datetime(d: date):
    return datetime.combine(d, _datetime.time(0))

def maybe_dt(ts, *, default=Nothing()):
    '''Parse ts to datetime object (using dateutil.parser.parse) or return
    Null

    '''
    if isinstance(ts, datetime):
        return ts
    if isinstance(ts, date):
        return date_to_datetime(ts)

    if not bool(ts):
        return default

    try:
        return parse_dt(ts)
    except (ValueError, TypeError):
        return default

def parse_dt(ts: str, local=False):
    dt = dateutil.parser.parse(ts)
    if local:
        return dt.astimezone(dateutil.tz.tzlocal())
    return dt

@curry
def to_dt(value, default=datetime.fromtimestamp(0), **du_kw):
    '''Attempt to parse the given value as a datetime object, otherwise
    return default=epoch

    Will try:
    - dateutil.parser.parse
    - 20190131T130506123456 (i.e. with microseconds)

    '''
    try_except = [
        (lambda v: dateutil.parser.parse(v, **du_kw), 
         (ValueError, TypeError)),
        (lambda v: dateutil.parser.parse(v, dayfirst=True), 
         (ValueError, TypeError)),
        (lambda v: datetime.strptime(v, "%Y%m%dT%H%M%S%f"),
         (ValueError, TypeError)),
    ]
    for func, excepts in try_except:
        try:
            output = func(value)
            return output
        except excepts:
            continue
    return default

