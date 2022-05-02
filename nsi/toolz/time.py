from pathlib import Path
from typing import Union
from datetime import datetime as _datetime, date as _date

from pymaybe import Nothing
import dateutil.parser
import dateutil.tz

from .common import pipe, curry

# ----------------------------------------------------------------------
#
# Time-oriented functions
#
# ----------------------------------------------------------------------

def ctime(path: Union[str, Path]):
    return Path(path).stat().st_ctime

def maybe_dt(ts, *, default=Nothing()):
    '''Parse ts to datetime object (using dateutil.parser.parse) or return
    Null

    '''
    if isinstance(ts, (_datetime, _date)):
        return ts

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

def ctime_as_dt(path: Union[str, Path]):
    return pipe(
        path,
        ctime,
        _datetime.fromtimestamp,
    )
dt_ctime = ctime_as_dt

@curry
def to_dt(value, default=_datetime.fromtimestamp(0), **du_kw):
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
        (lambda v: _datetime.strptime(v, "%Y%m%dT%H%M%S%f"),
         (ValueError, TypeError)),
    ]
    for func, excepts in try_except:
        try:
            output = func(value)
            return output
        except excepts:
            continue
    return default

