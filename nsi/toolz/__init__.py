try:
    from cytoolz.curried import *
    import cytoolz.curried as _toolz
except ImportError:
    from toolz.curried import *
    import toolz.curried as _toolz

from .common import *
from .csv import *
from .dictionary import *
from .filesystem import *
from .functions import *
from .graph import *
from .hashing import *
from .html import *
from .http import *
from .ips import *
from .json import *
from .pyrsistent import *
from .random import *
from .regex import *
from .text_processing import *
from .time import *
from .binary_data import *
from .dynamic_import import *
from .urllib import *

from . import (
    common,
    csv,
    dictionary,
    filesystem,
    functions,
    graph,
    hashing,
    html,
    http,
    ips,
    json,
    pyrsistent,
    random,
    regex,
    text_processing,
    time,
    binary_data,
    dynamic_import,
    urllib,
)

__all__ = tuple(concatv(
    common.__all__,
    json.__all__,
    html.__all__, 
    filesystem.__all__,
    dynamic_import.__all__,
    csv.__all__,
    time.__all__,
    functions.__all__,
    graph.__all__,
    regex.__all__,
    hashing.__all__,
    random.__all__,
    dictionary.__all__,
    ips.__all__,
    binary_data.__all__,
    urllib.__all__,
    text_processing.__all__,
    pyrsistent.__all__,
    http.__all__,
))

def toolz_imports():
    from pathlib import Path
    modules = pipe(
        Path(__file__).parent.glob('*.py'), 
        filter(lambda p: not p.name.startswith('_')),
        tuple,
    )
    def f_names(p):
        return pipe(
            slurplines(p),
            groupdicts(r'^(def (?P<name>.*?)\(|(?P<name>\w[\d\w_]*) = )'),
            map(get('name')),
            filter(lambda n: not n.startswith('_')),
            filter(lambda n: n != 'log'),
            sorted,
        )
    def grid(names):
        return pipe(
            names,
            partition_all(5),
            map(map(lambda s: f"'{s}'")),
            map(', '.join),
            map(lambda l: '    ' + l + ','),
            '\n'.join,
        )
    def f_grid(p):
        return pipe(
            f_names(p),
            grid,
            lambda s: f'    # {p.stem}\n' + s
        )
    t_c = pipe(
        dir(_toolz),
        filter(lambda n: not n.startswith('_')),
        grid,
        lambda s: f'    # toolz.curried\n' + s
    )
    return pipe(
        modules,
        map(f_grid),
        lambda l: concat([(t_c,), l]),
        '\n\n'.join,
    )
