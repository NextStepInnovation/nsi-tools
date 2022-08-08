'''
Superset of toolz API with quite a lot of extra bits in the toolz style
'''
try:
    import cytoolz.curried as toolz
    from cytoolz.curried import *
except ImportError:
    import toolz.curried as toolz
    from toolz.curried import *

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

