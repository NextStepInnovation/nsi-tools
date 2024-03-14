import coloredlogs
import logging
# Because the nsi.toolz submodule using this, avoiding circular import
from toolz.curried import merge

def new_log(name):
    log = logging.getLogger(name)
    log.addHandler(logging.NullHandler())
    return log

def setup_logging(loglevel: str, **config_kw):
    fmt = (
        '{asctime} {levelname: <6} [{name}:{lineno: >4}]  {message}'
    )
    datefmt = '%Y-%m-%d %H:%M:%S'
    kw = merge({
        'level': loglevel.upper(),
        'datefmt': datefmt,
        'fmt': fmt,
        'style': '{',
        'field_styles': merge(
            coloredlogs.DEFAULT_FIELD_STYLES, {
                'name': {'bold': True, 'color': 'blue'}
            }
        ),
    }, config_kw)
    coloredlogs.install(**kw)

