'''Tools for creating simple configuration setups for libraries that require
3rd-party API/service connectivity and the like

Using:

First, you'll want to come up with a boilerplate for this configuration. This
can either be just a string

```
### Configuration boilerplate

CONFIG_BP = (
    nsi.config.base_config('My Cool Toolkit') + """
# ------------------------------
#  WebDAV for My Cool Toolkit
# ------------------------------

webdav:
  # Username given after creating app password
  username: ''

  # App password
  password: ''

smtp:
  # Username to log into smtp server
  username: ''

  # Password for this user
  password: ''

  # Hostname for the SMTP server
  hostname: localhost

  # Port for the SMTP server
  port: 25
""")
```

XXX: Fix
'''
import functools
import typing as T
from pathlib import Path
from datetime import datetime, timedelta

from . import logging, yaml
from .toolz import *

log = logging.new_log(__name__)

class NsConfigFileError(IOError):
    pass

CONFIG_BP = '''\
#--------------------------------------------------------------------------
#
# Configuration for {app_name}
#
#--------------------------------------------------------------------------

cache_dir: >-
  {{cache}}

'''

def base_config(app_name: str):
    return  CONFIG_BP.format(
        app_name=app_name,
    )


KeyReqs = T.Iterable[ 
    T.Tuple[
        str,             # group key
        T.Iterable[str], # required sub-keys
        str              # information about key
    ]
]
@curry
def config_verifier(key_reqs: KeyReqs, config: dict):
    def verify_group(app_key, sub_keys, access_text):
        correct = True
        app_missing, sub_missing, no_value = [], [], []
        if app_key not in config:
            correct = False
            app_missing.append(app_key)
        else:
            for k in sub_keys:
                if k not in (config[app_key] or {}):
                    correct = False
                    sub_missing.append((app_key, k))
                elif not config[app_key][k]:
                    correct = False
                    no_value.append((app_key, k))
        if not correct:
            log.error(
                'The configuration is in a bad state for the following reasons:\n'
            )
            if app_missing:
                log.error(
                    '  The following application keys are missing:'
                )
                for app in app_missing:
                    log.error(f'    - {app}')

            make_dict = compose_left(groupby(first), valmap(map_t(second)))
            def log_dict(results):
                d = make_dict(results)
                for app in d:
                    log.error(
                        f'  - {app}:'
                    )
                    for key in d[app]:
                        log.error(
                            f'    - {key}'
                        )

            if sub_missing:
                log.error(
                    '  The following applications are missing keys:'
                )
                log_dict(sub_missing)

            if no_value:
                log.error(
                    '  The following application have keys that are missing values:'
                )
                log_dict(no_value)
    pipe(
        key_reqs,
        vmap(verify_group),
        tuple,
    )
    return config

@ensure_paths
def config_dir_provider(config_dir_path: Path, cache_dir_name: str):
    def provide_config_dir(func):
        @functools.wraps(func)
        def wrapper(*a, **kw):
            config_dir_path.mkdir(mode=0o700, exist_ok=True, parents=True)
            cache_dir_path = (config_dir_path / cache_dir_name)
            cache_dir_path.mkdir(mode=0o700, exist_ok=True, parents=True)
            return func(config_dir_path, cache_dir_path, *a, **kw)
        return wrapper
    return provide_config_dir


def config_loader(provide_config_dir_dec: T.Callable, config_name: str, 
                  config_bp: T.Union[str, T.Callable]):
    @provide_config_dir_dec
    def load_config(config_dir, cache_dir):
        path = config_dir / config_name
        if not path.exists():
            log.info(
                f'Creating new configuration: {path}'
            )
            path.write_text(config_bp.format(cache=cache_dir))
            path.chmod(0o600)
        return pipe(
            yaml.read_yaml(path),
            to_pyrsistent,
        )
    return load_config

def config_provider(loader: T.Callable, verifier: T.Callable):
    def with_config(func):
        @functools.wraps(func)
        def wrapper(*a, **kw):
            config = pipe(
                loader(),
                verifier,
            )
            return func(config, *a, **kw)
        return wrapper
    return with_config

def younger_than(delta, path):
    return datetime.now() - dt_ctime(path) < delta

# def _reset_cache(func, path):
#     func._reset = True
#     log.info(f'Cached file ({path}) for {func} ready for reset')

# @curry
# def from_cache(saver, loader, path):
#     def decorator(func):
#         func._reset = False
#         func.reset_cache = partial(_reset_cache, func, path)
        
#         @with_config
#         @functools.wraps(func)
#         def wrapper(config, *a, **kw):
#             cache_path = Path(config['cache_dir'], path)
#             if (cache_path.exists()
#                 and
#                 younger_than(timedelta(days=1), cache_path)
#                 and
#                 not func._reset):
#                 value = loader(cache_path)
#                 return value
#             value = func(*a, **kw)
#             saver(cache_path, value)
#             func._reset = False
#             return value
#         return wrapper

#     return decorator

# def xlsx_saver(path, wb):
#     wb.save(str(path))

# def xlsx_loader(path):
#     import openpyxl
#     return openpyxl.load_workbook(str(path))

# from_xlsx_cache = from_cache(xlsx_saver, xlsx_loader)

# def str_saver(path, content):
#     Path(path).write_text(content)

# def str_loader(path):
#     return Path(path).read_text()

# from_str_cache = from_cache(str_saver, str_loader)

# def binary_saver(path, content):
#     Path(path).write_binary(content)

# def binary_loader(path):
#     return Path(path).read_binary()

# from_binary_cache = from_cache(binary_saver, binary_loader)

