'''
Configuration setup for Nexpose connectivity information
'''
from pathlib import Path
import logging
import typing as T

from .. import logging
from .. import yaml
from ..toolz import *

from .api import Api, new_api

log = logging.new_log(__name__)


config_bp = '''
# ------------------------------
#  Setting up Nexpose API
# ------------------------------
#
nexpose:
  # Nexpose username
  username: ''
  # Nexpose password
  password: ''

  # Nexpose API server configuration
  #
  hostname: >-
    localhost
  port: 3780
'''

default_path = Path(
    '~', '.config', 'nsi', 'nexpose.yml'
).expanduser()

class Config(T.TypedDict):
    username: str
    password: str
    hostname: str
    port: int

ConfigSuccess = T.Tuple[bool, Config]

@ensure_paths
def init_config(path: Path) -> ConfigSuccess:
    if not path.exists():
        log.warning(
            f'Config does not exist at {path} and will be generated from'
            ' boilerplate.'
        )
        if not path.parent.exists():
            log.warning(
                f'Creating configuration directory... {path.parent}'
            )
            path.parent.mkdir(parents=True)
        path.write_text(config_bp)
    else:
        log.info(
            'Config already exists.'
        )
    return load_config(path)

def validate_config(config: dict):
    log.info(
        'Validating config...'
    )
    config = config or {}
    nexpose = config.get('nexpose')
    if not nexpose:
        log.error(
            'Config must have "nexpose" map defined at the top level'
        )
        return False, config

    success = True

    match nexpose:
        case {'username': name, 'password': pw, 
              'hostname': host, 'port': port}:
            for key in ['username', 'password', 'hostname']:
                if not is_str(nexpose[key]):
                    log.error(f'"{key}" key is not a string')
                    success = False
            if not is_int(port):
                log.error(f'"port" key is not an int')
                success = False

    for key in nexpose:
        if not nexpose[key]:
            log.error(f'"{key}" is an empty value.')
            success = False

    missing = set(['username', 'password', 'hostname', 'port']) - set(nexpose)
    if missing:
        log.error(
            f'"nexpose" map is missing the following keys: {", ".join(missing)}'
        )
        success = False

    if success:
        log.info('  ... valid.')
    else:
        log.error('  ... invalid.')
    return success, config

@ensure_paths
def load_config(path: Path) -> ConfigSuccess:
    '''Try to load a Nexpose configuration YAML file.

    Returns: Tuple[success(bool), config(dict)]
    '''
    if not path.exists():
        log.error(
            f'Config at path ({path}) does not exist. You should run'
            ' `init_config` first, edit that config YAML file, then try again.'
        )
        return False, {}

    log.info(
        f'Loading Nexpose config from path: {path}'
    )
    return pipe(
        path,
        yaml.read_yaml,
        validate_config,
    )

def load_default_config() -> ConfigSuccess:
    log.debug(repr(default_path))
    return load_config(default_path)

def api_from_config(path: Path) -> Api:
    success, config = load_config(path)
    if success:
        nexpose = config['nexpose']
        return new_api(
            nexpose['hostname'], nexpose['port'], 
            nexpose['username'], nexpose['password']
        )
    log.error('Could not load API object. See above.')

api_from_default_config = partial(api_from_config, default_path)
