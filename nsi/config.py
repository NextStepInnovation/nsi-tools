import logging
from pathlib import Path

from . import toolz as _
from . import yaml
from . import logging

log = logging.new_log(__name__)

CONFIG = '''\
# NSI tools YAML configuration
#
#
secretsdump:
  exec: impacket-secretsdump
wmiexec:
  exec: impacket-wmiexec
'''

def user_config():
    config_dir = Path('~/.config/nsi').expanduser()
    if not config_dir.exists():
        config_dir.mkdir(parents=True)

    path = Path(config_dir, 'config.yml')
    if path.exists():
        return yaml.read_yaml(path)

    path.write_text(CONFIG)
    return yaml.read_yaml(path)

def site_config(start_dir=Path('.')):
    config_path = _.check_parents_for_file('nsi.yml', start_dir)

    config = {}
    if config_path:
        config = yaml.read_yaml(config_path)

    return _.merge(user_config(), config)

