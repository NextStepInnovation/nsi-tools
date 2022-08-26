'''Tools for dealing with Rapid7's Nexpose scanner
'''

import pprint
from pathlib import Path

import click
import pyperclip

from .. import logging
from .. import nexpose
from ..toolz import *

from .common import loglevel

log = logging.new_log(__name__)

@click.group(
    help='''
    Tools for dealing with Rapid7's Nexpose scanner
    '''
)
@loglevel
def nexpose_command(loglevel):
    logging.setup_logging(loglevel)

@curry
def pprint_config(printer, config):
    return pipe(
        config,
        no_pyrsistent,
        valmap(itemmap(vcall(lambda k, v: (k, '*****' if v and k == 'password' else v)))),
        pprint.pformat,
        splitlines,
        map(printer),
        tuple,
    )
    
@nexpose_command.command(
    help='''
    Create a Nexpose configuration YAML file at a given path
    (~/.config/nsi/nexpose.yml by default)
    '''
)
@click.argument(
    'output-path', type=click.Path(dir_okay=False), 
    required=False, default=nexpose.config.default_path
)
def init_config(output_path):
    log.info('Initializing configuration YAML file for Nexpose API at:')
    log.info(f'  path: {output_path}')

    valid, config = nexpose.config.init_config(output_path)
    if not valid:
        log.error('Config is invalid:')
        pprint_config(log.error, config)

@nexpose_command.command(
    help='''
    Test connectivity to Nexpose scanner based on either configured or given
    connection information.  If no connection info is given, then it will be
    pulled from ~/.config/nsi/nexpose.yml configuration file (potentially)
    generated by the nsi-nexpose init-config command.
    '''
)
@click.option(
    '-c', '--config-path', type=click.Path(dir_okay=False, exists=True), 
    default=nexpose.config.default_path
)
def check_connection(config_path):
    log.info('Checking connection to Nexpose API based on configuration:')
    log.info(f'  path: {config_path}')
    valid, config = nexpose.config.load_config(config_path)
    if not valid:
        log.error('Config is invalid:')
        pprint_config(log.error, config)

    api = nexpose.api.new_api(**config['nexpose'])
    print(nexpose.reports.report_map(api))

# @nexpose_command.command(
#     '''
# )

