'''Tools for dealing with Rapid7's Nexpose scanner
'''

import pprint
from pathlib import Path
import typing as T

import click

from .. import logging
from .. import nexpose
from .. import yaml
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

def get_config(config_path: Path):
    valid, config = nexpose.config.load_config(config_path)
    if not valid:
        log.error('Config is invalid:')
        pprint_config(log.error, config)
        raise click.Abort

    return config

config_option = compose_left(
    click.option(
        '-c', '--config-path', type=click.Path(dir_okay=False, exists=True), 
        default=nexpose.config.default_path,
        help='''
        Path to YAML configuration file for connecting to Nexpose console API
        '''
    )
)

@curry
def get_api_obj(config: dict, api_function: T.Callable, *args, **kwargs):
    try:
        return api_function(*args, **kwargs)
    except:
        log.error(
            f'Problem with running API function {api_function} with given configuration:'
        )
        pprint_config(log.error, config)
        raise

    
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
    log.info('Initializing default configuration YAML file for Nexpose API at:')
    log.info(f'  path: {output_path}')

    valid, config = nexpose.config.init_config(output_path)
    if not valid:
        log.error('Config is invalid:')
        pprint_config(log.error, config)

@nexpose_command.command(
    help='''
    Test connectivity to Nexpose console API based on either previously-setup or
    provided connection configuration.  If no connection info is given, then it
    will be pulled from ~/.config/nsi/nexpose.yml configuration file
    (potentially) generated by the nsi-nexpose init-config command.
    '''
)
@config_option
@click.option(
    '-c', '--config-path', type=click.Path(dir_okay=False, exists=True), 
    default=nexpose.config.default_path,
    help='''
    Path to YAML configuration file for connecting to Nexpose console API
    '''
)
def check_config(config_path):
    log.info('Checking connection to Nexpose API based on configuration:')
    log.info(f'  path: {config_path}')

    config = get_config(config_path)
    api = nexpose.api.new_api(**config['nexpose'])

    site_map = get_api_obj(config, nexpose.sites.site_map, api)

    log.info(
        f'There are {len(site_map)} sites:'
    )
    for name in pipe(site_map, keyfilter(is_str), sorted):
        log.info(
            f'- {name}'
        )

@nexpose_command.command(
    help='''
    Download the XML report for some number of Nexpose sites
    '''
)
@click.argument('sites', nargs=-1)
@config_option
@click.option(
    '-n', '--name', help='''
    Name of report. If not given, will be ['-'.join(sites)]-nexpose-data
    
    Will function as stem of file path if --output-path not given.
    '''
)
@click.option(
    '-o', '--output-path', type=click.Path(),
    help='''
    Path to write Report XML data. If not given, will be constructed from
    --name.
    '''
)
@click.option(
    '--force', is_flag=True, help='''
    Force regeneration of report content. Normally, if report has already been
    generated, then this will pull the old content.
    '''
)
@click.option(
    '--keep', is_flag=True, help='''
    Keep the report on the Nexpose console. Otherwise, it will be deleted after
    being written to the filesystem.
    '''
)
def download_report(sites, config_path, name, output_path, force, keep):
    log.info('Initializing report download')

    config = get_config(config_path)
    api = nexpose.api.new_api(**config['nexpose'])

    site_map = get_api_obj(config, nexpose.sites.site_map, api)
    site_names = pipe(site_map, keyfilter(is_str), sorted)

    bad_sites = set(sites) - set(site_names)
    if bad_sites:
        log.error(
            'The following provided sites do not exist in the configured'
            ' Nexpose console:'
        )
        for name in bad_sites:
            log.error(f'- {name}')
        log.error(
            'The following are valid site names:'
        )
        for name in site_names:
            log.error(f'- {name}')
        raise click.Abort

    log.info(f'Downloading {len(sites)} report(s) for the following sites:')
    for site in sites:
        log.info(f'- {site}')

    if name is None:
        name = pipe(
            sites,
            sorted,
            '-'.join,
        )
    if output_path is None:
        output_path = f'{name}-nexpose-data.xml'
    output_path = Path(output_path).expanduser()

    log.info(
        f'Downloading XML data and writing to {output_path}'
    )

    success, content = nexpose.reports.download_report(
        api, name, site_ids=sites, force_regen=force,
    )

    if success:
        output_path.write_bytes(content)

    if not keep:
        log.info(f'Destroying report: {name}')
        nexpose.reports.destroy_report(api, name)
    

@nexpose_command.command(
    help='''
    For a given set of XML reports, get the relevant stats for the data in those
    reports
    '''
)
@click.argument('xml-paths', nargs=-1)
@click.option(
    '-o', '--output-path', type=click.Path(),
    default='report-stats.yml', show_default=True,
    help='''
    Path to write Report stats.
    '''
)
def report_stats(xml_paths, output_path):
    log.info(f'Pulling stats for {len(xml_paths)} XML reports')

    output_path = Path(output_path).expanduser()
    if not output_path.parent.exists():
        log.info(
            f'Creating parent directory for {output_path}'
        )
        output_path.parent.mkdir(parents=True)

    reports = pipe(
        xml_paths,
        map(lambda p: (str(p), nexpose.xml.stats.node_stats(p))),
        dict,
        yaml.write_yaml(output_path),
    )


    