'''Filesystem searching/analysis command line tools
'''
from pathlib import Path
from datetime import datetime, timedelta
import logging
import pprint

import click

from . import common
from ..toolz import *
from .. import logging, shell, filesystem, parallel, yaml

log = logging.new_log(__name__)

@click.command(help='''
Given some number of DIRECTORIES to search, provide metadata about those
directories.
''', context_settings={'show_default': True})
@click.argument(
    'directories', type=click.Path(file_okay=False, exists=True),
    nargs=-1,
)
@click.option(
    '-m', '--min-mtime', type=click.DateTime(),
    # default=str((datetime.now() - timedelta(days=6 * 30)).date()),
    help='''
    Minimum file modification time (mtime) to look for
    ''',
)
@common.ssh_options
@click.option(
    '--echo', is_flag=True,
    help=(
        'Echo the content of the individual commands for debugging purposes'
    ),
)
@click.option(
    '--dry-run', is_flag=True,
    help="Don't run command, just show what shell commands would have run",
)
@click.option(
    '-s', '--skip-dir', multiple=True, help='''
    Skip processing on all files in this directory
    '''
)
@click.option(
    '-e', '--max-examples', type=int, default=filesystem.DEFAULT_MAX_EXAMPLES,
    show_default=True,
    help='''
    Maximum number of examples of each file extension
    '''
)
@click.option(
    '-C', '--case-sensitive', is_flag=True, help='''
    Treat all files/extensions/etc. in a case-sensitive manner
    '''
)
@click.option(
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def metadata(directories, min_mtime, ssh, echo, dry_run, skip_dir, max_examples, 
             case_sensitive, loglevel):
    logging.setup_logging(loglevel)
    log.debug(directories)
    def outpath(path):
        return path.parent / f'meta-{path.name.replace(" ", "-")}.yml'

    directories = pipe(
        directories, 
        map(Path), 
        filter(lambda p: not outpath(p).exists()),
        tuple,
    )

    getoutput = shell.getoutput(echo=echo, dry_run=dry_run)
    if ssh:
        getoutput = common.ssh_getoutput(ssh, echo=echo, dry_run=dry_run)

    log.info(
        f'Starting metadata search for {len(directories)} dirs with minimum'
        f' modification time {min_mtime}'
    )

    @curry
    def writer(output_path: Path, meta: dict):
        return pipe(
            meta,
            no_pyrsistent,
            yaml.dump,
            output_path.write_text,
        )
    
    def meta(path):
        if dry_run:
            log.warning(
                f'DRY RUN: doing metadata search for {path}'
            )
            return
        output_path = outpath(path)
        if output_path.exists():
            log.warning(
                f'YAML output found {output_path}... skipping'
            )
            return None
        return pipe(
            filesystem.directory_metadata(
                path, min_mtime=min_mtime, skip_dirs=skip_dir,
                max_examples=max_examples, no_case=(not case_sensitive),
                writer=writer(output_path),
            ),
            writer(output_path),
            do(lambda b: log.info(
                f'  .. wrote {b} bytes to {output_path}'
            )),
        )

    pipe(
        directories,
        parallel.thread_map(meta),
        tuple,
        lambda t: log.info(f'  wrote {len(t)} files'),
    )

