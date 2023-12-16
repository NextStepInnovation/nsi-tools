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
    '-o', '--output-dir', type=click.Path(), default='.',
    show_default=True,
    help='''
    Ouptut directory for metadata files
    ''',
)
@click.option(
    '-m', '--min-mtime', type=click.DateTime(),
    # default=str((datetime.now() - timedelta(days=6 * 30)).date()),
    help='''
    Minimum file modification time (mtime) to look for
    ''',
)
@click.option(
    '--sub-dir', is_flag=True, help='''
    Get metadata for all sub-directories of the given directories
    '''
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
    '--keep-empty', is_flag=True, help='''
    Keep empty metadata files (i.e. ones with no files found)
    '''
)
@click.option(
    '--do-zero', is_flag=True, help='''
    Traverse zero-size directories
    '''
)
@click.option(
    '--loglevel', default='info',
    help=('Log output level (default: info)'),
)
def metadata(directories, min_mtime, sub_dir, output_dir, ssh, echo, dry_run, skip_dir, 
             max_examples, case_sensitive, keep_empty, do_zero, loglevel):
    logging.setup_logging(loglevel)
    log.debug(directories)

    output_dir_path = Path(output_dir)
    done_dir_path = Path(output_dir_path) / '.nsi-meta'
    if not output_dir_path.exists():
        log.info(f'Creating output directory: {output_dir_path}')
        output_dir_path.mkdir(parents=True)
    done_dir_path.mkdir(parents=True, exist_ok=True)

    def done_path(path: Path) -> Path:
        return done_dir_path / (path.name + '.done')
    def output_path(path: Path) -> Path:
        return output_dir_path / f'meta-{path.name.replace(" ", "-")}.yml'

    directories = pipe(
        directories, 
        map(Path), 
        mapcat(lambda p: ([s for s in p.glob('*') if s.is_dir()]) if sub_dir else [p]),
        # filter(lambda p: not done_path(p).exists()),
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
    def writer(path: Path, meta: dict):
        if (meta['totals']['files'] + meta['totals']['dirs']) == 0 and not keep_empty:
            log.warning(f'{path} has no files. Not writing...')
            done_path(path).write_text('')
            return 0
        
        return pipe(
            meta,
            no_pyrsistent,
            yaml.dump,
            path.write_text,
            do(lambda x: done_path(path).write_text('')),
        )
    
    def meta(meta_path: Path):
        if dry_run:
            log.warning(
                f'DRY RUN: doing metadata search for {path}'
            )
            return
        path = output_path(meta_path)
        if done_path(path).exists():
            log.warning(
                f'YAML output found {path}... skipping'
            )
            return None
        if meta_path.stat().st_size == 0 and not do_zero:
            log.warning(
                f'Directory {meta_path} has zero size... skipping'
            )
            return None

        return pipe(
            filesystem.directory_metadata(
                meta_path, min_mtime=min_mtime, skip_dirs=skip_dir,
                max_examples=max_examples, no_case=(not case_sensitive),
                writer=writer(path),
            ),
            writer(path),
            do(lambda b: log.info(
                f'  .. wrote {b} bytes to {path}'
            )),
        )

    pipe(
        directories,
        parallel.thread_map(meta, max_workers=5),
        tuple,
        lambda t: log.info(f'  wrote {len([v for v in t if v])} files'),
    )

