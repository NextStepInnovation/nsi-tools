import os
from pathlib import Path
import tempfile
import shutil
import typing as T
import sys

import click
import nsi
from nsi.toolz import *

log = nsi.logging.new_log(__name__)

def run_pycomplete(shell: str, path: str):
    log.info(f'Running pycomplete for path: {path}')
    log.info(f'  path: {path}')
    command = f'python3 -m pycomplete "{path}" {shell}'
    log.info(f'  command: {command}')
    shell_code = nsi.shell.getoutput(command, echo=False)
    scripts = pipe(
        shell_code,
        finditerd(r'complete -o default -F \w+ (?P<script>.*)'),
        map(get('script')),
        tuple,
    )
    log.info(f'  found {len(scripts)} scripts for path: {path}')

    return scripts, shell_code

def load_completions(shell: str, printer: T.Callable[[str], None]):
    found = set()
    for script, path in pipe('scripts.json', slurp, json_loads):
        if script in found:
            continue
        scripts, shell_code = run_pycomplete(shell, path)
        found.update(scripts)
        printer(shell_code)
        sys.stdout.flush()


@click.command()
@click.option(
    '-s', '--shell', type=click.Choice(
        choices=['bash', 'fish', 'zsh', 'powershell']), 
    default='bash',
)
def main(shell):
    nsi.logging.setup_logging('info')
    with tempfile.TemporaryDirectory() as dir_name:
        dir_path = Path(dir_name)
        shutil.copy('scripts.json', dir_path)
        os.chdir(dir_name)
        load_completions(shell, lambda s: print(s + '\n\n\n'))

if __name__ =='__main__':
    main()