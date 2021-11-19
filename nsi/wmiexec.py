from pathlib import Path
import logging

from . import shell, logging
from . import toolz as _
from .toolz import (
    map, filter, pipe, compose, partial, merge, curry
)
from . import config

log = logging.new_log(__name__)

@curry
def wmiexec(domain, username, password, target, command, *,
            getoutput=shell.getoutput, exe=None):
    exe = exe or config.site_config()['wmiexec']['exec']
    command = (
        f"{exe} {domain}/{username}:'{password}'@{target} '{command}'"
    )
    log.debug(command)
    return getoutput(command)

os_info_regexes = [
    r'^OS Name:\s+(?P<name>.*?)\s*$',
    r'^OS Version:\s+(?P<version>.*?)\s*$',
]

@curry
def os_info(domain, username, password, target, *,
            getoutput=shell.getoutput(timeout=60), exe=None):
    return pipe(
        wmiexec(
            domain, username, password, target,
            'systeminfo | findstr /B /C:"OS Name" /C:"OS Version"',
            getoutput=getoutput, exe=exe
        ).splitlines(),
        _.groupdicts_from_regexes(os_info_regexes),
        merge,
    )
