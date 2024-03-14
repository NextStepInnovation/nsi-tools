#!/usr/bin/env python3
from ipaddress import IPv4Address
import logging
import re
from pathlib import Path
import typing as T

import requests

from . import shell
from .toolz import *
from . import logging
from . import ntlm

log = logging.new_log(__name__)

@curry
def ntlmrelayx(ip: T.Union[str, IPv4Address], 
               user: str, hashes=None, 
               password=None, domain=None, *, 
               ntlmrelayx_exec='impacket-ntlmrelayx',
               getoutput=shell.getoutput, **ntlmrelayx_options):
    # -smb2support -tf signing-off.txt -of cosl -ts -6 -socks

    options = pipe(
        ntlmrelayx_options,
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
        (f"sudo {ntlmrelayx_exec} {hashes} {options} '{user}@{ip}'"
         if hashes else
         f"{ntlmrelayx_exec} {options} '{user}':'{password}'@'{ip}'")
    )

    log.info(f'ntlmrelayx command: {command}')

    return getoutput(command)

def get_socks():
    url = 'http://127.0.0.1:9090/ntlmrelayx/api/v1.0/relays'
    