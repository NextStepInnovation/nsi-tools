'''CrackMapExec wrapper
'''
from pathlib import Path
from datetime import datetime
import shlex
import xml.etree.ElementTree
import typing as T
from typing import Union
from collections import defaultdict
from pymaybe import Nothing
import hashlib
import pprint
import re
import json

import networkx as nx
import xmljson

from .toolz import *
from . import toolz as _
from . import yaml
from . import parallel
from .shell import getstatusoutput
from .graph import network as network_graph
from . import data
from . import logging

log = logging.new_log(__name__)

def cme_command(command: str, target: str, raw_options: str, **options) -> str:
    args = pipe(
        options,
        items,
        vmap(lambda k, v: (k.replace('_', '-'), v)),
        vmap(lambda k, v: f"{'-' if len(k)==1 else '--'}{k} '{v}'"),
        ' '.join,
    ) + raw_options
    command_str = f'crackmapexec {command} {target} {args}'
    return command_str

Target = str | Path

@curry
def crackmapexec(command: str, target: Target, *, 
                 raw_options: str = '',
                 getstatusoutput=getstatusoutput(echo=False), **cme_options):

    options = merge(cme_options, {
    })

    command_str = cme_command(command, target, raw_options, **cme_options)

    log.info(
        f'Running CrackMapExec with command: {command_str}'
    )

    code, output = getstatusoutput(command_str)

    return code == 0, output


smb_crackmapexec = crackmapexec('smb')


smb_line_re = re.compile(
    r'SMB\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+445\s+(?P<hostname>.*?)\s+'
    r'\[\*\]\s+(?P<os>.*?)\s+'
    r'\(name:(?P<name>.*?)\)\s+'
    r'\(domain:(?P<domain>.*?)\)\s+'
    r'\(signing:(?P<signing>(True|False))\)\s+'
    r'\(SMBv1:(?P<v1>(True|False))\)$'
)

parse_smb = compose_left(
    slurplines,
    map(groupdict(smb_line_re)),
    filter(None),
)