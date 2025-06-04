import importlib.resources
from pathlib import Path
import typing as T
import importlib
from datetime import datetime
import logging

import dateutil.tz
import networkx as nx
from nicegui import app, ui, elements, Client
from nicegui.elements.row import Row
from nicegui.elements.column import Column
from nicegui.elements.button import Button
from nicegui.elements.select import Select
from nicegui.elements.markdown import Markdown
from nicegui.elements.dialog import Dialog
from nicegui.elements.date import Date
from nicegui.events import (
    ValueChangeEventArguments, ClickEventArguments, UploadEventArguments,
)


from ..logging import new_log
from ..toolz import *

log = new_log(__name__)

@memoize
def get_salt() -> str:
    return pipe(
        'salt.txt', slurp, strip(),
    )

def get_now():
    now = datetime.now().astimezone(
        dateutil.tz.gettz('America/Chicago')
    )
    log.debug(f'Now: {now}')
    return now

def local_dt(dt: datetime):
    return dt.astimezone(
        dateutil.tz.gettz('America/Chicago')
    )

def get_partial_environ(client: Client) -> dict:
    if client is None:
        return {}
    return pipe(
        client.environ or {},
        keyfilter(lambda k: k.isupper()),
    )

def get_client_path(client_hash: str, client: Client) -> Path:
    environ = get_partial_environ(client)
    dir_path = common.get_client_dir(client_hash)
    fingerprint_key = pipe(
        [client.ip, environ.get('HTTP_USER_AGENT', '')],
        ''.join,
        md5,
    )
    return dir_path / f'{fingerprint_key}-{client.id}.json'

def log_client_data(client_hash: str, client: Client):
    environ = get_partial_environ(client)
    client_path = get_client_path(client_hash, client)
    client_path_tmp = client_path.parent / (client_path.name + '.tmp')

    if not client_path.exists():
        # add data to tmp path
        log.info(
            f'Adding client {client_hash} data to {client_path}'
        )
        pipe(
            {
                'ts': get_now(),
                'hash': client_hash,
                'type': 'client-data',
                'id': client.id,
                'ip': client.ip,
                'environ': environ,
            },
            json_dumps,
            client_path_tmp.write_text,
        )
        # move tmp to actual in atomic operation
        client_path_tmp.rename(client_path)

