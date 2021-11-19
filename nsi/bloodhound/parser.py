from itertools import product
from pathlib import Path
from typing import Union, Callable, Tuple, Iterable, Dict
import logging
from datetime import datetime
import typing as T
import pprint
import re

from ..toolz import *
from .. import logging

log = logging.new_log(__name__)
info = do_info(log)

@ensure_paths
def parse_json(path: Path):
    log.info(
        f'Loading JSON from: {path} size: {path.stat().st_size}'
    )
    return pipe(
        path.read_text(),
        json_loads,
        info(
            '  .. done.'
        )
    )

def get_name(d):
    match d:
        case {'Name': name}:
            return name
        case {'Properties': {'name': name}}:
            return name
        case {'ObjectIdentifier': name}:
            return name
    d_str = pprint.pformat(d)[:1000]
    log.error(d_str)
    raise KeyError(f'No name for {d_str}')

def get_id(d):
    match d:
        case {'MemberId': id}:
            return id
        case {'ObjectIdentifier': id}:
            return id
    d_str = pprint.pformat(d)[:1000]
    log.error(d_str)
    raise KeyError(
        f'Could not find ID for {d_str}'
    )

def bloodhound_data(data: dict):
    log.info(
        'Creating bloodhound data...'
    )
    for key, objects in data.items():
        for o in objects:
            o['type'] = key

    all_objects = (
        data['computers'] + data['domains'] + 
        data['groups'] + data['users']
    )
    return pipe(merge(
        data,
        {'all_objects': all_objects},
        {'by_id': {
            get_id(o): o for o in all_objects
        }},
        {'by_name': pipe(
            data.values(),
            concat,
            map(lambda o: (get_name(o), o)),
            dict,
        )},
    ), do(lambda _: log.info('  .. done.')))

def bloodhound_data_from_paths(paths: T.List[Path]):
    return pipe(
        merge(
            {'computers': [], 'domains': [], 'groups': [],
                'sessions': [], 'users': []},
            pipe(
                paths,
                map(parse_json),
                map(lambda d: (
                    d['meta']['type'], d[d['meta']['type']]
                )),
                dict,
            ),
        ),
        bloodhound_data,
    )

@memoize
def parse_directory(path: Union[str, Path]):
    '''Parse directory with Bloodhound JSON files

    '''
    return pipe(
        Path(path).expanduser().glob('*.json'),
        bloodhound_data_from_paths,
    )
    
@curry
def lookup_member(object, member: dict):
    return object.parent.by_id.get(member.get('MemberId'))

@curry
def get_members_from_key(key, object):
    return pipe(
        object.get(key, []),
        map(lookup_member(object)),
        filter(None),
        tuple,
    )

get_group_members = get_members_from_key('Members')

def get_displayname(user: dict):
    return user['Properties'].get('displayname', '') or ''

def get_groups(data: dict, group: dict):
    for g in data['groups']:
        for member in get_group_members(g):
            if get_id(member) == get_id(group):
                yield group

get_localadmins = get_members_from_key('LocalAdmins')

def get_sessions(computer: T.Dict):
    pass

def get_users(group):
    for member in group.members:
        if member.is_group:
            yield from get_users(member)
        elif member.is_user:
            yield member

def parse_root_path(path: Union[str, Path]):
    '''Parse the root data path, i.e. with timestamped subdirectories,
    return dictionary with Datetime objects as keys and list of JSON
    paths as values

    '''
    return pipe(
        Path(path).expanduser().glob('*'),
        filter(lambda p: p.is_dir() and maybe_dt(p.name)),
        mapcat(lambda p: product(
            (to_dt(p.name),),
            p.glob('*.json')
        )),
        bakedict(lambda t: t[0], lambda t: t[1]),
        valmap(bloodhound_data_from_paths),
    )

def ingest_time_dependent_data(data: Dict[datetime, Iterable[Path]],
                               ingestor: Callable[[datetime, Path],
                                                  Tuple[bool, Tuple[str]]], *,
                               short_circuit=True):
    error_prefix = f'Error ingesting for {ingestor}\n'

    def log_errors(errors):
        return pipe(
            errors,
            map(lambda e: f'- {e}'),
            '\n'.join,
            lambda estr: error_prefix + estr,
            log.error,
        )
    
    for dt, paths in data.items():
        for p in paths:
            success, errors = ingestor(dt, p)
            if not success:
                log_errors(errors)
                if short_circuit:
                    return False
    return True

def get_names(objects):
    return pipe(
        objects,
        map(get_name),
        set,
        sorted,
    )

get_computer_names = compose_left(
    parse_directory,
    lambda o: o['computers'],
    get_names,
)

@ensure_paths
def group_members(path: Path, group_name: str):
    data = parse_directory(path)
    return pipe(
        data['by_name'][group_name],
        get("Members"),
        map(get_id),
        map(data['by_id'].get),
        filter(None),
        tuple,
    )

group_member_names = compose_left(
    group_members,
    map(get_name),
    tuple,
)

@ensure_paths
def group_search(path: Path, group_re: str):
    data = parse_directory(path)
    group_re = re.compile(group_re, re.I)
    return pipe(
        data['groups'],
        map(get_name),
        filter(group_re.search),
        map(lambda uname: (uname, group_members(path, uname))),
        dict,
    )

group_search_names = compose_left(
    group_search,
    valmap(map_t(get_name)),
)


def list_objects(inpath, outpath, ssh, echo, from_clipboard,
                 to_clipboard, csv, user, keep_duplicates, obj_func):
    data = parse_directory(inpath)

    if user:
        user = pipe(
            data.users,
            filter(lambda o: re.search(user, o.name, re.I)),
            maybe_first,
        )
        if not user:
            log.error(f'No user could be found with name regex: {user}')
            raise AttributeError(
                f'No user could be found with name regex: {user}'
            )

    @curry
    def object_for_user(user, objects):
        pass

    def csv_format(hosts):
        return csv_rows_to_content(
            hosts, columns=['name', 'id'],
        )

    def print_formatter(hosts):
        return pipe(
            hosts,
            vmap(lambda name, id: f'{name}\t{id}'),
            '\n'.join,
        )
    
    formatter = print_formatter
    if csv:
        formatter = csv_format

    outputter = print
    if outpath:
        outputter = Path(outpath).expanduser().write_text

    pipe(
        obj_func(data),
        map(lambda c: (get_name(c), get_id(c))),
        set,
        sorted,
        formatter,
        outputter,
    )

