from itertools import product
from pathlib import Path
from typing import Union, Callable, Tuple, Iterable, Dict
import logging
from datetime import datetime
import typing as T
import pprint
import re
import math

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

def get_name(node: dict):
    match node:
        case {'Name': name}:
            return name
        case {'Properties': {'name': name}}:
            return name
        case {'ObjectIdentifier': name}:
            return name
    d_str = pprint.pformat(node)[:100]
    log.error(pprint.pformat(node))
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

def get_email(d):
    return d.get('Properties', {}).get('email') or ''

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
    def get_data(d, type):
        if type in d:
            return d[type]
        return d['data']
    return pipe(
        merge(
            {'computers': [], 'domains': [], 'groups': [],
                'sessions': [], 'users': []},
            pipe(
                paths,
                map(parse_json),
                error_raise(map(lambda d: (
                    d['meta']['type'], get_data(d, d['meta']['type'])
                ))),
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
    
# @curry
# def lookup_member(object, member: dict):
#     return object.parent.by_id.get(member.get('MemberId'))

# @curry
# def get_members_from_key(key, object):
#     return pipe(
#         object.get(key, []),
#         map(lookup_member(object)),
#         filter(None),
#         tuple,
#     )

# get_group_members = get_members_from_key('Members')

# def get_displayname(user: dict):
#     return user['Properties'].get('displayname', '') or ''

# def get_groups(data: dict, group: dict):
#     for g in data['groups']:
#         for member in get_group_members(g):
#             if get_id(member) == get_id(group):
#                 yield group

# get_localadmins = get_members_from_key('LocalAdmins')

# def get_sessions(computer: T.Dict):
#     pass

# def parse_root_path(path: Union[str, Path]):
#     '''Parse the root data path, i.e. with timestamped subdirectories,
#     return dictionary with Datetime objects as keys and list of JSON
#     paths as values

#     '''
#     return pipe(
#         Path(path).expanduser().glob('*'),
#         filter(lambda p: p.is_dir() and maybe_dt(p.name)),
#         mapcat(lambda p: product(
#             (to_dt(p.name),),
#             p.glob('*.json')
#         )),
#         bakedict(lambda t: t[0], lambda t: t[1]),
#         valmap(bloodhound_data_from_paths),
#     )

# def ingest_time_dependent_data(data: Dict[datetime, Iterable[Path]],
#                                ingestor: Callable[[datetime, Path],
#                                                   Tuple[bool, Tuple[str]]], *,
#                                short_circuit=True):
#     error_prefix = f'Error ingesting for {ingestor}\n'

#     def log_errors(errors):
#         return pipe(
#             errors,
#             map(lambda e: f'- {e}'),
#             '\n'.join,
#             lambda estr: error_prefix + estr,
#             log.error,
#         )
    
#     for dt, paths in data.items():
#         for p in paths:
#             success, errors = ingestor(dt, p)
#             if not success:
#                 log_errors(errors)
#                 if short_circuit:
#                     return False
#     return True

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

@memoize
@ensure_paths
def primary_groups(path: Path):
    data = parse_directory(path)
    return pipe(
        concatv(data['users'], data['computers']),
        filter(lambda n: n.get('PrimaryGroupSID')),
        map(lambda n: (
            pipe(
                data['by_id'][n['PrimaryGroupSID']],
                get_name,
            ), n
        )),
        groupby(first),
        valmap(map_t(second)),
    )

@curry
@ensure_paths
def get_members(path: Path, node: dict, *, level: int=0, 
                max_level: int=math.inf):
    data = parse_directory(path)
    prim_groups = primary_groups(path)
    match node:
        case {'type': 'groups'} as group:
            if level < max_level:
                yield from pipe(
                    concatv(
                        group['Members'],
                        prim_groups.get(get_name(group), [])
                    ),
                    map(get_id),
                    map(data['by_id'].get),
                    filter(None),
                    map(get_members(
                        path, 
                        level=level+1, 
                        max_level=max_level,
                    )),
                    concat,
                )
            else:
                yield group
        case {'type': 'computers'} as computer:
            yield computer
        case {'type': 'users'} as user:
            yield user

@curry
@ensure_paths
def object_search(obj_type: str, path: Path, obj_re: str):
    isearch = lambda s: bool(to_regex(obj_re, re.I).search(s))
    data = parse_directory(path)

    return pipe(
        data[obj_type],
        filter(compose_left(get_name, isearch, bool)),
        tuple,
        map(lambda obj: (get_name(obj), obj)),
        dict
    )

user_search = object_search('users')
group_search = object_search('groups')
computer_search = object_search('computers')

@curry
@ensure_paths
def object_members(obj_type: str, path: Path, obj_re: str, *, 
                   max_level: int=math.inf):
    log.info(
        (obj_type, path, obj_re, max_level)
    )
    return pipe(
        object_search(obj_type, path, obj_re),
        valmap(lambda node: get_members(
            path, node, max_level=max_level,
        )),
        valmap(unique(key=get_name)),
        valmap(tuple),
    )

group_members = object_members('groups')

def user_groups(path: Path):
    return pipe(
        group_members(path, '.*'),
        valmap(filter(lambda n: n['type'] == 'users')),
        valmap(map(get_name)),
        items,
        vmapcat(lambda g, users: [(u, g) for u in users]),
        groupby(first),
        valmap(map_t(second)),
    )

# @curry
# @ensure_paths
# def group_members(path: Path, group_name: str, *, recurse: bool = False):
#     data = parse_directory(path)

#     return pipe(
#         data['by_name'][group_name],
#         get_members(path, recurse=recurse),
#         filter(None),
#         unique(key=get_id),
#         tuple,

#     )

# @curry
# @ensure_paths
# def group_search(path: Path, group_re: str, *, recurse=False):
#     data = parse_directory(path)
#     groups = pipe(
#         data['groups'],
#         map(get_name),
#         igrept(group_re),
#     )
#     return pipe(
#         groups,
#         map(lambda gname: (
#             gname, 
#             group_members(path, gname, recurse=recurse),
#         )),
#         dict,
#     )

group_search_names = compose_left(
    group_search,
    valmap(map_t(get_name)),
)


