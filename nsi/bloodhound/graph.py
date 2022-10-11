import pprint
import typing as T
import re
from pathlib import Path

import networkx as nx

from ..toolz import *
from .. import markdown
from .. import logging

from . import parser
from .parser import (
    get_id,
)

log = logging.new_log(__name__)

#----------------------------------------------------------------------------
#
# BloodHound to NetworkX graph utilities
#
#----------------------------------------------------------------------------

NodeId = T.NewType('NodeId', str)
NodeType = T.NewType('NodeType', str)
class NodeData(T.TypedDict):
    sid: NodeId
    type: NodeType
    Properties: T.Dict[str, str|float|int|None]

def new_node_data(**data) -> NodeData:
    return merge({
        'sid': '',
        'type': 'unknown',
        'Properties': {},
    }, data)

NodeDataList = T.Iterable[NodeData]

def data_id(data: NodeData) -> NodeId:
    return data['sid']

sid_re = re.compile(
    r'^.*?S-(?P<sid>(?:\d+-)\d+)$'
)
def get_sid(data: NodeData):
    return pipe(data_id(data), groupdict(sid_re), get('sid'))

def data_type(data: NodeData) -> NodeType:
    try:
        return data['type']
    except KeyError:
        log.error('Could not find "type" key for:')
        for line in pprint.pformat(data).splitlines():
            log.error(line)
        raise

@curry
def node_type(graph: nx.MultiDiGraph, id: NodeId, 
              *ids: T.Tuple[NodeId]) -> T.Iterable[NodeType]:
    return (data_type(graph.nodes[i]) for i in ((id,) + ids))

@curry
def test_type(test_f: T.Callable[[T.Iterable[bool]], bool], type: NodeType, 
              graph: nx.MultiDiGraph, id: NodeId, *ids: T.Tuple[NodeId]) -> bool:
    return test_f(t == type for t in node_type(graph, id, *ids))

all_group = test_type(all, 'groups')
all_user = test_type(all, 'users')
all_computer = test_type(all, 'computers')
all_domain = test_type(all, 'domains')
any_group = test_type(any, 'groups')
any_user = test_type(any, 'users')
any_computer = test_type(any, 'computers')
any_domain = test_type(any, 'domains')

@curry
def node_search(query_f: T.Callable[[nx.Graph, NodeData], bool], 
                graph: nx.MultiDiGraph, ) -> NodeDataList:
    '''
    '''
    for _node_id, data in graph.nodes(data=True):
        if query_f(graph, data):
            yield data

def nodes_of_types(types: T.Iterable[NodeType]) -> NodeDataList:
    types = set(types)
    return node_search(
        lambda _graph, data: data_type(data) in types
    )

users = nodes_of_types(['users'])
computers = nodes_of_types(['computers'])
groups = nodes_of_types(['groups'])
domains = nodes_of_types(['domains'])
unknowns = nodes_of_types(['unknown'])

def in_edges(graph: nx.Graph, data: NodeData):
    '''
    '''


#-------------------------------------------
# BloodHound -> NetworkX ingest
#-------------------------------------------

def links_from_aces(object: dict):
    return pipe(
        object.get('Aces', []),
        map(lambda a: merge(a, {
            'source': get_id(a),
            'target': get_id(object),
        })),
    )

@curry
def get_links(type: str, data: dict):
    return pipe(
        data.get(type, []),
        mapcat(links_from_aces),
    )

user_links = get_links('users')
computer_links = get_links('computers')

def user_nodes(data: dict):
    return pipe(
        data['users'],
        map(cdissoc('Aces')),
        map(lambda u: merge(u, {
            'id': get_id(u),
            'sid': get_id(u),
        })),
    )

def computer_nodes(data: dict):
    return pipe(
        data['computers'],
        map(cdissoc('Aces')),
        map(lambda c: merge(c, {
            'id': get_id(c),
            'sid': get_id(c),
        })),
    )

def group_nodes(data: dict):
    return pipe(
        data['groups'],
        map(cdissoc('Aces')),
        map(cdissoc('Members')),
        map(lambda g: merge(g, {
            'id': get_id(g),
            'sid': get_id(g),
        })),
    )

def group_members(data: dict):
    for group in data['groups']:
        for member in group.get('Members', []):
            yield member

def group_links(data: dict):
    for group in data.get('groups', []):
        yield from links_from_aces(group)
        for member in group.get('Members', []):
            yield {
                'source': get_id(member),
                'target': get_id(group),
                'RightName': 'MemberOf',
            }

def domain_nodes(data: dict):
    def domains(domain: dict):
        yield pipe(
            domain,
            cmerge({
                'id': get_id(domain),
                'sid': get_id(domain),
            }),
            cdissoc('Aces'),
            cdissoc('Trusts'),
        )
        for trust in domain.get('Trusts', []):
            yield from domains({
                'ObjectIdentifier': trust['TargetDomainSid'],
                'Properties': {
                    'name': trust['TargetDomainName'],
                    'domain': trust['TargetDomainName'],
                },
                'type': 'domains',
            })

    return pipe(
        data['domains'],
        mapcat(domains),
    )

def domain_links(data: dict):
    for domain in data['domains']:
        yield from links_from_aces(domain)
        for trust in domain.get('Trusts', []):
            match trust:
                case {'TrustDirection': 'Inbound'}:
                    yield merge(trust, {
                        'source': get_id(domain),
                        'target': trust['TargetDomainSid'],
                        'RightName': 'TrustedBy',
                    })
                case {'TrustDirection': 'Outbound'}:
                    yield merge(trust, {
                        'source': trust['TargetDomainSid'],
                        'target': get_id(domain),
                        'RightName': 'TrustedBy',
                    })
                case {'TrustDirection': 'Bidirectional'}:
                    yield from [
                        merge(trust, {
                            'source': get_id(domain),
                            'target': trust['TargetDomainSid'],
                            'RightName': 'TrustedBy',
                        }),
                        merge(trust, {
                            'source': trust['TargetDomainSid'],
                            'target': get_id(domain),
                            'RightName': 'TrustedBy',
                        }),
                    ]

def node_list(data: dict) -> T.Iterable[dict]:
    users = tuple(user_nodes(data))
    computers = tuple(computer_nodes(data))
    domains = tuple(domain_nodes(data))
    groups = tuple(group_nodes(data))

    all_ids = pipe(
        concatv(users, computers, domains, groups),
        map(data_id),
        set,
    )

    all_members = pipe(
        group_members(data),
        groupby(get_id),
        # keyfilter(bool),
    )

    yield from concatv(users, computers, domains, groups)

    for unknown_id in set(all_members) - all_ids:
        if unknown_id:
            yield new_node_data(**{
                'id': unknown_id,
                'sid': unknown_id,
            })

def link_list(data: dict) -> T.Iterable[dict]:
    yield from user_links(data)
    yield from computer_links(data)
    yield from group_links(data)
    yield from domain_links(data)

def get_bloodhound_graph(directory: Path) -> nx.MultiDiGraph:
    data = parser.parse_directory(directory)
    nodes = tuple(node_list(data))
    links = tuple(link_list(data))

    node_ids = pipe(
        nodes,
        map(data_id),
        set,
    )
    link_ids = pipe(
        links,
        mapcat(lambda l: (l['source'], l['target'])),
        set,
    )

    nodes = tuple(concatv(nodes, pipe(
        link_ids - node_ids,
        filter(None),
        map(lambda i: new_node_data(**{
            'id': i, 
            'sid': i,
        })),
    )))

    return nx.node_link_graph({
        'directed': True,
        'multigraph': True,
        'nodes': nodes,
        'links': links,
    })



#----------------------------------------------------------------------------
# Exported graph utilities
#----------------------------------------------------------------------------

def get_exported_graph(path: Path) -> nx.Graph:
    data = pipe(
        path,
        slurp,
        json_loads,
    )
    nodes = pipe(
        data['nodes'],
        map(lambda n: merge({
            'node_id': n['id'],
        }, n)),
    )
    return nx.node_link_graph(
        {'nodes': nodes, 'links': data['edges']},
        directed=True,
    )

def user_ou_list(user: dict):
    return pipe(
        user.get('props', {}).get('distinguishedname', ''),
        split(','),
        filter(startswith('OU=')),
        map(split('=')),
        map(second),
        tuple,
    )

def job_from_ou(user: dict):
    return pipe(
        user,
        user_ou_list,
        map(lambda s: s.capitalize()),
        ', '.join,
    )

def job_from_description(user: dict):
    return user['props']['description']

def sort_by_account(nodes):
    return pipe(
        nodes,
        sort_by(vcall(lambda i, n: n['label'])),
    )

@curry    
def user_computer_perm_data(graph: nx.DiGraph, user_job_f=job_from_ou, 
                             node_sort_f=sort_by_account):
    edges = lambda u: [
        merge({'target': graph.nodes[dest]}, graph[u['node_id']][dest][edge])
        for dest in graph[u['node_id']] 
        for edge in graph[u['node_id']][dest]
    ]
    return pipe(
        graph.nodes(data=True),
        node_sort_f,
        vfilter(lambda i, n: n['type'] == 'User'),
        vmapcat(lambda i, u: [
            {
                'name': u['props'].get('displayname', u['label']), 
                'job': user_job_f(u),
                'account': f"`{u['label'].split('@')[0]}`",
                'perm': edge['label'],
                'host': edge['target']['label'],
            } for edge in edges(u)
        ]),
        tuple,
    )

@curry
def user_computer_perm_table(graph: nx.DiGraph, user_job_f=job_from_ou, 
                             node_sort_f=sort_by_account):
    cols = ['name', 'job', 'account', 'perm', 'host']
    mapped = ['User Name','Job/Role', 'Account', 'Permission', 'Host']
    return pipe(
        user_computer_perm_data(
            graph, user_job_f=user_job_f, node_sort_f=node_sort_f,
        ),
        markdown.make_table(
            cols, dict(zip(cols, mapped))
        )
    )

@curry
def user_data(graph: nx.DiGraph, user_job_f=job_from_ou, 
               node_sort_f=sort_by_account):
    return pipe(
        graph.nodes(data=True),
        node_sort_f,
        vfilter(lambda i, n: n['type'] == 'User'),
        vmapcat(lambda i, u: [
            {
                'name': u['props'].get('displayname', u['label']), 
                'job': user_job_f(u),
                'account': f"`{u['label'].split('@')[0]}`",
            }
        ]),
    )

def user_table(graph: nx.DiGraph, user_job_f=job_from_ou, 
               node_sort_f=sort_by_account):
    cols = ['name', 'job', 'account']
    mapped = ['User Name','Job/Role', 'Account']
    return pipe(
        user_data(
            graph, user_job_f=job_from_ou, node_sort_f=sort_by_account
        ),
        markdown.make_table(
            cols, dict(zip(cols, mapped))
        ),
    )