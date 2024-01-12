from pathlib import Path
import re
import typing as T
from ipaddress import ip_address

from ..toolz import *

'''
03/08/2022 07:59:51 AM - [*] [NBT-NS] Poisoned answer sent to ::ffff:10.240.12.52 for name WORKGROUP (service: Local Master Browser)
"03/07/2022 10:55:06 AM - Responder Started: ['./Responder.py', '-I', 'eth0', '-w']"
'''



class QueryDict(T.TypedDict):
    ts: str
    proto: str
    raw_ip: str
    query: str
    service: str
    ip: str

QueryList = T.Sequence[QueryDict]

def enrich_query(query: QueryDict):
    return merge(
        query,
        {'ip': to_ipv4(query['raw_ip'])},
        # {'dt': to_dt(query['ts'])},
        {'query': pipe(query['query'], replace('\u0005', ''))},
    )
    
start_time_re = re.compile(
    r'^(?P<ts>\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d \w\w)\s+-'
    r'\s+Responder Started: (?P<args>\[.*?\])'
)
query_re = re.compile(
    r'^(?P<ts>\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d \w\w)\s+-\s+\[\*\]'
    r'\s+\[(?P<proto>.*?)\]'
    r'\s+Poisoned answer sent to'
    r'\s+(?P<raw_ip>.*?)'
    r'\s+for name'
    r'\s+(?P<query>\S*)'
    r'\s*(\(service: (?P<service>.*?)\))?$', re.I | re.MULTILINE
)
skip_re = re.compile(
    r'^(?P<ts>\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d \w\w)\s+-\s+\[\*\]'
    r'\s+Skipping previously captured hash for (?P<account>.*)$',
    re.I | re.MULTILINE
)
hash_data_re = re.compile(
    r'^(?P<ts>\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d \w\w)\s+-'
    r'\s+\[(?P<proto>.*?)\]'
    r'\s+(?P<ntlm_version>NTLMv\d+)'
    r'\s+(?P<key>.*?)\s+:'
    r'\s+(?P<value>.*)$', re.I | re.MULTILINE
)

def dict_from_line(line: str):
    search = pipe((
        ('start_time', start_time_re),
        ('query', query_re),
        ('skip', skip_re),
        ('hash_data', hash_data_re),
    ), vmap(lambda t, r: (t, groupdict(r))))
    for type, gd_f in search:
        gd = gd_f(line)
        if gd:
            if type == 'query':
                gd = enrich_query(gd)
            return merge(gd, {
                'responder_type': type,
            })

query_from_line = compose_left(
    groupdict(query_re),
    lambda q: enrich_query(q) if q else {},
)

queries_from_lines = compose_left(
    groupdicts_from_regexes([query_re], keep_match=True),
    map(enrich_query),
)

# def queries_from_lines(lines: T.Iterable[str]):
#     return pipe(
#         lines,
#         map(groupdict(query_re)),
#         filter(None),
#         map(enrich_query),
#     )

def queries_from_content(content: str) -> QueryList:
    return pipe(
        content,
        query_re.finditer,
        map(lambda m: m.groupdict()),
        map(enrich_query),
    )

# queries_from_content = compose_left(
#     splitlines, queries_from_lines,
# )

queries_from_path: T.Callable[[Path], QueryList] = compose_left(
    slurp, 
    queries_from_content,
)
    
def queries_to_table(queries: QueryList):
    return pipe(
        queries,
        groupby('ip'),
        valmap(groupby('query')),
        valmap(valmap(lambda dicts: pipe(
            dicts,
            map(get('proto')),
            set,
            sorted,
            lambda t: html_list(t) if len(t) > 1 else t[0],
        ))),
        valmap(lambda d: pipe(
            d.items(),
            sorted,
        )),
        items,
        vmapcat(lambda ip, queries: [
            (ip, query, proto) for query, proto in queries
        ]),
        sort_by(lambda t: int(ip_address(t[0]))),
        vmap(lambda ip, query, proto: (
            f'| `{ip}` | `{query}` | {proto} |'
        )),
        '\n'.join
    )

def query_table_from_path(path: Path):
    return pipe(
        path,
        queries_from_path,
        queries_to_table,
    )