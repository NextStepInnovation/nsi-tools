from pathlib import Path

from .. import logging
from ..toolz import *

log = logging.new_log(__name__)

@ensure_paths
def parse_smb_shares_data(path: Path):
    '''Parse the data outputted by nsi-smb-shares
    '''
    return pipe(
        path,
        slurplines,
        map(split('\t')),
        vmap(lambda share, type, desc, access: {
            'share': share,
            'type': type,
            'description': desc,
            'access': set(access.split(', ')),
        }),
        map(lambda d: merge(d, {
            'ip': d['share'].split('/')[2],
            'name': d['share'].split('/')[3],
            'access': (d['access']|{'WRITE'} 
                       if ('WRITE-FILE' in d['access'] or
                           'WRITE-DIR' in d['access']) else d['access']),
        })),
        map(lambda d: merge(d, {
            'readable': 'READ' in d['access'],
            'writable': 'WRITE' in d['access'],
            'not_print': d['name'].lower() != 'print$',
        })),
        tuple,
    )

