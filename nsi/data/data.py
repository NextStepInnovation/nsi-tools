import random
from pathlib import Path

from pkg_resources import resource_filename as _resource_filename

from ..toolz import (
    pipe, curry, compose, memoize, concatv, groupby, take,
    filter, map, strip_comments, sort_by, vmap, get, noop,
)

resource_filename = curry(_resource_filename)(__name__)
path = compose(
    Path,
    resource_filename,
    str,
    lambda p: Path(p),
)


@memoize
def user_agents():
    return path('user-agents.txt').read_text().splitlines()

def random_user_agent():
    return pipe(
        user_agents(),
        random.choice,
    )

@memoize
def nmap_services(path='nmap-services'):
    return pipe(
        Path(path).read_text().splitlines(),
        strip_comments,
        filter(None),
        map(lambda l: l.split('\t')[:3]),
        map(lambda t: tuple(
            concatv(t[:1], t[1].split('/'), map(float, t[-1:]))
        )),
        sort_by(lambda t: t[-1]),
        vmap(lambda name, port, proto, perc: {
            'name': name, 'port': port, 'proto': proto, 'perc': perc,
        }),
        tuple,
    )
    
@curry
def top_ports(n, *, proto='tcp', services_generator=nmap_services,
              just_ports=True):
    '''For a given protocol ('tcp' or 'udp') and a services generator
    (default nmap services file), return the top n ports

    '''
    return pipe(
        services_generator(),
        groupby(lambda d: d['proto']),
        lambda d: d[proto],
        sort_by(get('perc'), reverse=True),
        map(get('port')) if just_ports else noop,
        take(n),
        tuple,
    )

