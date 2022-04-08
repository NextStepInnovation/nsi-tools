from pathlib import Path
from functools import partial

import requests

from ..toolz import *
from ..toolz.html import soup_from_url
from ..parallel import thread_map

BASE = 'https://cirt.net'

def passwords_url(vendor_qs: str = ''):
    return f'{BASE}/passwords' + vendor_qs

passwords_soup = compose_left(passwords_url, soup_from_url)

def get_vendors():
    for tr in passwords_soup().find_all('tr'):
        for td in tr.find_all('td'):
            for a in td.find_all('a'):
                yield (a.text, a['href'])

def transform_key(k: str):
    return k.lower().replace(' ', '_')

def transform_value(v: str):
    match v:
        case '(none)':
            return None
    return v

@curry
def vendor_passwords(vendor: str, path: str):
    for table in passwords_soup(path).find_all('table'):
        trs = table.find_all('tr')
        header = trs[0].find('h3').text
        _vendor, model = header.split('\xa0')[1].split(' - ')
        yield merge(
            {'vendor': vendor, 'model': model},
            pipe(
                trs[1:],
                map(lambda tr: tr.find_all('td')),
                vmap(lambda k, v: (
                    transform_key(k.text), 
                    transform_value(v.text)
                )),
                dict,
            )
        )

def all_passwords():
    return pipe(
        get_vendors(),
        filter(first),
        # take(10),
        thread_map(vcall(lambda v, p: pipe(
            vendor_passwords(v, p), tuple,
        ))),
        concat,
        tuple,
    )
