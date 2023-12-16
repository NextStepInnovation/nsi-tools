'''HTTP functionality (dirb, nikto, etc.)

'''
import re
import urllib
from typing import Iterable, Callable
from collections import namedtuple

import requests
import bs4

from . import toolz as _
from .shell import getoutput
from . import parallel
from . import yaml
from . import logging
from .toolz import (
    compose, merge, map, pipe, filter, curry, mapcat, juxt, concat,
    do,
)
from . import data
from . import http_content_types

log = logging.new_log(__name__)

def is_apache_page(soup):
    pass

def get_css(soup):
    return pipe(
        soup.find_all(attrs={'type': 'text/css'}),
        map(_.getitem('href')),
        tuple,
    )

@curry
def get_endpoints(base_url, soup):
    return pipe(
        soup.find_all('a', attrs={'href': re.compile('.*')}),
        map(_.getitem('href')),
        map(lambda href: _.url(base_url, href)),
        tuple,
    )

@curry
def url_queries(base_url, soup):
    return pipe(
        get_endpoints(base_url, soup),
        map(urllib.parse.urlparse),
        map(lambda u: (u.path, u.query)),
        _.vmap(lambda p, q: (p, urllib.parse.parse_qs(q))),
        _.vfilter(lambda p, q: q),
        tuple,
    )

@curry
def url_query_vars(base_url, soup):
    return pipe(
        url_queries(base_url, soup),
        _.vmapcat(lambda p, q: q.keys()),
        set,
    )

# def soup(response):
#     return bs4.BeautifulSoup(response.content, 'lxml')

charset_re = re.compile(r'charset=(?P<charset>.*?)\s*', re.I)
Content = namedtuple('Content', ['json', 'soup'])
def response_content(response):
    raw_content_type = response.headers.get('content-type', '')
    content_type = raw_content_type.split(';')[0].lower()
    charset_match = charset_re.search(raw_content_type)
    encoding = 'utf-8'
    if charset_match:
        encoding = charset_match.groupdict()['charset'].lower()
    if http_content_types.is_html(content_type):
        return Content(_.Null, bs4.BeautifulSoup(
            response.content, 'lxml', from_encoding=encoding
        ))
    elif http_content_types.is_json(content_type):
        return Content(_.maybe_json(response), _.Null)
    return Content(_.Null, _.Null)

@curry
def fingerprint(url, *, ssl=None, random_agent=True, **get_kw):
    '''Build a fingerprint for URL based on server technology used,
    path/variable space, etc.

    '''
    if not url.startswith('http'):
        proto = f'http{"s" if ssl else ""}'
        url = f'{proto}://{url}'
    agent = {'User-Agent': data.random_user_agent()} if random_agent else {}
    log.info(f'URL: {url}')
    try:
        response = requests.get(
            url, **merge(
                {'headers': merge(agent),
                 'verify': False},
                get_kw,
            ),
        )
        return (response, response_content(response))
    except (requests.ConnectTimeout, requests.ReadTimeout):
        log.error(f'Timeout on {url}')
        return (_.Null, _.Null)
    except requests.ConnectionError:
        log.error(f'ConnectionError on {url}')
        return (_.Null, _.Null)
    except Exception as exc:
        log.error(f'Error with {url}: {exc}')
        return (_.Null, _.Null)

@curry
def scrape(urls: Iterable[str], *, level=0, max_level=2,
           seen=None, ssl=None, random_agent=True,
           pmap=parallel.thread_map(max_workers=5),
           valid_url_filter: Callable[[str], bool] = lambda url: True,
           gather_f: Callable[[requests.Response, bs4.BeautifulSoup],
                              Iterable] = lambda *a: [],
           state_path: str = 'scrape-state.yml',
           **get_kw):
    seen = set(seen or set())
    log.warning(f'seen: {seen}')
    urls = set(urls) - seen
    log.warning(f'urls: {urls}')
    if seen:
        state = yaml.read_yaml(state_path)
        state['seen'] = pipe(
            set(state['seen']) | seen,
            sorted,
        )
        yaml.write_yaml(state_path, state)
    if urls:
        state = yaml.read_yaml(state_path)
        state['urls'] = sorted(urls)
        yaml.write_yaml(state_path, state)
        
    if urls and level <= max_level:
        content = pipe(
            urls,
            pmap(fingerprint(ssl=ssl, random_agent=random_agent, **get_kw)),
            _.vfilter(lambda r, c: c.soup),
            tuple,
        )
        for value in pipe(content,
                          _.vmap(lambda r, c: gather_f(r, c.soup)),
                          concat):
            yield value

        yield from pipe(
            content,
            _.vmap(lambda r, c: get_endpoints(r.url, c.soup)),
            concat,
            filter(valid_url_filter),
            set,
            scrape(seen=(seen | set(urls)), level=level + 1,
                   ssl=ssl, random_agent=random_agent, pmap=pmap,
                   valid_url_filter=valid_url_filter,
                   gather_f=gather_f, **get_kw),
        )

href_email_re = re.compile(r'^mailto:(?P<email>.*)$')
email_re = re.compile(r'''(?P<email>(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\]))''')

def get_emails(soup):
    return pipe(
        soup.find_all('a', attrs={'href': href_email_re}),
        mapcat(lambda e: [e['href'], e.text.strip()]),
        _.groupdicts(email_re),
        map(lambda d: d['email']),
        set,
    )
        
scrape_email = scrape(
    gather_f=lambda r, s: get_emails(s),
)

dirb_regexes = [
    re.compile(
        r'\+ (?P<url>http[s]?://.*?)\s+\(CODE:(?P<code>\d+)\|'
        r'SIZE:(?P<size>\d+)\)'
    ),
    re.compile(
        r'==> DIRECTORY: (?P<url>http[s]?://.*)$'
    ),
]
DIRB_TIMEOUT = (2 * 60)
DIRB_PORT = 80

def get_ssl_port(ssl, no_ssl, port):
    match (ssl, no_ssl, port):
        case (False, False, None):
            return False, 80
        case (True, False, None):
            return True, 443
        case (True, False, 80):
            return True, 80
        case (_1, True, 443):
            return False, 443
        case (False, _2, 443):
            return True, 443
        case (_1, _2, None):
            return False, 80
    if not port:
        raise AttributeError(
            f'Invalid port: {port} (ssl: {ssl}) (no_ssl: {no_ssl})'
        )
    return ssl, port

@curry
def dirb(host: str, port: int, ssl: bool, *, timeout=DIRB_TIMEOUT,
         path: str = None,
         getoutput=getoutput, dry_run=False):
    if not host.startswith('http'):
        proto = f'http{"s" if ssl else ""}'
        url = f'{proto}://{host}'
    else:
        url = host

    if port not in {80, 443}:
        url = f'{url}:{port}'

    agent = data.random_user_agent()
    command = f'dirb {url} -S -a "{agent}"'

    log.info(f'[dirb] command: {command}')
    if dry_run:
        log.warning('DRY RUN: not running command')
        output = ''
    else:
        output = getoutput(command, timeout=timeout)
    
    return (output, pipe(
        output.splitlines(),
        juxt(*[compose(list, _.groupdicts(r)) for r in dirb_regexes]),
        concat,
        # mapcat(juxt(*[_.groupdicts(r) for r in dirb_regexes])),
        tuple,
    ))


nikto_regexes = [
    re.compile(
        r'\+ (?P<interesting>.*?interesting.*?)'
    ),
]
NIKTO_TIMEOUT = (5 * 60)
NIKTO_PORT = 80

@curry
def nikto(host: str, port: int, ssl: bool, *, 
          path: str = None, timeout=NIKTO_TIMEOUT,
          getoutput=getoutput, dry_run: bool = False):
    if not host.startswith('http'):
        proto = f'http{"s" if ssl else ""}'
        url = f'{proto}://{host}'
    else:
        url = host

    if port not in {80, 443}:
        url = f'{url}:{port}'

    agent = data.random_user_agent()
    command = f"nikto -nointeractive -useragent '{agent}' -host {url}"
    if path is not None:
        command = f'{command} -root "{path}"'

    log.info(f'[nikto] command: {command}')
    if dry_run:
        log.warning('DRY RUN not running command')
        output = ''
    else:
        output = getoutput(command, timeout=timeout)
    
    return (output, pipe(
        output.splitlines(),
        juxt(*[compose(list, _.groupdicts(r)) for r in nikto_regexes]),
        concat,
        # mapcat(juxt(*[_.groupdicts(r) for r in nikto_regexes])),
        tuple,
    ))


