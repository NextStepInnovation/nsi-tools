import re
import typing as T
import pprint

from . import toolz as _
from . import logging
from . import shell
from . import parallel

log = logging.new_log(__name__)

host_regexes = [
    re.compile(
        r'^(?P<revip>\d+\.\d+\.\d+\.\d+)\.in-addr\.arpa domain name'
        r' pointer (?P<name>\S+?)\.$'
    ),
    re.compile(
        fr'^(?P<name>\S+?) has address (?P<ip>\d+\.\d+\.\d+\.\d+)$'
    ),
]

def revip_to_ip(revip):
    return _.pipe(
        revip.split('.'),
        reversed,
        '.'.join
    )

@_.curry
def resolve_host(ip, *, dns_server=None,
                 getoutput=shell.getoutput):
    def get_ip(d):
        if 'revip' in d:
            return _.replace_key(
                'revip', 'ip', lambda d: revip_to_ip(d['revip']), d
            )
        return d
    server = f' {dns_server}' if dns_server else ''
    command = f'host {ip}{server}'
    log.debug(f'Command: {command}')
    return _.pipe(
        getoutput(command).splitlines(),
        _.groupdicts_from_regexes(host_regexes, keep_match=True),
        _.map(get_ip),
    )

@_.curry
def resolve_hosts(hosts: T.Iterable[str], *,
                  dns_server: T.Optional[str]=None,
                  getoutput=shell.getoutput, max_workers=5):
    return _.pipe(
        hosts,
        parallel.thread_map(
            resolve_host(getoutput=getoutput, dns_server=dns_server), 
            max_workers=max_workers
        ),
        _.concat,
        tuple,
    )

def sort_dns_hostnames(hostnames):
    return _.pipe(
        hostnames,
        _.sort_by(lambda d: _.ip_tuple(d['ip'])),
    )

