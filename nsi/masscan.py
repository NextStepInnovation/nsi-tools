'''masscan functionality


'''
from pathlib import Path
# from subprocess import getoutput
import shlex
import re
from datetime import datetime

from .toolz import (
    pipe, curry, map, filter, groupby, valmap,
    vmap, strip_comments, is_seq, is_int, noop,
    do, slurp, to_regex,
)
from . import toolz as _
from .shell import getoutput
from . import data
from . import logging

log = logging.new_log(__name__)


mscan_gnmap_re = to_regex(
    r'Timestamp:\s+(?P<ts>\d+)\s+'
    r'Host:\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\((?P<name>.*?)\)\s+'
    r'Ports:\s+(?P<port>\d+)/'
    r'(?P<state>\w*?)/'
    r'(?P<proto>\w*?)/'
    r'(?P<v0>.*?)/'
    r'(?P<guess>\w.*?)/'
    r'(?P<v1>.*?)/(?P<v2>.*?)',
    re.M,
)

def is_gnmap(path: Path):
    return pipe(
        path,
        slurp,
        mscan_gnmap_re.search,
        bool,
    )

def parse_gnmap(path: Path):
    return pipe(
        path, 
        _.slurplines, 
        _.groupdicts(mscan_gnmap_re),
        _.groupby('ip'),
        _.valmap(lambda dicts: _.merge(
            {'ip': dicts[0]['ip'], 'name': dicts[0]['name']},
            {'ports': pipe(
                dicts,
                map(_.remove_keys(['ip', 'name'])), 
                map(lambda d: _.merge(
                    {'service': ''}, d, {
                        'port': int(d['port']),
                    },
                )),
                tuple,
            )},
        )),
        _.values,
        _.map(_.cmerge({'ip': '', 'name': '', 'ports': []})),
    )


@curry
def masscan(ip_or_range_or_path, *, ports=None, getoutput=getoutput,
            wait=0, rate=1000, banner=False, udp=False):
    '''Construct a masscan command and run, returning
    '''
    if Path(ip_or_range_or_path).exists():
        ip_list = pipe(
            Path(ip_or_range_or_path).read_text().split_lines(),
            strip_comments,
        )
    elif is_seq(ip_or_range_or_path):
        ip_list = pipe(
            ip_or_range_or_path,
            strip_comments,
        )
    else:
        ip_list = [ip_or_range_or_path]

    iprange = pipe(
        ip_list,
        ' '.join,
        lambda s: f'--range {s}',
    )

    if ports:
        if is_seq(ports):
            ports = pipe(ports, map(str), tuple)
        elif is_int(ports) or ports.isdigit():
            ports = data.top_ports(int(ports), proto='udp' if udp else 'tcp')
    else:
        ports = data.top_ports(1000, proto='udp' if udp else 'tcp')
    ports = pipe(
        ports,
        map(str),
        map(lambda p: f'U:{p}') if udp else noop,
        ','.join,
    )

    wait = f'--wait {wait}'
    rate = f'--rate {rate}'
    banner = '--banner' if banner else ''
    ports = f'-p {ports}'
        
    command = pipe(
        f'sudo masscan {iprange} {ports} {wait} {rate} -oL -',
        shlex.split,
        ' '.join,
    )
    log.info(
        command if len(command) < 500
        else command[:300] + ' [...] ' + command[-200:]
    )
    output = getoutput(command)

    return pipe(
        output,
        lambda d: d.splitlines(),
        strip_comments,
        # do(cprint(lambda v: '\n'.join(v))),
        map(lambda s: s.split()),
        filter(lambda t: t and t[0] == 'open'),
        vmap(lambda status, proto, port, ip, ts: {
            'status': status,
            'proto': proto,
            'port': int(port),
            'ip': ip,
            'dt': datetime.fromtimestamp(int(ts)),
        }),
        groupby(lambda d: d['ip']),
        # valmap(compose(tuple, map(lambda d: d['port']))),
    )

masscan_http = masscan(ports=[80, 443, 8080, 8443])
masscan_ssh = masscan(ports=[22, 2222])
