#!/usr/bin/env python3
import re

from ..toolz import (
    pipe, vfilter, vmap,
)

# [+] IP: 172.16.3.251:445	Name: 172.16.3.251
finding_re = re.compile(
    r'^\[\+\]\s+IP:\s+(?P<ip>\d+\.\d+\.\d+\.\d+):'
    r'\d+\s+Name:\s+(?P<name>\S+)\s*$'
)

def get_finding_headers(lines):
    return pipe(
        lines,
        enumerate,
        vmap(lambda i, line: (i, finding_re.search(line))),
        vfilter(lambda i, match: match),
        vmap(lambda i, match: (i, match.groupdict())),
        vmap(lambda i, d: (i, (d['ip'], d['name']))),
        tuple,
    )

line_re = re.compile(r'^\s(.*?)\s+(.*)$')

def get_findings(path):
    data = path.read_text()
    all_lines = data.splitlines()
    headers = get_finding_headers(all_lines)
    for i in range(len(headers) - 1):
        start, (ip, name) = headers[i]
        end = headers[i + 1][0]
        lines = all_lines[start + 1: end]
        for line in pipe(lines[2:], filter(line_re.match)):
            disk, perm = line_re.match(line).groups()
            yield ip, name, disk, perm

def print_findings(path):
    for ip, name, disk, perm in get_findings(path):
        print(f'{ip}\t{name}\t{disk}\t{perm}')

