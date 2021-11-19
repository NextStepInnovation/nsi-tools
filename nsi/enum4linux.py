#!/usr/bin/env python3
from pathlib import Path
import re
import csv
import random

from .toolz import (
    pipe, concat, filter, map, mapcat, groupby,
)

user_re = re.compile(
    r'^user:\[(.*?)\]\s+rid:\[(.*?)\]\s*$', re.M,
)

account_re = re.compile(
    r"^.*?Account:\s([\w.\s]+?)Name:\s([\w.'\s]+?)Desc:.*$"
)

group_re = re.compile(
    r"^Group\s'(.+?)'\s\(RID:\s\d+\) has member: .*?\\([\w.'\s]+?)$"
)

def get_group_lut(lines):
    return pipe(
        lines,
        filter(group_re.search),
        mapcat(group_re.findall),
        groupby(lambda t: t[0]),
        lambda d: d.items(),
        map(lambda t: (t[0], [v[1] for v in t[1]])),
        dict,
    )

def get_users(lines):
    return pipe(
        lines,
        filter(account_re.search),
        map(account_re.match),
        map(lambda m: m.groups()),
        map(lambda t: [s.strip() for s in t]),
        tuple,
    )

def get_user_info(lines, groups):
    glut = get_group_lut(lines)

    valid_users = pipe(
        groups,
        map(glut.get),
        filter(None),
        concat,
        set,
    )

    for uname, name in get_users(lines):
        if uname in valid_users:
            parts = name.split()
            if len(parts) >= 2:
                first, last = parts[0], parts[-1]
                yield f'{uname}@mdek12.org', first, last

def user_info_csv():
    lines = Path('e4l.txt').read_text().splitlines()
    groups = [
        '$CHS', '$MIS', '$SCHOOL ATTENDANCE OFFICERS',
        '$EIR', '$SD&B', '$GMNT'
    ]

    N = 300
    users = pipe(
        get_user_info(lines, groups),
        list,
        lambda u: random.sample(u, N),
        sorted,
    )

    columns = ['email_address', 'first_name', 'last_name']
    with Path('users.csv').open('w') as rfp:
        writer = csv.writer(rfp)
        writer.writerow(columns)
        writer.writerows(users)

if __name__ == '__main__':
    user_info_csv()
