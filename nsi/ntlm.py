from pathlib import Path
import re
import typing as T

from . import logging
from .toolz import *

log = logging.new_log(__name__)

# ----------------------------------------------------------------------
#
# NTLM/SAM database functions
#
# ----------------------------------------------------------------------

ntlm_re = re.compile(
    r'(?P<ntlm>\w{32}:\w{32})', 
)
ntlm_all_re = re.compile(
    r'(?:(?P<domain>\S+?)\\)?(?P<user>\S+):(?P<sid>\d+):(?P<lm>\w{32}):(?P<nt>\w{32})', 
)
# ntlm_domain_re = re.compile(
#     r'(?P<user>\w+):(?P<sid>\d+):(?P<lm>\w{32}):(?P<nt>\w{32})', 
# )
dcc2_re = re.compile(
    r'(?P<domain>\S+?)/(?P<user>\S+):(?P<dcc2>\$DCC2\$\d+#\S+#\w{32})'
)

def parse_ntlm_from_lines(lines: T.Iterable[str]):
    return pipe(
        lines,
        map(ntlm_re.search),
        filter(None),
        map(lambda m: m.groupdict()),
    )

parse_ntlm_from_content = compose_left(
    to_str,
    splitlines,
    parse_ntlm_from_lines,
)

@curry
def filter_binary(do_binary: bool, path: Path):
    if do_binary:
        return True

    if is_binary(path):
        log.info(
            f'Skipping binary file {path}'
        )
        return False
    return True

@curry
@ensure_paths
def parse_ntlm_from_path(root: Path, *, do_binary=False, max_size=5 * 2**20):
    def get_paths(path: Path):
        if path.is_dir():
            for p in walk(path):
                yield from get_paths(p)
        elif path.is_file():
            yield path

    return pipe(
        root,
        walk,
        filter(lambda path: path.stat().st_size < max_size),
        filter(filter_binary(do_binary)),
        map(slurp),
        mapcat(parse_ntlm_from_content),
    )


sam_re = re.compile(
    r'^\s*(?:(?P<domain>.*?)\\)?(?P<user>.*?):(?P<sid>\d+):(?P<ntlm>\w{32}:\w{32}):::\s*$', 
    re.M,
)

def parse_sam_from_lines(lines: T.Iterable[str]):
    return pipe(
        lines,
        groupdicts(sam_re),
        map(lambda d: merge(d, {
            'full_user': f"{d.get('domain', '.') or '.'}/{d['user']}",
        })),
    )

parse_sam_from_content = compose_left(
    to_str,
    splitlines,
    parse_sam_from_lines,
)
get_sam_hashes = parse_sam_from_content

@ensure_paths
def parse_sam_from_path(path: Path):
    content = slurp(path)
    ip = get_ip(path)
    return pipe(
        content,
        parse_sam_from_content,
        map(lambda d: merge(
            d, {'ip': ip}
        )),
    )
    
@ensure_paths(resolve=True)
def get_ip(p: Path):
    return maybe(ip_relaxed_re.search(str(p))).group(0) or ''
    return pipe(
        str(p),
        ip_relaxed_re.search,
        filter(None),
        maybe_first,
    ).group(0) or ''

@ensure_paths
def parse_ip_and_sam_from_path(root: Path, *, do_binary=False, max_size=2**20):
    return pipe(
        root,
        walk,
        vfilter(lambda ip, path: path.stat().st_size < max_size),
        filter(filter_binary(do_binary)),
        map(lambda p: (get_ip(p), p)),
        vmapcat(lambda ip, p: pipe(
            p,
            parse_sam_from_path,
            map(lambda d: pipe(d, valfilter(is_some))),
            map(lambda d: (ip, d)),
        )),
    )

MSCACHE_RE = re.compile(
    r'^(.+?)/(.+?):(\$.*?\$.*?#.*?#.*?)$', re.M,
)
def get_mscache_hashes(content):
    return pipe(
        content,
        to_str,
        MSCACHE_RE.findall,
    )
