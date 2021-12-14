from pathlib import Path
import re
import typing as T

from .toolz import *

# ----------------------------------------------------------------------
#
# NTLM/SAM database functions
#
# ----------------------------------------------------------------------

sam_re = re.compile(
    r'^\s*(?P<name>.*?):(?P<sid>\d+):(?P<ntlm>\w+:\w+):::\s*$', 
)

def parse_sam_from_lines(lines: T.Iterable[str]):
    return pipe(
        lines,
        groupdicts(sam_re),
    )

parse_sam_from_content = compose_left(
    to_str,
    splitlines,
    parse_sam_from_lines,
)
get_sam_hashes = parse_sam_from_content

parse_sam_from_path = compose_left(
    slurp,
    parse_sam_from_content,
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
