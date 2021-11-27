import re

from .toolz import pipe, to_str

# ----------------------------------------------------------------------
#
# NTLM/SAM database functions
#
# ----------------------------------------------------------------------

SAM_RE = re.compile(
    r'^(.*?):\d+:(\w+:\w+):::$', re.M,
)
def get_sam_hashes(content):
    return pipe(
        content,
        to_str,
        SAM_RE.findall,
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
