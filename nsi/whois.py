from pathlib import Path
import re

from . import toolz as _
from . import logging
from . import shell

log = logging.new_log(__name__)

kv_re = re.compile(r'^(?P<key>\w+):\s+(?P<value>.*)', re.M)

def chunk_output(output):
    return _.pipe(
        output.split('\n\n'),
        _.map(_.strip),
        _.filter(None),
        tuple,
    )

# def regex_chunk(chunk):
#     match = _.pipe(
#         [chunk],
#         _.groupdicts_from_regexes(regexes, flags=re.M),
#         _.merge,
#     )
#     if match:
#         return match

def from_camel(k):
    def camel(k):
        for c in k:
            if c.isupper():
                yield f'_{c.lower()}'
            else:
                yield c
    return _.pipe(
        camel(k),
        _.drop(1),
        ''.join,
    )

def regex_chunk(chunk):
    def match_gen():
        for match in kv_re.finditer(chunk):
            d = match.groupdict()
            yield (d['key'], d['value'])
    return _.pipe(
        match_gen(),
        dict,
    )

def strip_comments(content):
    return _.pipe(
        content.splitlines(),
        _.strip_comments,
        '\n'.join,
    )

def whois(ip):
    log.info(f'Doing whois lookup for {ip}')
    command = f'''
    whois {ip}
    '''.strip()

    return _.pipe(
        shell.getoutput(
            command, echo=False
        ),
        strip_comments,
        chunk_output,
        _.map(regex_chunk),
        tuple,
    ) 

