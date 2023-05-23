from pathlib import Path

import lxml.etree
import xmltodict

from ..logging import new_log
from ..toolz import *

log = new_log(__name__)

def get_issue():
    pass

@ensure_paths
def parse(xml_path: Path):
    json_path = xml_path.parent / (xml_path.stem + '.json')
    if json_path.exists() and newer(json_path, xml_path):
        log.info(f'Found JSON cache of {xml_path.name} at {json_path.name}')
        if not newer(xml_path, json_path):
            return pipe(
                json_path,
                slurp,
                json_loads,
            )
        log.info(f'  .. XML is newer than JSON. Reloading XML.')
    log.info(f'Loading Burp Suite XML report at {xml_path}')
    return pipe(
        xml_path,
        slurp,
        xmltodict.parse,
        do(
            lambda d: pipe(
                d,
                json_dumps(indent=2),
                json_path.write_text,
                do(lambda s: log.info(
                    f'  .. wrote JSON cache file {json_path} with'
                    f' size {s / 2**20:.02f}MiB'
                ))
            )
        ),
    )
