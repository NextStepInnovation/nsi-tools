from pathlib import Path

from scapy.all import *

from .toolz import *


def get_pcap(path: Path):
    return pipe(
        path,
        str,
        rdpcap,
    )

