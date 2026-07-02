import typing as T
from pathlib import Path
import json

from scapy.layers.l2 import Ether
from scapy.sendrecv import sniff

import zmq

from ..toolz import (
    json_dumps, pipe, curry, new_log, to_bytes, pformat,
)

from .common import Message

log = new_log(__name__)
context = zmq.Context()

@curry
def handle_frame(socket: zmq.Socket, frame: Ether):
    message = Message.from_frame(frame)
    json_dict = message.to_json()
    log.debug('Message sent')
    socket.send_string(f'mnr-{message.mnr.type}', flags=zmq.SNDMORE)
    try:
        json.dumps(json_dict)
    except:
        log.exception(pformat(json_dict))
    socket.send_json(json_dict)

def serve_mnr_listener():
    pub_socket = context.socket(zmq.PUB)
    pub_socket.bind('tcp://localhost:42042')
    sniff(
        filter='udp port 5353 or 5355 or 137', 
        prn=handle_frame(pub_socket),
        store=False,
    )

def serve_mnr_responder(prefix: str|bytes = b'mnr') -> T.Generator[Message]:
    with context.socket(zmq.SUB) as sub_socket:
        sub_socket.connect(
            'tcp://localhost:42042'
        )
        sub_socket.setsockopt(zmq.SUBSCRIBE, to_bytes(prefix))
        while True:
            mnr_type, mnr_data = sub_socket.recv_string(), sub_socket.recv_json()
            yield pipe(
                mnr_data,
                Message.from_json,
            )
