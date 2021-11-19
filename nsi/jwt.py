'''JSON Web Token tools

'''
import json

from .toolz import (
    pipe, map, b64encode, b64decode, to_str, call
)

def jwt_parts(content):
    return pipe(
        content,
        to_str,
        call('split', '.'),
        map(b64decode),
        tuple,
    )

def jwt_token_from_obj(header, data, sig):
    return jwt_token(json.dumps(header), json.dumps(data), sig)

def jwt_token(header, data, sig):
    return pipe(
        [header, data, sig],
        map(b64encode),
        map(call('replace', b'=', b'')),
        b'.'.join,
    )
