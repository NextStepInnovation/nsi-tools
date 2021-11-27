from pathlib import Path
import hashlib
import base64
from typing import Union

from .common import (
    curry, pipe,
    to_bytes, to_str, compose_left, 
)

# ----------------------------------------------------------------------
#
# Hashing and encoding functions
#
# ----------------------------------------------------------------------

def b64decode(content: Union[bytes, str]):
    return base64.b64decode(
        to_bytes(content) + b'=' * (len(content) % 4)
    )
b64decode_str = compose_left(b64decode, to_str)

def b64encode(content: Union[bytes, str]):
    return pipe(
        content,
        to_bytes,
        base64.b64encode,
    )
b64encode_str = compose_left(b64encode, to_str)

@curry
def hash(path: Union[str, Path], hash_func=hashlib.sha256):
    hash_obj = hash_func()
    with Path(path).expanduser().open('rb') as rfp:
        for chunk in iter(lambda: rfp.read(4096), b''):
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

