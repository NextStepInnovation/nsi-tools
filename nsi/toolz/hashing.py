from pathlib import Path
import hashlib
import base64
import binascii
from collections.abc import Callable as Function
from typing import Union, Callable

from multipledispatch import dispatch

from .common import (
    curry, is_str, pipe, to_bytes, to_str, compose_left, call,
)

__all__ = [
    # hashing
    'b64decode', 'b64decode_str', 'b64encode', 'b64encode_str', 'hash', 'md5',
    'sha1', 'sha256', 'sha512', 'nt',
]

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

def hash_content(hasher: Callable):
    def do_hash(content: Union[str, bytes]):
        if is_str(content):
            content = content.encode()
        return pipe(
            content,
            hasher,
            lambda h: h.hexdigest(),
        )
    return do_hash

def nt(content: str):
    return pipe(
        hashlib.new(
            'md4', content.encode('utf-16le')
        ).hexdigest(),
    )

md5 = hash_content(hashlib.md5)
sha1 = hash_content(hashlib.sha1)
sha256 = hash_content(hashlib.sha256)
sha512 = hash_content(hashlib.sha512)

