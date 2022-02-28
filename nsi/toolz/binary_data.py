# -*- coding: utf-8 -*-
from pathlib import Path
import io
import gzip
import string
import typing as T

import chardet
import charset_normalizer

from .common import (
    pipe, map, filter, curry,
)
from .filesystem import ensure_paths
from .. import logging


log = logging.new_log(__name__)


_control_chars = b'\n\r\t\f\b'
_printable_ascii = _control_chars + bytes(range(32, 127))
_printable_high_ascii = bytes(range(127, 256))

NULL_RATIO = 0.01

def get_starting_chunk(filename, length=1024):
    """
    :param filename: File to open and get the first little chunk of.
    :param length: Number of bytes to read, default 1024.
    :returns: Starting chunk of bytes.
    """
    # Ensure we open the file in binary mode
    try:
        with open(filename, 'rb') as f:
            chunk = f.read(length)
            return chunk
    except IOError as e:
        print(e)

def is_gzip(content: bytes):
    result = True
    with gzip.open(io.BytesIO(content)) as gzfp:
        try:
            gzfp.read()
        except gzip.BadGzipFile:
            result = False
        except:
            pass
    return result

@curry
def strings(path: T.Union[Path, bytes], min=4):
    def strings_iter(fp: T.IO):
        result = ""
        for c in fp.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:  # catch result at EOF
            yield result
    match path:
        case data if type(path) is bytes:
            yield from strings_iter(io.BytesIO(data))
        case path:
            with Path(path).expanduser().open(errors="ignore") as fp:
                yield from strings_iter(fp)

def get_string_content(path: Path, min=4):
    return pipe(
        path,
        strings(min=min),
        '\n'.join,
    )

@ensure_paths
def detect_encoding(path: Path):
    return pipe(
        path,
        get_starting_chunk,
        charset_normalizer.detect,
    )

@curry
def is_binary_string(bytes_to_check, *, null_ratio=NULL_RATIO):
    """
    Uses a simplified version of the Perl detection algorithm,
    based roughly on Eli Bendersky's translation to Python:
    http://eli.thegreenplace.net/2011/10/19/perls-guess-if-file-is-text-or-binary-implemented-in-python/

    This is biased slightly more in favour of deeming files as text
    files than the Perl algorithm, since all ASCII compatible character
    sets are accepted as text, not just utf-8.

    :param bytes: A chunk of bytes to check.
    :param null_ratio: Percentage of \x00/\xff that is acceptable
    :returns: True if appears to be a binary, otherwise False.
    """

    # Empty files are considered text files
    if not bytes_to_check:
        return False

    # Now check for a high percentage of ASCII control characters
    # Binary if control chars are > 30% of the string
    low_chars = bytes_to_check.translate(None, _printable_ascii)
    nontext_ratio1 = float(len(low_chars)) / float(len(bytes_to_check))
    log.debug('nontext_ratio1: %(nontext_ratio1)r', locals())

    # and check for a low percentage of high ASCII characters:
    # Binary if high ASCII chars are < 5% of the string
    # From: https://en.wikipedia.org/wiki/UTF-8
    # If the bytes are random, the chances of a byte with the high bit set
    # starting a valid UTF-8 character is only 6.64%. The chances of finding 7
    # of these without finding an invalid sequence is actually lower than the
    # chance of the first three bytes randomly being the UTF-8 BOM.

    high_chars = bytes_to_check.translate(None, _printable_high_ascii)
    nontext_ratio2 = float(len(high_chars)) / float(len(bytes_to_check))
    log.debug('nontext_ratio2: %(nontext_ratio2)r', locals())

    if nontext_ratio1 > 0.90 and nontext_ratio2 > 0.90:
        return True

    if is_gzip(bytes_to_check):
        log.debug('detected gzip file')
        return True

    is_likely_binary = (
        (nontext_ratio1 > 0.3 and nontext_ratio2 < 0.05) or
        (nontext_ratio1 > 0.8 and nontext_ratio2 > 0.8)
    )
    log.debug('is_likely_binary: %(is_likely_binary)r', locals())

    # then check for binary for possible encoding detection with chardet
    log.debug('checking encoding...')
    encoding = chardet.detect(bytes_to_check)
    log.debug(f'encoding: {encoding}')

    ascii_detected = False
    no_encoding = False
    match encoding:
        case {'confidence': 1.0, 'encoding': 'ascii'}:
            # if it's 100% decodable as ASCII, then it's not binary
            return False
        case {'encoding': 'ascii'}:
            ascii_detected = True
        case {'encoding': None, 'confidence': 0}:
            no_encoding = True

    if no_encoding:
        log.debug(
            'no encoding found'
        )
        return True

    # finally use all the check to decide binary or text
    decodable_as_unicode = False
    match encoding, ascii_detected:
        case {'confidence': conf}, False if conf > 0.9:
            try:
                bytes_to_check.decode(encoding=encoding['encoding'])
                decodable_as_unicode = True
            except LookupError:
                log.debug('failure: could not look up encoding %(encoding)s',
                            encoding)
            except UnicodeDecodeError:
                log.debug('failure: decodable_as_unicode: '
                            '%(decodable_as_unicode)r', locals())

    log.debug(
        f'decodable_as_unicode: {decodable_as_unicode}'
    )
    if decodable_as_unicode:
        return False

    if is_likely_binary:
        return True

    has_nulls = b'\x00' in bytes_to_check
    has_max = b'\xff' in bytes_to_check
    if has_nulls or has_max:
        log.debug(
            f'NULL bytes detected: {has_nulls}'
        )
        log.debug(
            f'MAX bytes detected: {has_max}'
        )
        return True

    return False

@curry
def is_binary(filename, *, null_ratio=NULL_RATIO):
    """
    :param filename: File to check.
    :returns: True if it's a binary file, otherwise False.
    """
    log.debug('is_binary: %(filename)r', locals())

    # Check if the file extension is in a list of known binary types
#     binary_extensions = ['.pyc', ]
#     for ext in binary_extensions:
#         if filename.endswith(ext):
#             return True

    # Check if the starting chunk is a binary string
    chunk = get_starting_chunk(filename)
    return is_binary_string(chunk)
