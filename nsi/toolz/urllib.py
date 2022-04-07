'''Curried versions of useful urllib functions
'''
import urllib.parse

from .common import curry, pipe, map, filter

urlencode = curry(urllib.parse.urlencode)
urlparse = curry(urllib.parse.urlparse)
urlsplit = curry(urllib.parse.urlsplit)
urlunparse = urllib.parse.urlunparse
urlunsplit = urllib.parse.urlunsplit
urljoin = curry(urllib.parse.urljoin)
parse_qs = curry(urllib.parse.parse_qs)
parse_qsl = curry(urllib.parse.parse_qsl)
