import urllib
from typing import Tuple

import requests
from pymaybe import Nothing

from .common import pipe
# ----------------------------------------------------------------------
#
# HTTP functions
#
# ----------------------------------------------------------------------

def url(*parts):
    base, *path = pipe(parts, map(str))
    return urllib.parse.urljoin(
        base, '/'.join(path),
        # base, Path(*path).as_posix(),
    )

def session_with_cookies(cookies: Tuple[dict]=None):
    cookies = cookies or [{}]
    session = requests.Session()
    for cookie_dict in cookies:
        session.cookies.set_cookie(
            requests.cookies.create_cookie(**cookie_dict)
        )
    return session

def valid_response(response: requests.Response):
    return response.status_code in range(200, 300)

def valid_content(response: requests.Response):
    return response.content if valid_response(response) else Nothing()
    