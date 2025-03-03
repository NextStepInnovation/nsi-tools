import logging

import bs4
import requests

__all__ = [
    # html
    'soup', 'soup_from_url',
]

from .common import pipe, curry
from .text_processing import clip_text

# ----------------------------------------------------------------------
#
# HTML handling functions
#
# ----------------------------------------------------------------------

@curry
def soup(content: str, **kw):
    if 'features' not in kw:
        kw['features'] = 'lxml'
    return bs4.BeautifulSoup(content, **kw)

def soup_from_url(url: str, soup_kw: dict = None, **requests_kw):
    try:
        match requests.get(url, **requests_kw):
            case requests.Response(status_code=200) as r_200:
                return pipe(
                    r_200.content,
                    soup(**(soup_kw or {})),
                )
            case error:
                content = clip_text(100, error.text)
                logging.error(
                    f'Got a response with code: {error.status_code} and'
                    f' content: {content}'
                )
    except KeyboardInterrupt:
        raise
    except:
        logging.exception(
            f'--EXCEPTION-- Problem loading URL {url} with kwargs: {requests_kw}'
        )
