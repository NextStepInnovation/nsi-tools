from .common import pipe
import bs4
import requests

# ----------------------------------------------------------------------
#
# HTML handling functions
#
# ----------------------------------------------------------------------

def soup(content: str):
    return bs4.BeautifulSoup(content, 'lxml')

def soup_from_url(url: str, **requests_kw):
    match requests.get(url, **requests_kw):
        case r_200 if r_200.status_code == 200:
            return pipe(
                r_200.content,
                soup
            )
