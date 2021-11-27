import bs4

# ----------------------------------------------------------------------
#
# HTML handling functions
#
# ----------------------------------------------------------------------

def soup(content: str):
    return bs4.BeautifulSoup(content, 'lxml')


