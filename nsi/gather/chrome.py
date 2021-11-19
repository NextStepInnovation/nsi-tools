import logging
import sqlite3

from toolz.curried import (
    pipe, map,
)

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

FILES = [
    {"raw": "", "in_file": "Web Data", "sql": "select * from autofill;"},
    {"raw": "", "in_file": "Web Data",
     "sql": "SELECT username_value,origin_url,signon_realm FROM logins;"},
    {"raw": "", "in_file": "Web Data",
     "sql": "select * from autofill_profiles;"},
    {"raw": "", "in_file": "Web Data", "sql": "select * from credit_cards;",
     "encrypted_fields": ["card_number_encrypted"]},
    {"raw": "", "in_file": "Cookies", "sql": "select * from cookies;"},
    {"raw": "", "in_file": "History", "sql": "select * from urls;"},
    {"raw": "", "in_file": "History", "sql": "SELECT url FROM downloads;"},
    {"raw": "", "in_file": "History",
     "sql": "SELECT term FROM keyword_search_terms;"},
    {"raw": "", "in_file": "Login Data", "sql": "select * from logins;",
     "encrypted_fields": ["password_value"]},
    {"raw": "", "in_file": "Bookmarks", "sql": None},
    {"raw": "", "in_file": "Preferences", "sql": None},
]

def get_sql_rows(data):
    if 'sql' in data:
        conn = sqlite3.connect(data['in_file'])
        conn.row_factory = sqlite3.Row
        cur = conn.execute(data['sql'])
        yield from pipe(
            cur.fetchall(),
            map(lambda r: zip(r.keys(), r)),
            map(dict),
        )
