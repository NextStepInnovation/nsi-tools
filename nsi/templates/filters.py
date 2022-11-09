import calendar
from tokenize import group

import jinja2

from ..toolz import *
from .. import logging
from .. import markdown

log = logging.new_log(__name__)

def pluralize(number, singular='', plural='s'):
    if number == 1:
        return singular
    return plural

@curry
def md_to_html(text, **md_kwargs):
    return markdown.markdown(text or '', **md_kwargs)

def long_date(text):
    return maybe_dt(text).strftime('%B %d, %Y') or log.error(
        f'Could not parse datetime: "{repr(text)}"'
    )


def year(text):
    return pipe(
        text,
        maybe_dt,
        deref('year'),
    )

def month(text):
    return pipe(
        text,
        maybe_dt,
        deref('month'),
        lambda m: calendar.month_name[m],
    )

@curry
def add_filters(env: jinja2.Environment, **filters):
    env.filters.update(filters)
    return env

@curry
def nsi_filters(env: jinja2.Environment, **filters):
    return add_filters(env, **merge(
        {
            'pluralize': pluralize,
            'md_to_html': md_to_html,
            'md_to_pandoc': markdown.md_to_pandoc,
            'md5': md5,
            'sha1': sha1,
            'sha256': sha256,
            'sha512': sha512,
            'long_date': long_date,
            'year': year,
            'month': month,
            'b64encode': b64encode_str,
            'groupby': groupby,
        }, filters
    ))
