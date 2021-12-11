import calendar

import jinja2

from ..toolz import *
from .. import markdown

def pluralize(number, singular='', plural='s'):
    if number == 1:
        return singular
    return plural

def md_to_html(text):
    return markdown.markdown(text)

def long_date(text):
    return maybe_dt(text).stftime('%B %d, %Y') or log.error(
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

def add_filters(env: jinja2.Environment, **filters):
    env.filters.update(filters)
    return env

def nsi_filters(env: jinja2.Environment, **filters):
    return add_filters(**merge(
        {
            'pluralize': pluralize,
            'md_to_html': md_to_html,
            'md_to_pandoc': markdown.md_to_pandoc,
            'long_date': long_date,
            'year': year,
            'month': month,
            'b64encode': b64encode_str,
        }, filters
    ))
