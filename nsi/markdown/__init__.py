import markdown as _markdown

from . import (
    meta_yaml, card, table, yaml_data, image_fig,
)
from .. import toolz as _
from .. import logging

log = logging.new_log(__name__)

@_.curry
def markdown(content: str, **kwargs):
    class HtmlWithMeta(str):
        meta = None

    md = _markdown.Markdown(
        extensions=_.pipe(
            _.concatv(
                ['nsi.markdown.meta_yaml',
                 'nsi.markdown.yaml_data',
                 'nsi.markdown.card',
                 'nsi.markdown.table'],
                ['extra', 'codehilite', 'toc', 'admonition'],
                kwargs.get('extensions', []),
            ),
            set,
            tuple,
        ),
            
        extension_configs=_.merge(
            {
                'extra': {},
                'admonition': {
                },
                'codehilite': {
                    'noclasses': True,
                    'guess_lang': False,
                },
            },
            kwargs.get('extension_configs', {}),
        ),
    )

    output = HtmlWithMeta(md.convert(content))
    output.meta = md.meta or {}
    return output

def make_table(columns=None, col_map=None):
    def maker(rows):
        rows = tuple(rows)
        if not rows:
            return ''

        nonlocal columns, col_map
        if columns is None:
            columns = tuple(rows[0].keys())
        if col_map is None:
            header = columns
        else:
            header = [col_map[c] for c in columns]

        if _.is_seq(rows[0]):
            value_f = lambda r: [r[i] for i, _c in enumerate(columns)]
        else:
            value_f = lambda r: [r[c] for c in columns]
            
        yield '| ' + ' | '.join(header) + ' |'
        yield '|:--'*len(header) + '|'
        for row in rows:
            try:
                values = value_f(row)
            except:
                log.exception(row)
                raise
            yield '| ' + _.pipe(
                values,
                _.map(str),
                ' | '.join
            ) + ' |'

    return _.compose_left(maker, '\n'.join)
