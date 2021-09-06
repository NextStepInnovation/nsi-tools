import markdown as _markdown

from . import (
    meta_yaml, card, table, yaml_data, image_fig,
)
from .. import toolz as _


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
