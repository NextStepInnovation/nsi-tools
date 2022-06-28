from pathlib import Path
import random

import jinja2

from ..toolz import *
from .. import images
from .common import find_files
from .environments import get_env

@curry
def make_figure(im_type, filename, caption, images, *, style: dict = None):
    style = pipe(
        pipe(
            style.items(),
            vmap(lambda k, v: f"{k}: {v}"),
            ';'.join,
        ),
        'style="{}"'.format,
    ) if style else ''
    figure = {'type': im_type, 'filename': Path(filename).name,
              'search': filename, 'caption': caption,
              'images': images, 'style': style}
    return get_env().get_template('figure.html.j2').render(figure=figure)

@curry
def figure_function(im_type, bytes_function, caption, filename, start='.',
                    *, style: dict = None):
    return pipe(
        filename,
        find_files(start),
        map(bytes_function),
        map(b64encode_str),
        tuple,
        make_figure(im_type, filename, caption, style=style),
    )

png = figure_function('png', images.png_bytes)
jpeg = figure_function('jpeg', images.jpeg_bytes)

def table(data):
    return get_env().get_template('table.html.j2').render(data=data)

@curry
def add_functions(env: jinja2.Environment, **funcs):
    env.globals.update(funcs)
    return env

@curry
def nsi_functions(env: jinja2.Environment, **funcs):
    return add_functions(env, **merge(
        {
            'png': png,
            'jpeg': jpeg,
            'table': table,
            'choice': random.choice,
            'random_str': random_str,
            'random_str_word_set': random_str_word_set,
            'randrange': random.randrange,
        }, funcs
    ))

