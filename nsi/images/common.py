import io
from functools import wraps
from pathlib import Path
import typing as T

from pkg_resources import resource_filename
from PIL import (
    Image,
    ImageDraw,
    ImageFont,
)

from ..toolz import *
from .. import logging

log = logging.new_log(__name__)

BLUE = (87, 116, 160, 255)
BLUE2 = (100, 140, 200, 255)
GREY = (100, 100, 100, 255)

@curry
def to_bytes(im_func: T.Callable, obj: T.Union[str, Path, Image.Image]):
    match obj:
        case path if isinstance(path, (str, Path)):
            return pipe(
                path,
                Image.open,
                to_bytes(im_func),
            )
        case image if isinstance(image, Image.Image):
            buf = io.BytesIO()
            im_func(image, buf)
            return buf.getvalue()
        case nonsense:
            raise IOError(
                f'Cannot convert {str(nonsense)[:1000]} to bytes.'
            )

jpeg_bytes = to_bytes(
    lambda image, buf: image.convert('RGB').save(
        buf, 'jpeg', optimize=True,
    )
)
png_bytes = to_bytes(
    lambda image, buf: image.save(buf, 'png')
)

def delta_point(x, y):
    def delta(dx=0, dy=0):
        return (x + dx, y + dy)
    return delta

def get_font(name):
    return resource_filename(__name__, f'templates/fonts/{name}')

def tt_font(path):
    def font(*a, **kw):
        return ImageFont.truetype(path, *a, **kw)
    return font

def cambria():
    fmap = pipe(
        [(frozenset(['italic', 'bold']), 'Cambria Bold Italic.ttf'),
         (frozenset(['bold']), 'Cambria Bold.ttf'),
         (frozenset(['italic']), 'Cambria Italic.ttf'),
         (frozenset(['math']), 'Cambria Math.ttf'),
         (frozenset(), 'Cambria.ttf')],
        map(lambda d: (d[0], tt_font(get_font(d[1])))),
        dict,
    )

    def font(*mods):
        return fmap[frozenset(mods)]
    return font

@curry
def draw_text(base_image: Image.Image, text: str, loc: T.Tuple[int, int], *,
              font_f: T.Callable = cambria, font_size: int = 20,
              mods: T.Iterable = None, size: T.Tuple[int, int] = None,
              fill: T.Union[str, T.Tuple[int, int, int]] = 'white'):
    overlay = Image.new('RGBA', base_image.size, (255, 255, 255, 0))
    ovl_draw = ImageDraw.Draw(overlay)

    font = font_f()(*(mods or []))(font_size)
    loc = tuple(loc)

    draw_method = ovl_draw.text
    if '\n' in text:
        draw_method = ovl_draw.multiline_text
        
    draw_method(loc, text, font=font, fill=fill)

    final = Image.alpha_composite(base_image, overlay)

    if size:
        sx, sy = size
        w, h = final.size
        final = final.resize(
            (int(w * sx), int(h * sy)), resample=Image.LANCZOS
        )
        
    return final
