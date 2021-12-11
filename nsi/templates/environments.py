from pathlib import Path
import typing as T

import jinja2

from ..toolz import *
from .common import resource_filename
from . import filters, functions

def get_env(path: Path = None):
    path = path or resource_filename('j2')
    return pipe(
        jinja2.Environment(
            loader = pipe(
                path,
                jinja2.FileSystemLoader,
            ),
        ), 
        filters.nsi_filters,
        functions.nsi_functions,
    )

def get_metatemplate_env(path: T.Union[str, Path] = None):
    path = path or resource_filename('j2')
    env = jinja2.Environment(
        variable_start_string='%%',
        variable_end_string='%%',
        block_start_string='<%',
        block_end_string='%>',
        comment_start_string='<#',
        comment_end_string='#>',
        loader = pipe(
            path,
            jinja2.FileSystemLoader,
        ),
    )

    return pipe(
        env, 
        filters.nsi_filters,
        functions.nsi_functions,
    )

