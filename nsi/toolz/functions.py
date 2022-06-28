import inspect

from .common import pipe

__all__ = [
    # functions
    'arg_intersection', 'is_arg_superset', 'positional_args',
    'positional_only_args',
]

def arg_intersection(func, kw):
    params = inspect.signature(func).parameters
    if any(p.kind == p.VAR_KEYWORD for p in params.values()):
        return kw
    else:
        return {k: kw[k] for k in set(params) & set(kw)}

def positional_args(func):
    return pipe(
        inspect.signature(func).parameters.values(),
        filter(
            lambda p: p.kind not in {p.VAR_KEYWORD,
                                     p.KEYWORD_ONLY,
                                     p.VAR_POSITIONAL}
        ),
        filter(lambda p: p.default == p.empty),
        map(lambda p: p.name),
        tuple,
    )
# This might need to change in Python 3.8 with actual pos-only args
positional_only_args = positional_args

def is_arg_superset(kwargs, func):
    '''Does the kwargs dictionary contain the func's required params?

    '''
    return pipe(
        func,
        positional_only_args,
        set(kwargs).issuperset,
    )

