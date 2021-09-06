import concurrent.futures

from .toolz import curry, concatv, vcall

@curry
def thread_map(func, iterable, *iterables, **tpe_kw):
    with concurrent.futures.ThreadPoolExecutor(**tpe_kw) as executor:
        for value in executor.map(func, *concatv((iterable,), *iterables)):
            yield value

@curry
def thread_vmap(func, iterable, *iterables, **tpe_kw):
    yield from thread_map(vcall(func), iterable, *iterables, **tpe_kw)

@curry
def process_map(func, iterable, *iterables, **tpe_kw):
    with concurrent.futures.ProcessPoolExecutor(**tpe_kw) as executor:
        for value in executor.map(func, *concatv((iterable,), *iterables)):
            yield value

@curry
def process_vmap(func, iterable, *iterables, **tpe_kw):
    yield from process_map(vcall(func), iterable, *iterables, **tpe_kw)

@curry
def pmap(ptype: str):
    return {
        'thread': thread_map,
        'proccess': process_map,
        'vthread': thread_vmap,
        'vproccess': process_vmap,
    }.get(ptype, thread_map)
