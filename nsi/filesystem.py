from pathlib import Path
from re import M
import statistics
from collections import defaultdict, OrderedDict
from datetime import datetime, date
import typing as T
import builtins
import random
import math

from . import shell, logging
from .toolz import *

_min = builtins.min
_max = builtins.max
min = maybe_min
max = maybe_max

log = logging.new_log(__name__)

@ensure_paths
def file_type(path: Path, *, getoutput: T.Callable = None, echo: bool = False, 
              no_brief: bool = False, **file_options):
    getoutput = getoutput or shell.getoutput(echo=echo)
    if not no_brief:
        file_options = merge(file_options, {'brief': True})
    options_string = shell.options_string(file_options)
    command = f'file {options_string} "{path}"'
    log.debug(f'file_type command: {command}')
    return getoutput(command)

order_map = {
    0: '',
    1: 'K',
    2: 'M',
    3: 'G',
    4: 'T',
    5: 'P',
    6: 'X',
}

def n_digits(value: T.Union[int, float]):
    value = abs(int(value))
    if 0 < value <= 999999999999997:
        return int(math.log10(value)) + 1
    return len(str(value))

def get_order(value):
    digits = n_digits(value)
    zeros = digits - 1
    order = zeros // 3
    add_zeros = zeros % 3
    return (digits, f"1{add_zeros * '0'}{order_map[order]}")
    return zeros, digits, order, add_zeros

def size_stats():
    return {
        'min': None,
        'max': None,
        'mean': None,
        'sizes': {},
    }

def time_stats():
    return {
        'min': None,
        'max': None,
        'mean': None,
    }

@curry
def running_stats(stats: dict, values: T.Sequence):
    new_stats = {}
    if is_some(stats['min']):
        new_stats['min'] = min(concatv([stats['min']], values))
    else:
        new_stats['min'] = maybe_min(values)

    if is_some(stats['max']):
        new_stats['max'] = max(concatv([stats['max']], values))
    else:
        new_stats['max'] = maybe_max(values)

    if is_some(stats['mean']):
        weight, mean = stats['mean']
        new_mean = weight * mean
        new_mean += len(values) * maybe_mean(values, default=0)
        new_weight = weight + len(values)
        new_mean /= new_weight
        new_stats['mean'] = (new_weight, new_mean)
    else:
        new_stats['mean'] = (len(values), maybe_mean(values))

    if 'sizes' in stats:
        # size_stats
        new_sizes = new_stats['sizes'] = stats['sizes'].copy()
        for value in values:
            order = get_order(value)
            new_sizes[order] = stats['sizes'].get(order, 0) + 1

    return new_stats

def finalize_stats(stats: dict):
    return merge(
        stats, 
        {'mean': stats['mean'][-1]},
        {'sizes': pipe(
            stats['sizes'],
            items,
            sorted,
            dict,
            keymap(lambda t: t[1]),
        )} if 'sizes' in stats else {}, 
    )

final_running_stats = compose_left(running_stats, finalize_stats)

DEFAULT_MAX_EXAMPLES = 10

@ensure_paths
def directory_metadata(root: Path, *, min_mtime: date = None, 
                       max_examples: int = DEFAULT_MAX_EXAMPLES,
                       skip_dirs: T.Sequence[str] = None, 
                       no_case: bool = True, 
                       writer: T.Callable[[dict], int] = None):
    '''
    Walk a directory, gathing metadata about the files contained within
    '''
    log.info(f'Building metadata for directory: {root}')
    
    meta = {
        'root': root,
        'extensions': {
        },
        'totals': {
            'files': 0,
            'dirs': 0,
        },
        'size': {
            'file': size_stats(),
            'dir': size_stats(),
        },
        'times': {
            'file': {
                'created': time_stats(),
                'modified': time_stats(),
            },
            'dir': {
                'created': time_stats(),
                'modified': time_stats(),
            },
        },
    }
    file_sizes = []
    times = {
        'file': {
            'created': [],
            'modified': [],
            'accessed': [],
        },
        'dir': {
            'created': [],
            'modified': [],
            'accessed': [],
        },
    }
    dirs = defaultdict(int)
    skipped = 0
    batch_size = 1e5

    def finalize():
        meta['size']['file'] = final_running_stats(meta['size']['file'], file_sizes)
        # meta['size']['file']['min'] = maybe_min(file_sizes)
        # meta['size']['file']['max'] = maybe_max(file_sizes)
        # meta['size']['file']['mean'] = maybe_mean(file_sizes)
        # meta['size']['file']['median'] = maybe_median(file_sizes)
        # meta['size']['file']['mode'] = maybe_mode(file_sizes)

        meta['totals']['dirs'] = len(dirs)
        dir_sizes = tuple(dirs.values())
        meta['size']['dir'] = final_running_stats(meta['size']['dir'], dir_sizes)
        # meta['size']['dir']['min'] = maybe_min(dir_sizes)
        # meta['size']['dir']['max'] = maybe_max(dir_sizes)
        # meta['size']['dir']['mean'] = maybe_mean(dir_sizes)
        # meta['size']['dir']['median'] = maybe_median(dir_sizes)
        # meta['size']['dir']['mode'] = maybe_mode(dir_sizes)

        for f_t in ['file', 'dir']:
            for t_t in ['created', 'modified']: #, 'accessed']:
                meta['times'][f_t][t_t] = final_running_stats(
                    meta['times'][f_t][t_t], times[f_t][t_t]
                )
                # meta['times'][f_t][t_t]['min'] = maybe_min(times[f_t][t_t])
                # meta['times'][f_t][t_t]['max'] = maybe_max(times[f_t][t_t])
                # meta['times'][f_t][t_t]['mean'] = maybe_mean(times[f_t][t_t])
                # meta['times'][f_t][t_t]['median'] = maybe_median(times[f_t][t_t])
                # meta['times'][f_t][t_t]['mode'] = maybe_mode(times[f_t][t_t])
                for t in ['min', 'max', 'mean']: #, 'median', 'mode']:
                    meta['times'][f_t][t_t][t] = maybe_pipe(
                        meta['times'][f_t][t_t][t],
                        datetime.fromtimestamp,
                        lambda dt: dt.date(),
                    )

    for path in walk(root, skip_dirs=skip_dirs):
        if min_mtime and mtime(path) < maybe_dt(min_mtime):
            if skipped and skipped % 10000 == 0:
                log.info(f'  skipped... {skipped} ({root})')
            skipped += 1
            continue
        
        skipped = 0
        if path.parent not in dirs:
            log.debug(f'  dir: {path.parent}')
        log.debug(f'  file: {path}')
        ext_d = meta['extensions']

        def suffix(path):
            return path.suffix.lower() if no_case else path.suffix

        if suffix(path) not in ext_d:
            ext_d[suffix(path)] = {
                'type': file_type(path),
                'examples': [],
                'total': 0,
            }
            
        if len(ext_d[suffix(path)]['examples']) < max_examples:
            ext_d[suffix(path)]['examples'].append(path)
        else:
            if random.random() < 0.1:
                ext_d[suffix(path)]['examples'][random.randrange(max_examples)] = path
        ext_d[suffix(path)]['total'] += 1

        meta['totals']['files'] += 1

        file_sizes.append(file_size(path))
        times['file']['created'].append(ctime(path).timestamp())
        times['file']['modified'].append(mtime(path).timestamp())
        # times['file']['accessed'].append(atime(path).timestamp())

        if len(file_sizes) >= batch_size:
            meta['size']['file'] = running_stats(
                meta['size']['file'], file_sizes,
            )
            file_sizes = []
            for t_t in ['created', 'modified']:
                meta['times']['file'][t_t] = running_stats(
                    meta['times']['file'][t_t], times['file'][t_t]
                )
                times['file'][t_t] = []

        if path.parent not in dirs:
            times['dir']['created'].append(ctime(path.parent).timestamp())
            times['dir']['modified'].append(mtime(path.parent).timestamp())
            # times['dir']['accessed'].append(atime(path.parent).timestamp())

        dirs[path.parent] += 1

        if meta['totals']['files'] % 10000 == 0:
            log.info(
                f"  currently on file {meta['totals']['files']} ({root})"
            )
            writer(meta) if writer else None

    finalize()

    return meta
