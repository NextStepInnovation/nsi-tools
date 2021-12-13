try:
    from cytoolz.curried import *
    import cytoolz.curried as _toolz
except ImportError:
    from toolz.curried import *
    import toolz.curried as _toolz

from .common import *
from .csv import *
from .dictionary import *
from .filesystem import *
from .functions import *
from .graph import *
from .hashing import *
from .html import *
from .http import *
from .ips import *
from .json import *
from .pyrsistent import *
from .random import *
from .regex import *
from .text_processing import *
from .time import *

__all__ = [
    # toolz.curried
    'accumulate', 'apply', 'assoc', 'assoc_in', 'comp',
    'complement', 'compose', 'compose_left', 'concat', 'concatv',
    'cons', 'count', 'countby', 'curry', 'diff',
    'dissoc', 'do', 'drop', 'excepts', 'filter',
    'first', 'flip', 'frequencies', 'get', 'get_in',
    'groupby', 'identity', 'interleave', 'interpose', 'isdistinct',
    'isiterable', 'itemfilter', 'itemmap', 'iterate', 'join',
    'juxt', 'keyfilter', 'keymap', 'last', 'map',
    'mapcat', 'memoize', 'merge', 'merge_sorted', 'merge_with',
    'nth', 'operator', 'partial', 'partition', 'partition_all',
    'partitionby', 'peek', 'peekn', 'pipe', 'pluck',
    'random_sample', 'reduce', 'reduceby', 'remove', 'second',
    'sliding_window', 'sorted', 'tail', 'take', 'take_nth',
    'thread_first', 'thread_last', 'topk', 'unique', 'update_in',
    'valfilter', 'valmap',

    # json
    'jmes', 'json_dumps', 'json_loads', 'log', 'maybe_json',

    # http
    'session_with_cookies', 'url', 'valid_content', 'valid_response',

    # text_processing
    'clipboard_copy', 'clipboard_paste', 'difflines', 'escape_row', 'intlines',
    'lines_without_comments', 'output_rows_to_clipboard', 'remove_comments', 'strip_comments', 'strip_comments_from_line',
    'strip_comments_from_lines', 'xlsx_to_clipboard', 'xorlines',

    # filesystem
    'POS_PARAM_KINDS', 'backup_path', 'check_parents_for_file', 'ensure_paths', 'is_path',
    'log', 'newer', 'older', 'peek', 'read_text', 'read_bytes',
    'slurp', 'slurpb', 'slurpblines', 'slurplines', 'to_paths', 'walk', 'walkmap',

    # common
    'as_tuple', 'call', 'callif', 'cat_to_set', 'concat_t',
    'concatv_t', 'contains', 'cprint', 'deref', 'dispatch', 'do_error',
    'do_info', 'do_log', 'error_raise', 'find', 'first_true',
    'flatdict', 'float_or_zero', 'function_from_path', 'get_t', 'help_text',
    'index', 'is_dict', 'is_float', 'is_indexable', 'is_int',
    'is_none', 'is_not_dict', 'is_not_seq', 'is_not_string', 'is_seq',
    'is_some', 'is_str', 'items', 'log', 'log_lines',
    'lower', 'map_t', 'map_to_set', 'mapdo', 'mapif',
    'max', 'maybe_first', 'maybe_float', 'maybe_int', 'maybe_last',
    'maybe_max', 'maybe_min', 'maybe_pipe', 'maybe_second', 'min',
    'mini_tb', 'new_log', 'noop', 'replace', 'sc_juxt',
    'select', 'seti', 'seti_t', 'short_circuit', 'shuffled',
    'sort_by', 'sorted', 'split', 'splitlines', 'starmap',
    'strip', 'to_bytes', 'to_str', 'upper', 'val',
    'vcall', 'vcallif', 'vdo', 'vfilter', 'vfind',
    'vgroupby', 'vindex', 'vitemmap', 'vkeymap', 'vmap',
    'vmapcat', 'vmapdo', 'vmapif', 'vseti', 'vseti_t',
    'vvalmap', 'wrap_text',

    # pyrsistent
    'freeze', 'frozen_curry', 'no_pyrsistent', 'to_pyrsistent',

    # csv
    'csv_rows', 'csv_rows_from_content', 'csv_rows_from_fp', 'csv_rows_from_path', 'csv_rows_to_content',
    'csv_rows_to_fp', 'csv_rows_to_path', 'log',

    # html
    'soup',

    # time
    'ctime', 'ctime_as_dt', 'dt_ctime', 'maybe_dt', 'parse_dt',
    'to_dt',

    # functions
    'arg_intersection', 'is_arg_superset', 'positional_args', 'positional_only_args',

    # graph
    'bfs_tree', 'from_edgelist',

    # regex
    'Regex', 'bakedict', 'grep', 'grep_t', 'grepitems',
    'grepv', 'grepv_t', 'grepvitems', 'groupdict', 'groupdicts',
    'groupdicts_from_regexes', 'match_d', 're_search', 'regex_transform', 'to_regex',
    'vbakedict',

    # hashing
    'b64decode', 'b64decode_str', 'b64encode', 'b64encode_str', 'hash',

    # random
    'random_pw', 'random_sample', 'random_sentence', 'random_str', 'random_user',

    # dictionary
    'cmerge', 'create_key', 'dict_hash', 'drop_key', 'drop_keys',
    'merge_keys', 'only_if_key', 'remove_key', 'remove_keys', 'replace_key',
    'set_key', 'switch_keys', 'update_if_key_exists', 'update_key', 'update_key_v',
    'valmaprec',

    # ips
    'current_ip', 'current_ipv4', 'current_ipv6', 'free_port', 'get_ips_from_content',
    'get_ips_from_file', 'get_ips_from_lines', 'get_ips_from_str', 'get_networks_from_content', 'get_networks_from_file',
    'get_networks_from_lines', 'get_slash', 'get_slash_from_mask', 'in_ip_range', 'ip_only_re',
    'ip_re', 'ip_to_seq', 'ip_tuple', 'is_comma_sep_ip', 'is_interface',
    'is_ip', 'is_ip_range', 'is_ipv4', 'is_network', 'log',
    'sort_ips', 'sortips', 'unzpad', 'zpad',
]

def toolz_imports():
    from pathlib import Path
    modules = pipe(
        Path(__file__).parent.glob('*.py'), 
        filter(lambda p: not p.name.startswith('_')),
        tuple,
    )
    def f_names(p):
        return pipe(
            slurplines(p),
            groupdicts(r'^(def (?P<name>.*?)\(|(?P<name>\w[\d\w_]*) = )'),
            map(get('name')),
            filter(lambda n: not n.startswith('_')),
            sorted,
        )
    def grid(names):
        return pipe(
            names,
            partition_all(5),
            map(map(lambda s: f"'{s}'")),
            map(', '.join),
            map(lambda l: '    ' + l + ','),
            '\n'.join,
        )
    def f_grid(p):
        return pipe(
            f_names(p),
            grid,
            lambda s: f'    # {p.stem}\n' + s
        )
    t_c = pipe(
        dir(_toolz),
        filter(lambda n: not n.startswith('_')),
        grid,
        lambda s: f'    # toolz.curried\n' + s
    )
    return pipe(
        modules,
        map(f_grid),
        lambda l: concat([(t_c,), l]),
        '\n\n'.join,
    )