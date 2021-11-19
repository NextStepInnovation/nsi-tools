'''MSF MSGRPC API

https://metasploit.help.rapid7.com/docs/standard-api-methods-reference

'''
import os
import re
import functools
import pprint
import time
import collections

import msgpack
import requests
from pymaybe import Nothing

from . import toolz as _
from . import logging

log = logging.new_log(__name__)

def unbinary(v):
    if _.is_seq(v):
        return tuple(unbinary(o) for o in v)
    elif _.is_dict(v):
        return {unbinary(key): unbinary(val) for key, val in v.items()}
    elif isinstance(v, bytes):
        try:
            return v.decode()
        except ValueError:
            return v
    else:
        return v
        
@_.curry
def packb(thing, *a, **kw):
    return msgpack.packb(thing, *a, **kw)

@_.curry
def unpackb(content, **kw):
    return msgpack.unpackb(content, **kw)

MSF_USER = 'KUZU_MSF_USER'
MSF_PASS = 'KUZU_MSF_PASS'
class MsfSession:
    def __init__(self, host, port, path, user, password):
        if user is None:
            if MSF_USER not in os.environ:
                raise AttributeError(
                    f'MSGRPC username must be provided (e.g. {MSF_USER}'
                    ' environment variable)'
                )
            user = os.environ[MSF_USER]
        if password is None:
            if MSF_PASS not in os.environ:
                raise AttributeError(
                    f'MSGRPC password must be provided (e.g. {MSF_PASS}'
                    ' environment variable)'
                )
            password = os.environ[MSF_PASS]
        self.conn = host, port, path, user, password
        self.url = f'http://{host}:{port}{path}'
        self.session = requests.Session()
        self.session.headers.update(
            {'Content-type': 'binary/message-pack'},
        )
        
    _token = None
    @property
    def token(self):
        if self._token is not None:
            return self._token
        log.info('Regenerating MSF session token')
        *_c, user, password = self.conn
        self._token = _.pipe(
            self.session.post(
                self.url,
                data=packb(['auth.login', user, password])
            ),
            lambda r: _.pipe(r.content, msgpack.unpackb),
            unbinary,
            lambda d: d['token'],
        )
        return self._token

    def raise_on_error(func):
        @functools.wraps(func)
        def wrap(*a, **kw):
            output = func(*a, **kw)
            if output.get('error'):
                raise ValueError(pprint.pformat(output))
            return output
        return wrap

    def _post(self, *args, do_unbinary=True):
        args = _.pipe(
            (args[:1], [self.token], args[1:]),
            _.concat,
            tuple,
        )
        log.debug(f'POST args: {args}')
        return _.pipe(
            self.session.post(self.url, data=msgpack.packb(args)),
            lambda r: r.content,
            _.do(log.debug),
            unpackb(strict_map_key=False),
            unbinary if do_unbinary else _.do_nothing,
        )

    # @raise_on_error
    def __call__(self, *args, do_unbinary=True):
        output = self._post(*args, do_unbinary=do_unbinary)
        if (output.get('error_message') == 'Invalid Authentication Token'):
            self._token = None
            output = self._post(*args, do_unbinary=do_unbinary)
            if output.get('error'):
                raise ValueError(pprint.pformat(output))
            return output
        elif output.get('error'):
            raise ValueError(pprint.pformat(output))
        return output

    def __hash__(self):
        return hash(self.token)

default_msf = _.partial(MsfSession, '127.0.0.1', 55552, '/api/')

_sample = r'''
Process List
============
          1         2         3         4         5         6         7         8
012345678901234567890123456789012345678901234567890123456789012345678901234567890

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System             x86   0        NT AUTHORITY\SYSTEM
 180   700   vmtoolsd.exe       x86   0        NT AUTHORITY\SYSTEM           C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
'''

ps_regex = re.compile('''\
^\s(P<pid>[\d ]{5})\s
^\s(P<ppid>[\d ]{5})\s
^\s(P<name>.{17})\s
(^\s(P<arch>.{4})\s)?
(^\s(P<session>[\d ]{7})\s)?
''', re.VERBOSE)
ps_cols = [
    'PID', 'PPID', 'Name', 'Arch', 'Session', 'User', 'Path'
]
maybe_int = _.maybe_int
ps_col_map = {
    'PID': maybe_int,
    'PPID': maybe_int,
    'Session': maybe_int,
}
def parse_ps(content):
    lines = content.splitlines()
    start_index = _.pipe(
        lines,
        enumerate,
        _.vfilter(lambda i, l: 'Process List' in l),
        _.maybe_first,
    )[0]
    if _.is_null(start_index):
        log.error('Could not find ps content')
        return 

    col_line = lines[start_index + 3]
    columns = _.pipe(
        ps_cols,
        _.map(lambda c: (c, col_line.index(c))),
        collections.OrderedDict,
    )

    ps_lines = _.pipe(
        lines[start_index + 5:],
        _.filter(lambda l: l.strip()),
        tuple,
    )
    for i, line in enumerate(ps_lines):
        row = []
        for j, (c, start) in enumerate(columns.items()):
            if j == len(columns) - 1:
                end = len(line)
            else:
                end = columns[ps_cols[j + 1]]
            value = _.pipe(
                line[start: end].strip(),
                ps_col_map.get(c, lambda v: v),
            )
            row.append((c, value))
        row = dict(row)
        if not _.is_null(row['PID']):
            yield row

    # return columns
    

class MsfConsole:
    def __init__(self, msf):
        self.msf = msf
        self.id = msf('console.create')['id']
        self._output = []
        self._read()

    def _read(self):
        done, content = False, ''
        while not done:
            response = self.msf('console.read', self.id)
            data = response['data']
            if data:
                content += data
                self._output.append(data)
            if response['busy'] or data:
                log.info('   ... busy')
                time.sleep(1)
            else:
                done = True

        data = self.msf('console.read', self.id)['data']
        if data:
            content += data
            self._output.append(data)
        return content

    def load(self, session_id, *modules):
        return _.pipe(
            modules,
            _.map(lambda m: f'sessions -i {session_id} -C "load {m}"'),
            _.vcall(self.write),
        )

    @_.curry
    def session_command(self, session_id, command, *commands):
        return _.pipe(
            _.concatv([command], commands),
            _.map(lambda c: f'sessions -i {session_id} -C "{c}"'),
            _.vcall(self.write),
        )

    @property
    def output(self):
        return ''.join(self._output)

    def read(self):
        return self._read()
        
    def write(self, *commands):
        log.info(f'Running commands: {commands}')
        self.msf('console.write', self.id, '\n'.join(commands) + '\n')
        time.sleep(0.1)
        return self.read()

ModuleType = {"exploit", "auxiliary", "post", "payload", "encoder", "nop"}

def info(msf, module_type: ModuleType, module_name):
    return msf('module.info', module_type, module_name)

def options(msf, module_type: ModuleType, module_name):
    return msf('module.options', module_type, module_name)

def execute(msf, module_type: ModuleType, module_name, kw):
    return msf('module.execute', module_type, module_name, kw)

def exploit(msf, path, kw):
    return msf(
        'module.execute', 'exploit', path, kw,
    )

def multi_handler(msf, pl_path, pl_kw):
    return exploit(
        msf, exploits(msf).multi.handler,
        _.merge(
            pl_kw, {'PAYLOAD': pl_path},
        )
    )

def payload(msf, path, kw):
    return msf(
        'module.execute', 'payload', path, kw, do_unbinary=False
    )[b'payload']

def job_data(data):
    return _.merge(
        data,
    )

def jobs(msf):
    return _.pipe(
        msf('job.list').keys(),
        _.map(lambda n: (n, msf('job.info', n))),
        _.vmap(lambda n, data: (int(n), job_data(data))),
        dict,
    )

def job_ports(msf):
    return _.pipe(
        jobs(msf).values(),
        _.map(lambda j: j.get('datastore', {}).get('LPORT')),
        _.filter(None),
        tuple,
    )

def next_port(msf):
    return _.pipe(
        job_ports(msf),
        max(default=4443),
        lambda p: p + 1,
    )

def sessions(msf):
    return msf('session.list')

@_.curry
def session_with_attr(msf, attr):
    return _.pipe(
        sessions(msf).items(),
        _.vfilter(lambda session_id, data: all(
            data.get(k) == v for k, v in attr.items()
        )),
        _.maybe_first(default=(None, None)),
    )


@_.curry
def init_session(msf, console_id, session_id):
    log.info(met_command(msf, session_id, 'load stdapi'))
    time.sleep(1)

def met_read(msf, session_id):
    time.sleep(1)
    content = ''
    new = msf('session.meterpreter_read', session_id).get('data')

@_.curry
def met_command(msf, session_id, command):
    result = msf('session.meterpreter_run_single', session_id, command)
    if result.get('result') == 'success':
        # time.sleep(2)
        return msf('session.meterpreter_read', session_id).get('data')
    log.error(f'Error executing command: {result}')
    return Nothing()

@_.curry
def met_ps(msf, session_id):
    output = met_command(msf, session_id, 'ps')
    if output:
        return _.pipe(
            output.splitlines(),
        )
    return Nothing()


required_options = _.compose(
    dict,
    _.vfilter(lambda k, v: v.get('default') is None),
    _.vfilter(lambda k, v: v.get('required')),
    lambda d: d.items(),
    options,
)

class Nav:
    def __init__(self, nav_type, tuples, parents=()):
        self._nav_type = nav_type
        self._parents = parents
        attr = _.pipe(
            tuples,
            _.groupby(_.first),
            _.valmap(lambda t: [x[1:] for x in t])
        )
        for k, t in attr.items():
            new_parents = _.concatv_t(parents, [k])
            if any(len(x) for x in t):
                attr[k] = Nav(self._nav_type, t, new_parents)
            else:
                attr[k] = '/'.join(new_parents)
        self.__dict__ = _.merge(self.__dict__, attr)

    @classmethod
    def _from_paths(cls, nav_type, paths):
        return _.pipe(
            paths,
            _.map(lambda p: p.split('/')),
            tuple,
            lambda tuples: cls(nav_type, tuples),
        )

    @property
    def _keys(self):
        return _.pipe(
            self.__dict__.keys(),
            _.filter(lambda k: not k.startswith('_')),
            tuple,
        )

    def __repr__(self):
        parents = " " + "/".join(self._parents) if self._parents else ""
        return f'<Nav {self._nav_type}{parents}: {", ".join(self._keys)}>'

@_.memoize
def exploits(msf):
    modules = msf('module.exploits')['modules']
    return Nav._from_paths('exploit', modules)

@_.memoize
def auxiliary(msf):
    modules = msf('module.auxiliary')['modules']
    return Nav._from_paths('auxiliary', modules)

@_.memoize
def post(msf):
    modules = msf('module.post')['modules']
    return Nav._from_paths('post', modules)

@_.memoize
def payloads(msf):
    modules = msf('module.payloads')['modules']
    return Nav._from_paths('payload', modules)


