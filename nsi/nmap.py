'''nmap functionality


'''
from pathlib import Path
from datetime import datetime
import shlex
import xml.etree.ElementTree
import typing as T
from typing import Union
from collections import defaultdict
from pymaybe import Nothing
import hashlib
import pprint
import re
import json

import networkx as nx
import xmljson

from . import toolz as _
from . import yaml
from . import parallel
from .shell import getoutput
from .graph import network as network_graph
from . import data
from . import logging
from . import masscan

log = logging.new_log(__name__)

nmap_gnmap_re = _.to_regex(
    r'^Host:\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\((?P<name>.*?)\)\s+'
    r'Ports:\s+(?P<ports>.*?)', re.M
)

def is_nmap_gnmap(path: Path):
    return _.pipe(
        path,
        _.slurp,
        nmap_gnmap_re.search,
        bool,
    )

def is_gnmap(path: Path):
    return masscan.is_gnmap(path) or is_nmap_gnmap(path)

@_.ensure_paths
def parse_nmap_gnmap(path: Path):
    host_re = _.to_regex(r'Host: (?P<ip>[\d.]+?) \((?P<name>.*?)\)')
    ports_re = _.to_regex(r'Ports: ')
    port_re = _.to_regex(
        r'(?P<port>\d+?)/'
        r'(?P<state>.+?)/'
        r'(?P<proto>.+?)/'
        r'(?P<v0>.*?)/'
        r'(?P<guess>.*?)/'
        r'(?P<v1>.*?)/'
        r'(?P<service>.*?)/'
        r'(?P<v2>.*?)'
    )
    os_re = _.to_regex(r'OS: (?P<os>.*)')

    def get_data(line: str):
        for part in line.split('\t'):
            matches = _.juxt(host_re.match, ports_re.match, os_re.match)(part)
            match matches:
                case (None, None, None):
                    continue
                case (host, None, None):
                    yield host.groupdict()
                case (None, ports, None):
                    yield {
                        'ports': _.pipe(
                            port_re.finditer(line),
                            _.map(lambda m: m.groupdict()),
                            _.map(lambda d: _.merge(
                                d, {
                                    'port': int(d['port']),
                                },
                            )),
                            tuple,
                        )
                    }
                case (None, None, os):
                    yield os.groupdict()
            
    return _.pipe(
        path,
        _.slurplines,
        _.grep('Host: .*?Ports: .*?'),
        _.map(get_data),
        _.map(_.merge),
        _.filter(None),
        _.map(_.cmerge({'ip': '', 'name': '', 'ports': []})),
        tuple,
    )

def parse_gnmap(path: Path):
    if masscan.is_gnmap(path):
        return masscan.parse_gnmap(path)
    return parse_nmap_gnmap(path)

def try_parse_xml(command: str, xml_output: str):
    try:
        return xml.etree.ElementTree.fromstring(xml_output)
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        log.error(
            f'Error in command: {command}'
        )
        log.error(exc)
        return xml.etree.ElementTree.Element('')


@_.curry
def nmap(ip_or_range: str, *, ports=None, top_ports=None,
         getoutput=getoutput(echo=False), no_dns=False, force: bool=False,
         syn=False, rate=20000, version=False, tcp=None, udp=False,
         skip_discovery=False, sudo=False, os_discovery=False,
         aggressive=False, output_dir='nmap', stem_prefix=None,
         verbose=False, args=None):
    '''
    Perform an nmap scan of some number of hosts. Checks for previous runs with
    same command arguments, unless --force is given.

    Args:

      ip_or_range (str): Either an IP or an nmap-formatted IP range
        (e.g. 192.168.1.1-10 or CIDR 192.168.1.0/24)

    Optional:

      ports (str, seq, int): Either an nmap-formatted port list (str)
        or a sequence of ports (list/tuple). Default: default nmap behavior

      top_ports (int): Integer designating the N top ports to scan.

      getoutput (function): Function to pass the constructed shell
        command that will run nmap and generate nmap's XML output for the given
        input. Default: subprocess.getoutput

      syn (bool): Should this be a SYN "stealth" scan (implies
        sudo)? Default: False

      version (bool): Should this have a version/banner scan?
        Default: False

      tcp (bool): Should this be a TCP scan? Only relevant if udp is
        set. Default: None

      udp (bool): Should this be a UDP scan? Default: False

      skip_discovery (bool): Skip host discovery, assume host
        exists. Default: False (do host discovery before scan)

      sudo (bool): Run nmap with sudo privileges, automatically set with
        syn or udp. Default: False

      os_discovery (bool): Do OS discovery. Default: False

      aggressive (bool): Do OS discovery, default script scan, version
        scan, and traceroute. Default: False

      output_dir (str): Directory for nmap output to be saved, Default: nmap

      stem_prefix (str): Prefix to add to output filename stem

      verbose (bool): Verbose output?

      args (dict): Extra nmap arguments to pass. Default: None

    '''
    ports_str = ''
    comma_join = _.compose_left(_.map(str), ','.join)
    if ports:
        ports_str = _.pipe(
            ports,
            comma_join if _.is_seq(ports) else _.noop,
            lambda ports: f'-p {ports}',
        )
    elif top_ports:
        ports_str = _.pipe(
            top_ports,
            int,
            data.top_ports,
            comma_join,
            lambda ports: f'-p {ports}',
        )
    else:
        ports_str = ''

    args_str = ''
    if _.is_dict(args):
        args_str = _.pipe(
            args.items(),
            _.vmap(lambda key, val: f'-{key} {val}'),
            ' '.join,
        )

    aggressive = '-A' if aggressive else ''
    syn = '-sS' if syn else ''
    probe = '-Pn' if skip_discovery else ''
    version = '-sV' if version and not aggressive else ''
    os_discovery = '-O' if os_discovery and not aggressive else ''
    tcp = '-sT' if tcp is not None and tcp else ''
    udp = '-sU' if udp else ''
    verbose = '-v' if verbose else ''
    no_dns = '-n' if no_dns else ''

    output_stem = ip_or_range.replace('/', '_')
    if stem_prefix:
        output_stem = f'{stem_prefix}-{output_stem}'

    output_dir_path = Path(output_dir).expanduser()

    normal_path = output_dir_path / (output_stem + '.nmap')
    gnmap_path = output_dir_path / (output_stem + '.gnmap')
    xml_path = output_dir_path / (output_stem + '.xml')

    output = f'-oX {xml_path} -oG {gnmap_path} -oN {normal_path} '

    need_sudo = syn or udp or os_discovery or sudo
    nmap_command = 'sudo nmap' if need_sudo else 'nmap'
    
    command = _.pipe(
        f'{nmap_command} {ports_str} {syn} {version} {tcp} {udp}'
        f' {os_discovery} {aggressive} {no_dns} {probe} {verbose} {args_str}'
        f' {output} -noninteractive {ip_or_range} ',
        shlex.split,            # clean up extra whitespace
        ' '.join,
    )

    finished_name = _.pipe(
        [output_stem, _.md5(command), ],
        '-'.join,
    )
    finished_path: Path = output_dir_path / '.done' / finished_name
    if finished_path.exists() and not force:
        log.warning(
            f'Previous run detected for {ip_or_range}... skipping.'
            ' Use --force to force a re-run.'
        )
        return try_parse_xml(command, xml_path.read_text())

    def shorten(s):
        if len(s) > 500:
            return s[:250] + ' [...] ' + s[-250:]
        return s
    log.info(f'[nmap] command: {shorten(command)}')

    getoutput(command)

    # write finished file
    log.info(
        f'Writing out finish file: {finished_path}'
    )
    finished_path.parent.mkdir(exist_ok=True, parents=True)
    finished_path.write_text('')
    
    xml_output = xml_path.read_text()

    return _.pipe(
        xml_output,
        lambda xml: (xml, try_parse_xml(command, xml)),
        # xmljson.BadgerFish(dict_type=dict).data,
        # xmljson.Parker(dict_type=dict).data,
        lambda t: {
            'xml': t[0],
            'dict': xmljson.Yahoo(dict_type=dict).data(t[1])
        },
        lambda d: _.merge(
            d, {'dict': d['dict'].get('nmaprun', {})}
        ),
    )

nmap_http = nmap(ports=[80, 443, 8080, 8443])
nmap_ssh = nmap(ports=[22, 2222, 22222])
nmap_smb = nmap(ports=[445, 139])
nmap_aggressive = nmap(aggressive=True)
nmap_banner = nmap(version=True)
nmap_os = nmap(os_discovery=True)
nmap_smb_os = nmap(ports=[445, 65535], os_discovery=True)
nmap_fingerprint = nmap(aggressive=True, version=True, os_discovery=True)
nmap_all = nmap(ports='1-65535', syn=True)

# @_.curry
# def cached_nmap(output_dir: Union[str, Path], host: str, *,
#                 prefix='', force=False, **nmap_kw):
#     '''Run nmap, where output is saved in an output dir by hostname and
#     only run if that file does not exist

#     '''
#     root = Path(output_dir).expanduser()
#     path_stem = f'{prefix}{host}'
#     json_path = Path(root, f'{path_stem}.json')
#     xml_path = Path(root, f'{path_stem}.xml')
#     normal_path = Path(root, f'{path_stem}.txt')
#     if json_path.exists() and normal_path.exists() and not force:
#         log.info(
#             f'[cached_nmap] {json_path} exists, skipping...'
#         )
#         return json.loads(json_path.read_text())
#     if force:
#         log.info('[cached_nmap] FORCE rerunning nmap')

#     output = nmap(host, **_.merge(
#         {'output': normal_path},
#         nmap_kw,
#     ))
#     json_path.write_text(json.dumps(output['dict'], indent=2))
#     xml_path.write_text(output['xml'])
#     return output['dict']
    

get_num_hosts = _.compose(_.maybe_int, _.jmes('runstats.hosts.up'))

def parse_address(address: dict):
    return _.merge(
        address,
        {'addr': address.get('addr'),
         'vendor': address.get('vendor', Nothing())},
    )

def parse_addresses(host: dict):
    address = host['address']
    if _.is_seq(address):
        return _.merge(
            {'ipv4': Nothing()},
            {a['addrtype']: parse_address(a) for a in address},
        )
    return _.merge(
        {'ipv4': Nothing()},
        {address['addrtype']: parse_address(address)},
    )

def parse_host(host: dict):
    return _.pipe(
        host,
        _.update_if_key_exists(
            'address', lambda h: parse_addresses(h)
        ),
    )

def get_hosts(nmap):
    if not nmap:
        return Nothing()
    nhosts = get_num_hosts(nmap)

    if nhosts == 1:
        yield _.pipe(
            nmap,
            _.jmes('host'),
            parse_host,
        )
    elif nhosts > 1:
        yield from _.pipe(
            nmap,
            _.jmes('host'),
            _.map(parse_host),
        )

def process_script_node(node):
    if _.is_seq(node):
        return _.pipe(node, _.map(process_script_node), dict)
    if _.is_dict(node):
        if 'content' in node:
            return (node['key'], node['content'])
        if 'elem' in node:
            if _.is_dict(node['elem']):
                nodes = [node['elem']]
            else:
                nodes = node['elem']
            return process_script_node(nodes)
        if 'table' in node:
            if _.is_dict(node['table']):
                nodes = [node['table']]
            else:
                nodes = node['table']
            return _.map(nodes, process_script_node, tuple)

class Service:
    def __init__(self, data):
        self.data = data
        self.port = data['portid']
        self.protocol = data['protocol']
        self.state = data['state']
        
        service = defaultdict(str)
        service.update(data.get('service', {}))
        self.name = service['name']
        self.product = service['product']
        self.version = service['version']
        self.method = service['method']
        self.conf = _.maybe_int(service['conf'], service['conf'])
        self.tunnel = service['tunnel']
        self.os = service['ostype']

        self.scripts = tuple(get_scripts(data))

    def __getitem__(self, key):
        return self.data[key]

    def __repr__(self):
        return (
            f'<Service {self.port:<6}{self.name:<16}\t'
            f'{self.product:<25}\t{self.version:<6}>'
        )

    @property
    def open(self):
        return self.state['state'] == 'open'

def get_scripts(port):
    scripts = port.get('script', [])
    if _.is_seq(scripts):
        yield from _.pipe(
            scripts,
            _.map(lambda s: (s['id'], s)),
        )
    elif _.is_dict(scripts):
        yield (scripts['id'], scripts)

def get_services(host):
    services = host.get('ports', {}).get('port', [])
    if _.is_dict(services):
        services = [services]
    return _.pipe(
        services,
        _.map(Service),
        tuple,
    )

def get_open_services(host):
    return _.pipe(
        get_services(host),
        _.filter(lambda s: s.open),
        tuple,
    )

def parse_elem(elem):
    if _.is_seq(elem):
        if _.is_dict(elem[0]):
            if 'key' in elem[0] and 'content' in elem[0]:
                return ('dict', {
                    e.get('key', ''): e.get('content', '') for e in elem
                })
        else:
            return ('tuple', _.pipe(elem, tuple))
    elif _.is_dict(elem):
        if 'key' in elem and 'content' in elem:
            return ('dict', {elem['key']: elem['content']})
    return ('str', elem)

def parse_table(table):
    if _.is_dict(table):
        return ('dict', {table['key']: parse_elem(table['elem'])})
    elif _.is_seq(table):
        return ('dict', {
            r['key']: parse_elem(r['elem']) for r in table
        })
    return None

def parse_script(script):
    key_funcs = {
        'output': _.do_nothing,
        'elem': parse_elem,
        'table': parse_table,
    }

    processed = _.pipe(
        script,
        _.itemmap(_.vcall(
            lambda k, v: (k, key_funcs.get(k, lambda v: None)(v))
        )),
        _.valfilter(lambda v: v),
    )

    new = {
        'output': processed.get('output', ''),
    }
        
    if 'elem' in processed and 'table' in processed:
        (etype, elem), (ttype, table) = _.pipe(
            ['elem', 'table'],
            _.map(processed.get),
        )
        return _.merge(new, {
            'data': {
                'elem': elem,
                'table': table,
            },
        })

    if 'elem' in processed:
        etype, elem = processed['elem']
        return _.merge(new, {
            'data': elem
        })

    if 'table' in processed:
        ttype, table = processed['table']
        return _.merge(new, {
            'data': table,
        })

    return new

def get_hostscripts(host):
    scripts = _.jmes('hostscript.script', host)
    if scripts:
        try:
            if _.is_dict(scripts):
                return {scripts['id']: parse_script(scripts)}
            elif _.is_seq(scripts):
                return {
                    s['id']: parse_script(s) for s in scripts
                }
        except:
            _.pipe(host, _.no_pyrsistent, pprint.pformat, log.error)
            raise
    return {}
        
def get_os_guesses(host):
    smb_guess = _.pipe(
        get_hostscripts(host),
        _.jmes('"smb-os-discovery".data.os'),
    )
    
    if smb_guess:
        yield {'name': smb_guess, 'accuracy': 100}
            
    if 'os' in host:
        os_data = host['os'].get('osmatch')
        if not os_data:
            log.debug(f"no os data:\n{pprint.pformat(host['os'])}")
            yield {}
        if _.is_seq(os_data):
            yield from os_data
        elif _.is_dict(os_data):
            yield os_data
        else:
            yield {'name': str(os_data)}
    else:
        yield {}

def get_likely_os(host):
    return _.maybe_pipe(
        get_os_guesses(host),
        # tuple,
        # _.do(print),
        _.maybe_first,
        _.jmes('name'),
    )

'''
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
2701/tcp open  cmrcservice   Microsoft Configuration Manager Remote Control service (CmRcService.exe)
3389/tcp open  ms-wbt-server Microsoft Terminal Services    
'''
def get_port(data):
    try:
        data = _.merge(data, {
            'port': int(data['portid']),
            'open_bool': data['state']['state'] == 'open',
            'open': data['state']['state'],
        })
    except:
        print(data)
        raise
    
    service = defaultdict(str)
    service.update(data.get('service', {}))
    extra = f"({service['extrainfo']})" if service['extrainfo'] else ''
    name_parts = _.pipe(
        [data['port'], data['protocol'], data['open'], service['name'],
         f"{service['product']} {service['version']} {extra}",
         service['ostype'], service['method']],
        #_.map(lambda v: v or ''),
        _.map(str),
    )
    
    return _.merge(data, {
        'name': '\t'.join(name_parts),
    })

def get_ports(host):
    ports = host.get('ports', {}).get('port', [])
    if isinstance(ports, dict):
        ports = [ports]
    return _.pipe(
        ports,
        _.map(get_port),
        tuple,
    )

def get_ip(host):
    try:
        return parse_addresses(host)['ipv4']['addr']
        return host.get('address', {}).get('addr', 'No IP given')
    except:
        log.exception(pprint.pformat(host))
        raise

def get_hostnames(host):
    if 'hostnames' in host:
        hostnames = host['hostnames']
        if _.is_dict(hostnames):
            name = hostnames.get('hostname', {}).get('name')
            if name:
                yield name

def get_first_hostname(host):
    return (
        _.maybe_first(get_hostnames(host)) or get_ip(host)
    )

def get_hosts(nmap):
    if not nmap:
        return

    nhosts = get_num_hosts(nmap)
    if not nhosts:
        return
    #log.info(f'nhosts: {nhosts}')
    #log.info((nmap['host']))
    if nhosts == 1:
        yield nmap['host']
    elif nhosts > 1:
        yield from nmap['host']
        
def get_services_from_nmap_dict(nmap: dict):
    return _.pipe(
        get_hosts(nmap),
        tuple,
        _.mapcat(lambda h: [(
            get_ip(h),
            get_first_hostname(h),
            p['name'],
        ) for p in get_ports(h)]),
        tuple,
    )

dict_hash = _.dict_hash(hashlib.md5)

def graph(yaml_path: T.Union[str, Path]):
    path = Path(yaml_path).expanduser()
    log.info(f'   ... reading: {path}')
    data = yaml.read_yaml(path)

    nt = network_graph.node_types

    G = nx.DiGraph()

    @_.curry
    def jmes(host, search):
        return _.jmes(search, host)

    hosts = tuple(get_hosts(data))
    for host in hosts:
        j = jmes(host)

        host_id = f'host_{dict_hash(host)}'

        host_attrs = _.merge(host, {
            'state': j('status.state') == 'up',
        })

        ip = j('address.ipv4.addr') or j('address.ipv6.addr')
        G.add_node(
            ip, type=nt.ip, **host_attrs
        )

        hostnames = _.pipe(
            get_hostnames(host),
            _.mapcat(lambda h: set((h, h.upper(), h.lower()))),
            tuple,
        )
        for i, name in enumerate(hostnames):
            G.add_node(name, type=nt.hostname)
            G.add_edge(ip, name)
            G.add_edge(name, ip)

        # host findings i.e. hostscripts
        for sid, script in get_hostscripts(host).items():
            G.add_node(sid, type=nt.finding)
            G.add_edge(ip, sid, **script)
            G.add_edge(sid, ip)

        # OS fingerprints
        for i, os in enumerate(get_os_guesses(host)):
            certainty = _.pipe(
                os.get('accuracy', 0),
                _.maybe_float(default=0),
            )
            os_id = os.get('name', 'Unknown OS')
            G.add_node(os_id, type=nt.fingerprint, **os)
            G.add_edge(ip, os_id, rank=i, certainty=certainty)
            G.add_edge(os_id, ip)

        # # Host findings
        # for vuln in host.get('tests', []):
        #     vuln_id = vuln['id']
        #     G.add_edge(ip, vuln_id, **vuln_edge(vuln))
        G.nodes[ip]['os'] = get_likely_os(host) or 'Unknown OS'

        # Service endpoints
        for i, service in enumerate(get_open_services(host)):
            # Ports
            port = int(service.port)
            G.add_node(port, type=nt.port)
            G.add_edge(ip, port, protocol=service.protocol)
            if service.product:
                G.add_node(service.product, type=nt.service)
                # G.add_edge(ip, service.product)
                G.add_edge(port, service.product)

            for sid, script in service.scripts:
                finding_id = sid
                G.add_node(finding_id, type=nt.finding, **script)
                G.add_edge(ip, finding_id)
                G.add_edge(port, finding_id)

    return G

def graph_from_yml(path):
    return network_graph.new_graph(graph(path))

def graph_from_dirs(*dir_paths):
    return _.pipe(
        dir_paths,
        _.map(lambda d: Path(d).expanduser()),
        tuple,
        _.do(lambda dirs: 'Reading YAML from dirs:\n{yaml.dump(dirs)}'),
        _.mapcat(lambda d: d.glob('*.yml')),
        # _.map(graph),
        parallel.thread_map(graph),
        nx.compose_all,
        network_graph.new_graph,
    )

def yaml_from_dirs(*dir_paths):
    return _.pipe(
        dir_paths,
        _.map(lambda d: Path(d).expanduser()),
        tuple,
        _.do(
            lambda dirs: log.info(
                f'Retrieving YAML from dirs:\n{yaml.dump(dirs)}'
            )
        ),
        _.mapcat(lambda d: d.glob('*.yml')),
        tuple,
    )

