from pathlib import Path
import argparse
import sys
import logging
import cmd
from urllib.request import ProxyHandler, build_opener, Request
import json
from time import sleep
from threading import Thread
import typing as T
from dataclasses import dataclass, field

import click
from impacket import version
from impacket.examples import logger
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.ntlmrelayx.clients import ProtocolClient
from impacket.examples.ntlmrelayx.servers import SMBRelayServer, HTTPRelayServer, WCFRelayServer, RAWRelayServer
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig, parse_listening_ports
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor, TargetsFileWatcher
from impacket.examples.ntlmrelayx.servers.socksserver import SOCKS

from ... import logging
from ...toolz import *

import re

from .common import (
    parse_credentials, parse_listening_ports, parse_target,
)

@dataclass
class Configuration:
    interfaceIp: str = None
    listeningPort: int = None
    domainIp: str = None
    machineAccount: str = None
    machineHashes: str = None
    target: TargetsProcessor = None
    mode: str = None
    redirecthost: str = None
    outputFile: str = None
    attacks: T.Dict[str, ProtocolAttack] = field(default_factory=dict)
    lootdir: str = None
    randomtargets: bool = False
    encoding: str = sys.getdefaultencoding()
    ipv6: bool = False
    remove_mic: bool = False
    disableMulti: bool = False

    command: str = None

    # WPAD options
    wpad_host: str = None
    wpad_auth_num: int = 0
    @property
    def serve_wpad(self):
        return self.wpad_host is not None
    smb2support: bool = False

    # SMB options
    exeFile: str = None
    interactive: bool = False
    enumLocalAdmins: bool = False
    SMBServerChallenge: str = None

    # RPC options
    rpc_mode: str = None
    rpc_use_smb: bool = False
    smbdomain: str = None
    smblmhash: str = None
    smbnthash: str = None
    port_smb: int = 445

    # LDAP options
    dumpdomain: bool = True
    addda: bool = True
    aclattack: bool = True
    validateprivs: bool = True
    escalateuser: str = None

    # MSSQL options
    queries: T.Sequence[str] = field(default_factory=list)

    # Registered protocol clients
    protocolClients: T.Dict[str, ProtocolClient] = field(default_factory=dict)

    # SOCKS options
    runSocks: bool = False
    socksServer: str = None

    # HTTP options
    remove_target: bool = False

    # WebDAV options
    serve_image: bool = False

    # AD CS attack options
    isADCSAttack: bool = False
    template: str = None
    altName: str = None

    # Shadow Credentials attack options
    IsShadowCredentialsAttack: bool = False
    ShadowCredentialsPFXPassword: str = None
    ShadowCredentialsExportType: str = None
    ShadowCredentialsOutfilePath: str = None

    def set_hashes(self, hashes: str):
        self.smblmhash, self.smbnthash = hashes.split(':') if hashes else '', ''

    def set_smb_auth(self, smb_auth: str):
        self.smbdomain, self.smbuser, self.smbpass = parse_credentials(smb_auth)

    def from_click(self, **click_kwargs):
        pass

click_options = compose_left(
    click.option('-v', '--debug', is_flag=True, help='Turn DEBUG output ON'),
    click.option(
        '-t', "--target", help="""
        Target to relay the credentials to, can be an IP, hostname or URL like
        domain/username@host:port. If unspecified, it will relay back to the
        client')
        """
    ),
    click.option(
        '-tf', '--targets-file', help='''
        File that contains targets by hostname or full URL, one per line
        '''
    ),
    click.option(
        '-w', '--watch-targets-file', is_flag=True, help='''
        Watch the target file for changes and update target list automatically
        (only valid with -tf)
        '''),
    click.option(
        '-i','--interactive', is_flag=True, help='''
        Launch an smbclient or LDAP console instead of executing a command after
        a successful relay. This console will listen locally on a tcp port and
        can be reached with for example netcat.
        '''
    ),

    # Interface address specification
    click.option(
        '-ip','--interfaceip', help='''
        IP address of interface to bind SMB and HTTP servers
        '''
    ),

    click.option('--no-smb-server', is_flag=True, help='Disables the SMB server'),
    click.option('--no-http-server', is_flag=True, help='Disables the HTTP server'),
    click.option('--no-wcf-server', is_flag=True, help='Disables the WCF server'),
    click.option('--no-raw-server', is_flag=True, help='Disables the RAW server'),

    click.option(
        '--smb-port', type=int, help='Port to listen on smb server', default=445,
    ),
    click.option(
        '--http-port', default="80", help='''
        Port(s) to listen on HTTP server. Can specify multiple ports by
        separating them with `,`, and ranges with `-`. Ex: `80,8000-8010`
        ''', 
    ),
    click.option(
        '--wcf-port', type=int, help='Port to listen on wcf server', default=9389
    ),  # ADWS
    click.option(
        '--raw-port', type=int, help='Port to listen on raw server', default=6666
    ),

    click.option(
        '--no-multirelay', is_flag=True,
        help='If set, disable multi-host relay (SMB and HTTP servers)'
    ),
    click.option(
        '-ra','--random', is_flag=True, help='Randomize target selection'
    ),
    click.option(
        '-r', '--redirect-server', metavar = 'SMBSERVER', 
        help='Redirect HTTP requests to a file:// path on SMBSERVER'
    ),
    click.option(
        '-l','--lootdir', type=str, default='.', help='''
        Loot directory in which gathered loot such as SAM dumps will be stored
        (default: current directory).
        '''
    ),
    click.option(
        '-of','--output-file', help='''
        Base output filename for encrypted hashes. Suffixes will be added for
        ntlm and ntlmv2'
        '''
    ),
    click.option(
        '--codec', default=sys.getdefaultencoding(), help=f'''
        Sets encoding used (codec) from the target's output (default
        {sys.getdefaultencoding()}). If errors are detected, run chcp.com at the
        target, map the result with
        https://docs.python.org/3/library/codecs.html#standard-encodings and
        then execute ntlmrelayx.py again with -codec and the corresponding codec 
        '''
    ),
    click.option(
        '--smb2-support', is_flag=True, help='SMB2 Support'
    ),
    click.option(
        '--ntlm-challenge', help='''
        Specifies the NTLM server challenge used by the SMB Server (16 hex bytes
        long. eg: 1122334455667788)
        '''
    ),
    click.option(
        '-s', '--socks', is_flag=True, default=False,
        help='Launch a SOCKS proxy for the connection relayed'
    ),
    click.option(
        '-wh','--wpad-host', help='''
        Enable serving a WPAD file for Proxy Authentication attack, setting the
        proxy host to the one supplied.
        '''
    ),
    click.option(
        '-wa', '--wpad-auth-num', type=int, default=1, help='''
        Prompt for authentication N times for clients without MS16-077 installed
        before serving a WPAD file. (default=1)
        '''),
    click.option('-6','--ipv6', is_flag=True, help='Listen on both IPv6 and IPv4'),
    click.option(
        '--remove-mic', is_flag=True, help='Remove MIC (exploit CVE-2019-1040)'
    ),
    click.option(
        '--serve-image', help='''
        local path of the image that will we returned to clients
        '''
    ),
    click.option(
        '-c', '--command', type=str, metavar = 'COMMAND', help='''
        Command to execute on target system (for SMB and RPC). If not specified
        for SMB, hashes will be dumped (secretsdump.py must be in the same
        directory). For RPC no output will be provided.
        '''
    ),

    #SMB arguments
    click.option(
        '-e', '--execute-file', metavar = 'FILE', help='''
        File to execute on the target system. If not specified, hashes will be
        dumped (secretsdump.py must be in the same directory)
        '''
    ),
    click.option(
        '--enum-local-admins', is_flag=True, help='''
        If relayed user is not admin, attempt SAMR lookup to see who is (only
        works pre Win 10 Anniversary)
        '''
    ),

    #RPC arguments
    click.option(
        '--rpc-mode', type=click.Choice(["TSCH"]), default="TSCH", 
        help='Protocol to attack, only TSCH supported'
    ),

    click.option(
        '--rpc-use-smb', is_flag=True,
        help='Relay DCE/RPC to SMB pipes'
    ),
    click.option(
        '--auth-smb', default='', metavar='[domain/]username[:password]',
        help='Use this credential to authenticate to SMB (low-privilege account)'
    ),
    click.option('--hashes-smb', metavar="LMHASH:NTHASH"),
    click.option('--rpc-smb-port', type=int, choices=[139, 445], default=445, 
                 help='Destination port to connect to SMB'),

    #MSSQL arguments
    click.option(
        '-q','--query', multiple=True, metavar = 'QUERY', 
        help='MSSQL query to execute (can specify multiple)'
    ),

    #HTTPS options
    click.option(
        '--machine-account', help='''
        Domain machine account to use when interacting with the domain to grab a
        session key for signing, format is domain/machine_name
        '''
    ),
    click.option('--machine-hashes', action="store", metavar="LMHASH:NTHASH",
                 help='Domain machine hashes, format is LMHASH:NTHASH'),
    click.option('--domain', help='Domain FQDN or IP to connect using NETLOGON'),
    click.option(
        '--remove-target', is_flag=True, help='''
        Try to remove the target in the challenge message (in case CVE-2019-1019
        patch is not installed)
        '''
    ),

    #LDAP options
    click.option(
        '--no-dump', is_flag=True, help='''
        Do not attempt to dump LDAP information
        '''
    ),
    click.option(
        '--no-da', action='store_false', 
        help='Do not attempt to add a Domain Admin'
    ),
    click.option(
        '--no-acl', action='store_false', help='Disable ACL attacks'
    ),
    click.option(
        '--no-validate-privs', action='store_false', help='''
        Do not attempt to enumerate privileges, assume permissions are granted
        to escalate a user via ACL attacks
        '''
    ),
    click.option(
        '--escalate-user', 
        help='Escalate privileges of this user instead of creating a new one'
    ),
    click.option(
        '--add-computer', metavar=('COMPUTERNAME', 'PASSWORD'), nargs=2, 
         help='Attempt to add a new computer account'
    ),
    click.option(
        '--delegate-access', is_flag=True,
        help='Delegate access on relayed computer account to the specified account'
    ),
    click.option(
        '--sid', is_flag=True,
        help='Use a SID to delegate access rather than an account name'
    ),
    click.option(
        '--dump-laps', is_flag=True,
        help='Attempt to dump any LAPS passwords readable by the user'
    ),
    click.option(
        '--dump-gmsa', is_flag=True,
        help='Attempt to dump any gMSA passwords readable by the user'
    ),
    click.option(
        '--dump-adcs', is_flag=True, 
        help='''
        Attempt to dump ADCS enrollment services and certificate templates info
        '''
    ),

    #IMAP options
    click.option(
        '-k', '--keyword', metavar="KEYWORD", default="password", 
        help='''
        IMAP keyword to search for. If not specified, will search for mails
        containing "password"
        '''
    ),
    click.option(
        '-m', '--mailbox', metavar="MAILBOX", default="INBOX", 
        help='Mailbox name to dump. Default: INBOX'
    ),
    click.option(
        '-a','--all', is_flag=True, 
        help='Instead of searching for keywords, dump all emails'
    ),
    click.option(
        '-im', '--imap-max', type=int, default=0, 
        help='Max number of emails to dump (0 = unlimited, default: no limit)'
    ),

    # AD CS options
    click.option(
        '--adcs', is_flag=True, help='Enable AD CS relay attack'
    ),
    click.option(
        '--template', metavar="TEMPLATE", 
        help='''
        AD CS template. Defaults to Machine or User whether relayed account name
        ends with `$`. Relaying a DC should require specifying
        `DomainController`
        '''
    ),
    click.option(
        '--altname', metavar="ALTNAME", help='''
        Subject Alternative Name to use when performing ESC1 or ESC6 attacks.
        '''
    ),

    # Shadow Credentials attack options
    click.option(
        '--shadow-credentials', is_flag=True, help='''
        Enable Shadow Credentials relay attack (msDS-KeyCredentialLink
        manipulation for PKINIT pre-authentication)
        '''
    ),
    click.option(
        '--shadow-target', help='''
        target account (user or computer$) to populate msDS-KeyCredentialLink
        from
        '''
    ),
    click.option(
        '--pfx-password', help='''
        password for the PFX stored self-signed certificate (will be random if
        not set, not needed when exporting to PEM)
        '''
    ),
    click.option(
        '--export-type', type=click.Choice(["PEM", " PFX"]), default="PFX", help='''
        choose to export cert+private key in PEM or PFX (i.e. #PKCS12) (default:
        PFX))
        '''
    ),
    click.option(
        '--cert-outfile-path', help='''
        filename to store the generated self-signed PEM or PFX certificate and
        key
        '''
    ),
    click.option(
        '--mode', type=click.Choice(['RELAY', 'REDIRECT', 'REFLECTION']), help='''
        Mode of relay servers. By default, chosen based on target choice.
        '''
    )
)

class Options(T.TypedDict):
    socks: bool
    execute_file: Path
    command: str
    enum_local_admins: bool
    no_multirelay: bool
    codec: str
    mode: str
    loot_dir: Path
    output_file: Path
    interactive: bool
    ipv6: bool
    smb2_support: bool
    ntlm_challenge: str

    # LDAP
    no_dump: bool
    no_da: bool
    no_acl: bool
    no_validate_privs: bool
    escalate_user: bool
    add_computer: bool
    delegate_access: bool
    dump_laps: bool
    dump_gmsa: bool
    dump_adcs: bool
    sid: bool

    # RPC
    rpc_mode: str
    rpc_use_smb: bool
    auth_smb: str
    hashes_smb: str
    rpc_smb_port: int

    # MSSQL
    query: str

    # IMAP
    keyword: str
    mailbox: str
    all: bool
    imap_max: int

    # WPAD
    wpad_host: str
    wpad_auth_num: int




