from pathlib import Path
import ftplib
import socket

from pymaybe import Nothing

from . import toolz as _
from . import logging

log = logging.new_log(__name__)

@_.curry
def connection(host, *a, **kw):
    try:
        conn = ftplib.FTP(host, *a, **kw)
        conn.login()
        return conn
    except socket.timeout:
        log.error(f'Socket timeout connecting to {host}')
    return Nothing()

anon_con = connection(
    user='anonymous', passwd=f'{_.random_user()}@{_.random_user()}.com',
    timeout=3,
)

def get_files(con):
    try:
        out = tuple(con.mlsd())
        log.debug(f'mlsd: {out}')
        return out
    except (ftplib.error_perm, ftplib.error_temp):
        try:
            out = tuple(con.nlst())
            log.debug(f'nlst: {out}')
            return out
        except Exception as error:
            log.exception(f'Exception for {con.host}')
    except:
        log.error(f'Timeout for {con.host}')
    return []

def anon_contents(ip):
    return _.maybe_pipe(
        anon_con(ip),
        get_files,
        tuple,
    ) or ()
