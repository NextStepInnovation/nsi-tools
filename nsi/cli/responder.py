import asyncio

from .. import logging
from ..responder.common import new_configuration
from ..responder.servers import serve_async

log = logging.new_log(__name__)

def main():
    logging.setup_logging('debug')
    try:
        asyncio.run(serve_async(new_configuration()))
    except KeyboardInterrupt:
        log.error('KeyboardInterrupt')
    finally:
        log.info('Done')
    

