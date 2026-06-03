

from dns.rrset import RRset

from .common import (
    DnsConfig, DnsMessage,
)

class LlmnrMessage(DnsMessage):
    type = 'llmnr'

    def query_to_dict(self, rrset: RRset):
        return {}
    
    def rrset_to_dict(self, rrset: RRset):
        return {}
