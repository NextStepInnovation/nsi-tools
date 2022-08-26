import typing as T
import enum

from requests import Response

from .. import logging
from ..rest import Api
from ..toolz import *

from .api import (
    post_iterator,
)
from .types import (
    Ip,
)

log = logging.new_log(__name__)

class Operators(enum.Enum):
    are = 'are'
    contains = 'contains'
    does_not_contain = 'does-not-contain'
    does_not_include = 'does-not-include'
    ends_with = 'ends-with'
    in_ = 'in'
    in_range = 'in-range'
    includes = 'includes'
    is_ = 'is'
    is_applied = 'is-applied'
    is_between = 'is-between'
    is_earlier_than = 'is-earlier-than'
    is_empty = 'is-empty'
    is_greater_than = 'is-greater-than'
    is_on_or_after = 'is-on-or-after'
    is_on_or_before = 'is-on-or-before'
    is_not = 'is-not'
    is_not_applied = 'is-not-applied'
    is_not_empty = 'is-not-empty'
    is_within_the_last = 'is-within-the-last'
    less_than = 'less-than'
    like = 'like'
    not_contains = 'not-contains'
    not_in = 'not-in'
    not_in_range = 'not-in-range'
    not_like = 'not-like'
    starts_with = 'starts-with'
Ops = Operators

fields = {
    'alternate_address_type': [Ops.in_],
    'container_image': [
        Ops.is_, Ops.is_not, Ops.starts_with, Ops.ends_with, 
        Ops.contains, Ops.does_not_contain, Ops.like, Ops.not_like
    ],
    'container_status': [Ops.is_, Ops.is_not],
    'containers': [Ops.are],
    'criticality_tag': [
        Ops.is_, Ops.is_not, Ops.is_greater_than, Ops.less_than, 
        Ops.is_applied, Ops.is_not_applied,
    ],
    'custom_tag': [
        Ops.is_, Ops.is_not, Ops.starts_with, Ops.ends_with, 
        Ops.contains, Ops.does_not_contain, Ops.is_applied, Ops.is_not_applied
    ],
    'cve': [Ops.is_, Ops.is_not, Ops.contains, Ops.does_not_contain],
    'cvss_access_complexity': [Ops.is_, Ops.is_not],
    'cvss_authentication_required': [Ops.is_, Ops.is_not],
    'cvss_access_vector': [Ops.is_, Ops.is_not],
    'cvss_availability_impact': [Ops.is_, Ops.is_not],
    'cvss_confidentiality_impact': [Ops.is_, Ops.is_not],
    'cvss_integrity_impact': [Ops.is_, Ops.is_not],
    'cvss_v3_confidentiality_impact': [Ops.is_, Ops.is_not],
    'cvss_v3_integrity_impact': [Ops.is_, Ops.is_not],
    'cvss_v3_availability_impact': [Ops.is_, Ops.is_not],
    'cvss_v3_attack_vector': [Ops.is_, Ops.is_not],
    'cvss_v3_attack_complexity': [Ops.is_, Ops.is_not],
    'cvss_v3_user_interaction': [Ops.is_, Ops.is_not],
    'cvss_v3_privileges_required': [Ops.is_, Ops.is_not],
    'host_name': [
        Ops.is_, Ops.is_not, Ops.starts_with, Ops.ends_with, 
        Ops.contains, Ops.does_not_contain, Ops.is_empty, Ops.is_not_empty, 
        Ops.like, Ops.not_like,
    ],
    'host_type': [Ops.in_, Ops.not_in],
    'ip_address': [
        Ops.is_, Ops.is_not, Ops.in_range, Ops.not_in_range, 
        Ops.like, Ops.not_like,
    ],
    'ip_address_type': [Ops.in_, Ops.not_in],
    'last_scan_date': [
        Ops.is_on_or_before, Ops.is_on_or_after, Ops.is_between, 
        Ops.is_earlier_than, Ops.is_within_the_last,
    ],
    'location_tag': [
        Ops.is_, Ops.is_not, Ops.starts_with, Ops.ends_with, 
        Ops.contains, Ops.does_not_contain, Ops.is_applied, Ops.is_not_applied
    ],
    'mobile_device_last_sync_time': [
        Ops.is_within_the_last, Ops.is_earlier_than,
    ],
    'open_ports': [Ops.is_, Ops.is_not, Ops.in_range],
    'operating_system': [
        Ops.contains, Ops.does_not_contain, Ops.is_empty, Ops.is_not_empty,
    ],
    'owner_tag': [
        Ops.is_, Ops.is_not, Ops.starts_with, Ops.ends_with, 
        Ops.contains, Ops.does_not_contain, Ops.is_applied, 
        Ops.is_not_applied,
    ],
    'pci_compliance': [Ops.is_],
    'risk_score': [
        Ops.is_, Ops.is_not, Ops.in_range, Ops.is_greater_than, Ops.less_than,
    ],
    'service_name': [Ops.contains, Ops.does_not_contain],
    'site_id': [Ops.in_, Ops.not_in],
    'software': [Ops.contains, Ops.does_not_contain],
    'vAsset_cluster': [
        Ops.is_, Ops.is_not, Ops.contains, Ops.does_not_contain, 
        Ops.starts_with,
    ],
    'vAsset_datacenter': [Ops.is_, Ops.is_not],
    'vAsset_host_name': [
        Ops.is_, Ops.is_not, Ops.contains, Ops.does_not_contain, 
        Ops.starts_with,
    ],
    'vAsset_power_state': [Ops.in_, Ops.not_in],
    'vAsset_resource_pool_path': [Ops.contains, Ops.does_not_contain],
    'vulnerability_assessed': [
        Ops.is_on_or_before, Ops.is_on_or_after, Ops.is_between, 
        Ops.is_earlier_than, Ops.is_within_the_last,
    ],
    'vulnerability_category': [
        Ops.is_, Ops.is_not, Ops.starts_with, Ops.ends_with, 
        Ops.contains, Ops.does_not_contain,
    ],
    'vulnerability_cvss_v3_score': [Ops.is_, Ops.is_not],
    'vulnerability_cvss_score': [
        Ops.is_, Ops.is_not, Ops.in_range, Ops.is_greater_than, 
        Ops.less_than,
    ],
    'vulnerability_exposures': [Ops.includes, Ops.does_not_include],
    'vulnerability_title': [
        Ops.contains, Ops.does_not_contain, Ops.is_, Ops.is_not, 
        Ops.starts_with, Ops.ends_with,
    ],
    'vulnerability_validated_status': [Ops.are],
}

FieldMatch = T.Tuple[bool, T.Optional[str]]

def get_field(partial_name: str) -> FieldMatch:
    exact_match = pipe(
        fields,
        filter(lambda f: f == partial_name),
        maybe_first
    )
    if exact_match:
        return True, exact_match

    matching = pipe(
        fields,
        filter(startswith(partial_name)),
        tuple,
    )
    if not matching:
        log.error(
            f'Could not find a field matching "{partial_name}"'
        )
        return False, None
    if len(matching) > 1:

        matching_str = pipe(matching, ', '.join)
        log.error(
            f'Found multiple matches for "{partial_name}": {matching_str}'
        )
        return False, None
    return True, matching[0]

FilterMatch = T.Tuple[bool, T.Optional[dict]]

@curry
def search_filter(field: str, values: T.Iterable[str], ) -> FilterMatch:
    success, field = get_field(field)
    if not success:
        pass

def by_ip(api: Api, ip: Ip):
    filters = [
        {'field': 'ip-address', 'value': ip, 'operator': 'is'},
    ]
    return post_iterator(api, ['assets', 'search'], json={
        'match': 'all',
        'filters': filters
    })
