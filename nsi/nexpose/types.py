from pathlib import Path
import typing as T
import pprint

from .. import logging
from ..toolz import *

log = logging.new_log(__name__)

# Url = T.NewType('Url', str)
# Ip = T.NewType('Ip', str)
# IpList = T.Sequence[Ip]
# Regex = T.NewType('Regex', str)
# RegexList = T.Sequence[Regex]
# Mac = T.NewType('Mac', str)
# Port = T.NewType('Port', int)
# Protocol = T.NewType('Protocol', str)
# Timestamp = T.NewType('Timestamp', str)
# Int = T.NewType("Int", str)
# Float = T.NewType('Float', str)
# Html = T.NewType('Html', str)
# ErrorJson = T.NewType('ErrorJson', dict)

from ..types import (
    Url, Ip, IpList, Regex, RegexList, Mac, Port, Protocol, Timestamp, 
    Int, Float, Html, ErrorJson,
)

class Link(T.TypedDict):
    href: Url
    rel: str

LinkList = T.Sequence[Link]


class Vulnerabilities(T.TypedDict):
    critical: int
    moderate: int
    severe: int
    total: int


class SwaggerSearchCriteriaFilter(T.TypedDict):
    field: str
    lower: str
    operator: str
    upper: str
    value: str
    values: T.Sequence[str]


class CreateAuthenticationSource(T.TypedDict):
    type: str


class UserCreateRole(T.TypedDict):
    allAssetGroups: bool
    allSites: bool
    id: str
    superuser: bool


class VulnerabilityCvssV2(T.TypedDict):
    accessComplexity: str
    accessVector: str
    authentication: str
    availabilityImpact: str
    confidentialityImpact: str
    exploitScore: float
    impactScore: float
    integrityImpact: str
    score: float
    vector: str


class VulnerabilityCvssV3(T.TypedDict):
    attackComplexity: str
    attackVector: str
    availabilityImpact: str
    confidentialityImpact: str
    exploitScore: float
    impactScore: float
    integrityImpact: str
    privilegeRequired: str
    scope: str
    score: float
    userInteraction: str
    vector: str


class ContentDescription(T.TypedDict):
    html: str
    text: str


class PCI(T.TypedDict):
    adjustedCVSSScore: int
    adjustedSeverityScore: int
    fail: bool
    specialNotes: str
    status: str


class SharedCredentialAccount(T.TypedDict):
    authenticationType: str
    communityName: str
    database: str
    domain: str
    enumerateSids: bool
    notesIDPassword: str
    ntlmHash: str
    oracleListenerPassword: str
    password: str
    pemKey: str
    permissionElevation: str
    permissionElevationPassword: str
    permissionElevationUserName: str
    privacyPassword: str
    privacyType: str
    privateKeyPassword: str
    realm: str
    service: str
    sid: str
    useWindowsAuthentication: bool
    username: str


class Address(T.TypedDict):
    ip: Ip
    mac: Mac


class Configuration(T.TypedDict):
    name: str
    value: str


class Database(T.TypedDict):
    description: str
    id: int
    name: str


class AssetHistory(T.TypedDict):
    date: str
    description: str
    scanId: int
    type: str
    user: str
    version: int
    vulnerabilityExceptionId: int


class HostName(T.TypedDict):
    name: str
    source: str


class UniqueId(T.TypedDict):
    id: str
    source: str


OperatingSystemCpe = T.TypedDict('OperatingSystemCpe', {
    'edition': str,
    'language': str,
    'other': str,
    'part': str,
    'product': str,
    'swEdition': str,
    'targetHW': str,
    'targetSW': str,
    'update': str,
    'v2.2': str,
    'v2.3': str,
    'vendor': str,
    'version': str,
})


class GroupAccount(T.TypedDict):
    id: int
    name: str


class UserAccount(T.TypedDict):
    fullName: str
    id: int
    name: str


class WebPage(T.TypedDict):
    linkType: str
    path: str
    response: int


SoftwareCpe = T.TypedDict('SoftwareCpe', {
    'edition': str,
    'language': str,
    'other': str,
    'part': str,
    'product': str,
    'swEdition': str,
    'targetHW': str,
    'targetSW': str,
    'update': str,
    'v2.2': str,
    'v2.3': str,
    'vendor': str,
    'version': str,
})


class AssetVulnerabilities(T.TypedDict):
    critical: int
    exploits: int
    malwareKits: int
    moderate: int
    severe: int
    total: int


class ReportConfigDatabaseCredentialsResource(T.TypedDict):
    password: str
    username: str


ReportEmailSmtp = T.TypedDict('ReportEmailSmtp', {
    'global': bool,
    'relay': str,
    'sender': str,
})


class RepeatSchedule(T.TypedDict):
    dayOfWeek: str
    every: str
    interval: int
    lastDayOfMonth: bool
    weekOfMonth: int


class ReportConfigScopeResource(T.TypedDict):
    assetGroups: T.Sequence[int]
    assets: T.Sequence[int]
    scan: int
    sites: T.Sequence[int]
    tags: T.Sequence[int]


class ReportStorage(T.TypedDict):
    location: str
    path: str


class SearchCriteria(T.TypedDict):
    filters: T.Sequence[SwaggerSearchCriteriaFilter]
    match: str


class LocalePreferences(T.TypedDict):
    default: str
    links: LinkList
    reports: str


class SharedCredential(T.TypedDict):
    account: SharedCredentialAccount
    description: str
    hostRestriction: str
    id: int
    name: str
    portRestriction: int
    siteAssignment: str
    sites: T.Sequence[int]


class File(T.TypedDict):
    attributes: T.Sequence[Configuration]
    name: str
    size: int
    type: str


class WebApplication(T.TypedDict):
    id: int
    pages: T.Sequence[WebPage]
    root: str
    virtualHost: str


class ReportConfigDatabaseResource(T.TypedDict):
    credentials: ReportConfigDatabaseCredentialsResource
    host: str
    name: str
    port: Port
    vendor: str


class ReportEmail(T.TypedDict):
    access: str
    additional: str
    additionalRecipients: T.Sequence[str]
    assetAccess: bool
    owner: str
    smtp: ReportEmailSmtp


class ReportConfigCategoryFilters(T.TypedDict):
    excluded: T.Sequence[str]
    included: T.Sequence[str]
    links: LinkList


class ReportFrequency(T.TypedDict):
    nextRuntimes: T.Sequence[str]
    repeat: RepeatSchedule
    start: str



class OperatingSystem(T.TypedDict):
    architecture: str
    configurations: T.Sequence[Configuration]
    cpe: OperatingSystemCpe
    description: str
    family: str
    id: int
    product: str
    systemName: str
    type: str
    vendor: str
    version: str


class Software(T.TypedDict):
    configurations: T.Sequence[Configuration]
    cpe: SoftwareCpe
    description: str
    family: str
    id: int
    product: str
    type: str
    vendor: str
    version: str


class ReportConfigFiltersResource(T.TypedDict):
    categories: ReportConfigCategoryFilters
    severity: str
    statuses: T.Sequence[str]

TagName = T.NewType('TagName', str)
TagList = T.Sequence[TagName]
TagNexposeId = T.NewType('TagNexposeId', int)
TagId = T.Union[str, TagNexposeId]

class Tag(T.TypedDict):
    color: str
    created: str
    id: TagNexposeId
    links: LinkList
    name: TagName
    riskModifier: float
    searchCriteria: SearchCriteria
    source: str
    type: str


class VulnerabilityCvss(T.TypedDict):
    links: LinkList
    v2: VulnerabilityCvssV2
    v3: VulnerabilityCvssV3


class Service(T.TypedDict):
    configurations: T.Sequence[Configuration]
    databases: T.Sequence[Database]
    family: str
    links: LinkList
    name: str
    port: Port
    product: str
    protocol: Protocol
    userGroups: T.Sequence[GroupAccount]
    users: T.Sequence[UserAccount]
    vendor: str
    version: str
    webApplications: T.Sequence[WebApplication]


# -----------------------------------------------------------------------------
# Vulnerability (i.e. finding)
# -----------------------------------------------------------------------------

VulnerabilityNexposeId = T.NewType('VulnerabilityNexposeId', str)
VulnerabilityId = VulnerabilityNexposeId

class Vulnerability(T.TypedDict):
    added: str
    categories: T.Sequence[str]
    cves: T.Sequence[str]
    cvss: VulnerabilityCvss
    denialOfService: bool
    description: ContentDescription
    exploits: int
    id: VulnerabilityNexposeId
    links: LinkList
    malwareKits: int
    modified: str
    pci: PCI
    published: str
    riskScore: float
    severity: str
    severityScore: int
    title: str


# -----------------------------------------------------------------------------
# Site
# -----------------------------------------------------------------------------

class Site(T.TypedDict):
    assets: int
    connectionType: str
    description: str
    id: int
    importance: str
    lastScanTime: str
    links: LinkList
    name: str
    riskScore: float
    scanEngine: int
    scanTemplate: str
    type: str
    vulnerabilities: Vulnerabilities

SiteNexposeId = T.NewType('SiteNexposeId', int)
SiteId = T.Union[str, SiteNexposeId]
SiteList = T.Iterable[SiteId]
SiteMap = T.Dict[SiteId, Site]



# -----------------------------------------------------------------------------
# Scan
# -----------------------------------------------------------------------------


class Scan(T.TypedDict):
    assets: int
    duration: str
    endTime: str
    engineId: int
    engineName: str
    id: int
    links: LinkList
    message: str
    scanName: str
    scanType: str
    startTime: str
    startedBy: str
    status: str
    vulnerabilities: Vulnerabilities

ScanNextposeId = T.NewType('ScanNexposeId', int)
ScanId = T.Union[T.Tuple[SiteId, str], ScanNextposeId]
ScanMap = T.Dict[ScanId, Scan]
ScanList = T.Iterable[ScanId]

# -----------------------------------------------------------------------------
# ScanEngine
# -----------------------------------------------------------------------------


class ScanEngine(T.TypedDict):
    address: str
    contentVersion: str
    enginePools: T.Sequence[int]
    id: int
    lastRefreshedDate: str
    lastUpdatedDate: str
    links: LinkList
    name: str
    port: Port
    productVersion: str
    sites: T.Sequence[int]

ScanEngineNexposeId = T.NewType('ScanEngineNexposeId', int)
ScanEngineId = T.Union[str, ScanEngineNexposeId]
ScanEngineMap = T.Dict[ScanEngineId, ScanEngine]

# -----------------------------------------------------------------------------
# ScanTemplate
# -----------------------------------------------------------------------------

class ScanTemplateDatabase(T.TypedDict):
    db2: str # Database name for DB2 database instance.
    links: LinkList
    oracle: T.Sequence[str] # Database name (SID) for an Oracle database instance.
    postgres: str # Database name for PostgesSQL database instance.

class ScanTemplateVulnerabilityCheckCategories(T.TypedDict):
    # The categories of vulnerability checks to disable during a scan.
    disabled: T.Sequence[str]
    # The categories of vulnerability checks to enable during a scan.
    enabled: T.Sequence[str]
    # Hypermedia links to corresponding or related resources.
    links: LinkList

class ScanTemplateVulnerabilityCheckIndividual(T.TypedDict):
    # The individual vulnerability checks to disable during a scan.
    disabled: T.Sequence[str]
    # The individual vulnerability checks to enable during a scan.
    enabled: T.Sequence[str]
    # Hypermedia links to corresponding or related resources.
    links: LinkList

class VulnerabilityCheckType(T.TypedDict):
    # The types of vulnerability checks to disable during a scan.
    disabled: T.Sequence[str]
    # The types of vulnerability checks to enable during a scan.
    enabled: T.Sequence[str]
    # Hypermedia links to corresponding or related resources.
    links: LinkList

JsonApiDefinitionPropertyItem = T.TypedDict(
    'JsonApiDefinitionPropertyItem', {
        'type': str,
        "$ref": str,
    },
)

JsonApiDefinitionProperties = T.TypedDict(
    'JsonApiDefinitionProperties', {
        'type': str,
        'readOnly': bool,
        'description': str,
        'items': JsonApiDefinitionPropertyItem,
        'example': bool | str,
        '$ref': str,
    }
)

class JsonApiDefinition(T.TypedDict):
    type: str
    discriminator: str
    properties: T.Dict[str, JsonApiDefinitionProperties]

class ApiClass(T.TypedDict):
    predicates: T.Sequence['ApiClass']
    name: str
    attributes: T.Sequence[
        T.Tuple[
            str, # name 
            str, # type string
            str, # example str
            str, # description/comment
        ]
    ]

api_class_bp = '''\
{predicates}

class {name}:
{attributes}
'''
def api_class_to_str(api_class: ApiClass):
    def desc_str(example: str, desc: str):
        return pipe(
            concatv(
                desc.splitlines(),
                ['', f'Example: {example}'] if example else [],
            ),
            map(lambda s: f'# {s}'),
            map(lambda s: f'    {s}'),
            '\n'.join,
        )
    
    attributes_str = pipe(
        api_class['attributes'],
        vmap(lambda name, type, example, desc: (
            f'{desc_str(example, desc)}\n'
            f'    {name}: {type}'
        )),
        '\n'.join,
    )
    return api_class_bp.format(
        predicates = pipe(
            api_class['predicates'],
            map(api_class_to_str),
            '\n\n'.join,
        ),
        name=api_class['name'], 
        attributes=attributes_str,
    )

class JsonApi(T.TypedDict):
    definitions: T.Dict[str, JsonApiDefinition]

def api_def_to_class(json_api: JsonApi, def_name: str, 
                     def_list: T.Tuple[T.Tuple[str, ApiClass]]):
    type_map = {
        'string': 'str',
        'integer': 'int',
        'int32': 'int',
        'int64': 'int',
        'boolean': 'bool',
        'number': 'float',
    }
    predicates = []
    match json_api['definitions'][def_name]:
        case {'type': 'object', 'properties': properties}:
            attributes = []
            for prop_name, property in properties.items():
                def_lut: T.Dict[str, ApiClass] = dict(def_list)
                example = property.get('example')
                example = '' if example is None else str(example)
                match property:
                    case {'type': 'array',
                          'description': desc,
                          'items': {'type': array_type}}:
                        attributes.append(
                            (prop_name, 
                             f'T.Sequence[{type_map[array_type]}]',
                             example,
                             desc)
                        )
                    case {'type': 'array', 
                          'description': desc, 
                          'items': {'$ref': "#/definitions/Link"}}:
                        attributes.append(
                            (prop_name, 
                             f'LinkList',
                             example,
                             desc)
                        )
                    case {'type': type, 'description': desc}:
                        attributes.append((
                            prop_name, type_map[type], example, desc
                        ))
                    case {'$ref': ref, 'description': desc}:
                        if ref in def_lut:
                            api_class = def_lut[ref]
                        else:
                            ref_name = ref.split('/')[-1]
                            api_class = api_def_to_class(
                                json_api, ref_name, def_list,
                            )
                            log.info(f'{prop_name} {ref} {ref_name}')
                            def_list = concatv_t(
                                def_list,
                                [(ref, api_class)],
                            )
                            predicates.append(api_class)
                        attributes.append(
                            (prop_name, 
                             api_class['name'],
                             example,
                             desc)
                        )

            return ApiClass({
                'name': def_name,
                'attributes': attributes,
                'predicates': predicates,
            })

            
    
class ScanTemplateVulnerabilityChecks(T.TypedDict):
    # The vulnerability check categories enabled or disabled during a scan.
    categories: ScanTemplateVulnerabilityCheckCategories
    # Whether an extra step is performed at the end of the scan where more trust
    # is put in OS patch checks to attempt to override the results of other
    # checks which could be less reliable.
    correlate: bool 
    # The individual vulnerability checks enabled or disabled during a scan.
    individual: ScanTemplateVulnerabilityCheckIndividual
    # Hypermedia links to corresponding or related resources.
    links: LinkList
    # Whether checks that result in potential vulnerabilities are assessed during a scan.
    potential: bool 
    # The vulnerability check types enabled or disabled during a scan.
    types: None 
    # Whether checks considered "unsafe" are assessed during a scan.    
    unsafe: bool 

class ScanTemplate(T.TypedDict):
    # Settings for which vulnerability checks to run during a scan. 
    # 
    # The rules for inclusion of checks is as follows: 
    #  
    # - Enabled checks by category and by check type are included
    # - Disabled checks in by category and by check type are removed
    # - Enabled checks in by individual check are added (even if they are
    #   disabled in by category or check type)
    # - Disabled checks in by individual check are removed
    # - If unsafe is disabled, unsafe checks are removed
    # - If potential is disabled, potential checks are removed
    checks: None 

    database: ScanTemplateDatabase # Settings for discovery databases.
    description: str # A verbose description of the scan template..
    discovery: None # Discovery settings used during a scan.
    discoveryOnly: bool # Whether only discovery is performed during a scan.
    # Whether Windows services are enabled during a scan. Windows services will
    # be temporarily reconfigured when this option is selected. Original
    # settings will be restored after the scan completes, unless it is
    # interrupted.
    enableWindowsServices: bool 
    # Whether enhanced logging is gathered during scanning. Collection of
    # enhanced logs may greatly increase the disk space used by a scan.
    enhancedLogging: bool 
    id: str # The identifier of the scan template
    links: LinkList
    maxParallelAssets: int 
    # The maximum number of scan processes simultaneously allowed against each
    # asset during a scan.
    maxScanProcesses: int 
    name: str # A concise name for the scan template.
    policy: None # Policy configuration settings used during a scan.
    policyEnabled: bool # Whether policy assessment is performed during a scan.
    telnet: None # Settings for interacting with the Telnet protocol.
    # Whether vulnerability assessment is performed during a scan.
    vulnerabilityEnabled: bool 
    web: None # Web spider settings used during a scan.
    # Whether web spidering and assessment are performed during a scan.
    webEnabled: bool 

ScanTemplateNexposeId = T.NewType('ScanTemplateNexposeId', int)
ScanTemplateId = T.Union[str, ScanTemplateNexposeId]
ScanTemplateMap = T.Dict[ScanTemplateId, ScanTemplate]

# -----------------------------------------------------------------------------
# Asset
# -----------------------------------------------------------------------------


class Asset(T.TypedDict):
    addresses: T.Sequence[Address]
    assessedForPolicies: bool
    assessedForVulnerabilities: bool
    configurations: T.Sequence[Configuration]
    databases: T.Sequence[Database]
    files: T.Sequence[File]
    history: T.Sequence[AssetHistory]
    hostName: str
    hostNames: T.Sequence[HostName]
    id: int
    ids: T.Sequence[UniqueId]
    ip: Ip
    links: LinkList
    mac: Mac
    os: str
    osFingerprint: OperatingSystem
    rawRiskScore: float
    riskScore: float
    services: T.Sequence[Service]
    software: T.Sequence[Software]
    type: str
    userGroups: T.Sequence[GroupAccount]
    users: T.Sequence[UserAccount]
    vulnerabilities: AssetVulnerabilities

AssetNextposeId = T.NewType('AssetNexposeId', int)

AssetId = T.Union[Ip, AssetNextposeId]
AssetList = T.Iterable[AssetId]
AssetMap = T.Dict[AssetId, Asset]

# -----------------------------------------------------------------------------
# User
# -----------------------------------------------------------------------------

class User(T.TypedDict):
    authentication: CreateAuthenticationSource
    email: str
    enabled: bool
    id: int
    links: LinkList
    locale: LocalePreferences
    locked: bool
    login: str
    name: str
    password: str
    passwordResetOnLogin: bool
    role: UserCreateRole

UserNexposeId = T.NewType('UserNexposeId', int)
UserId = T.Union[UserNexposeId, str]

# -----------------------------------------------------------------------------
# Report
# -----------------------------------------------------------------------------

class Report(T.TypedDict):
    bureau: str
    component: str
    database: ReportConfigDatabaseResource
    email: ReportEmail
    enclave: str
    filters: ReportConfigFiltersResource
    format: str
    frequency: ReportFrequency
    id: int
    language: str
    links: LinkList
    name: str
    organization: str
    owner: int
    policy: int
    query: str
    scope: ReportConfigScopeResource
    storage: ReportStorage
    template: str
    timezone: str
    users: T.Sequence[int]
    version: str

ReportNexposeId = T.NewType('ReportNexposeId', int)
ReportId = T.Union[ReportNexposeId, str]
ReportList = T.Iterable[ReportId]
ReportMap = T.Dict[ReportId, Report]

