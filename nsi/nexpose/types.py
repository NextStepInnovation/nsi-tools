from pathlib import Path
import typing as T

from .. import logging
from ..toolz import *

log = logging.new_log(__name__)

Url = T.NewType('Url', str)
Ip = T.NewType('Ip', str)
IpList = T.Sequence[Ip]
Regex = T.NewType('Regex', str)
RegexList = T.Sequence[Regex]
Mac = T.NewType('Mac', str)
Port = T.NewType('Port', int)
Protocol = T.NewType('Protocol', str)
Timestamp = T.NewType('Timestamp', str)
Int = T.NewType("Int", str)
Float = T.NewType('Float', str)
Html = T.NewType('Html', str)

class Link(T.TypedDict):
    href: Url
    rel: str


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
    links: T.Sequence[Link]
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
    links: T.Sequence[Link]


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
    links: T.Sequence[Link]
    name: TagName
    riskModifier: float
    searchCriteria: SearchCriteria
    source: str
    type: str


class VulnerabilityCvss(T.TypedDict):
    links: T.Sequence[Link]
    v2: VulnerabilityCvssV2
    v3: VulnerabilityCvssV3


class Service(T.TypedDict):
    configurations: T.Sequence[Configuration]
    databases: T.Sequence[Database]
    family: str
    links: T.Sequence[Link]
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
    links: T.Sequence[Link]
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
    links: T.Sequence[Link]
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
    links: T.Sequence[Link]
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

class ScanEngine(T.TypedDict):
    address: str
    contentVersion: str
    enginePools: T.Sequence[int]
    id: int
    lastRefreshedDate: str
    lastUpdatedDate: str
    links: T.Sequence[Link]
    name: str
    port: Port
    productVersion: str
    sites: T.Sequence[int]

ScanEngineNexposeId = T.NewType('ScanEngineNexposeId', int)
ScanEngineId = T.Union[str, ScanEngineNexposeId]
ScanEngineMap = T.Dict[ScanEngineId, ScanEngine]

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
    links: T.Sequence[Link]
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
    links: T.Sequence[Link]
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
    links: T.Sequence[Link]
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

