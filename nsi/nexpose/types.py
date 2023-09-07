from pathlib import Path
import typing as T
import pprint
from keyword import iskeyword

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
    Int, Float, Html, ErrorJson, Outcome,
)

# -----------------------------------------------------------------------------
# Nexpose API JSON Swagger parsing functionality
# -----------------------------------------------------------------------------

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

class {name}(T.TypedDict):
{attributes}
'''
api_class_invalid_bp = '''\
{predicates}

{name} = T.TypedDict('{name}', {{
{attributes}
}})
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
    
    any_invalid = pipe(
        api_class['attributes'],
        map(first),
        map(lambda name: not name.isidentifier() or iskeyword(name)),
        any,
    )

    if any_invalid:
        attributes_str = pipe(
            api_class['attributes'],
            vmap(lambda name, type, example, desc: (
                f'{desc_str(example, desc)}\n'
                f"    '{name}': {type},"
            )),
            '\n'.join,
        )
        class_bp = api_class_invalid_bp
    else:
        attributes_str = pipe(
            api_class['attributes'],
            vmap(lambda name, type, example, desc: (
                f'{desc_str(example, desc)}\n'
                f'    {name}: {type}'
            )),
            '\n'.join,
        )
        class_bp = api_class_bp

    return class_bp.format(
        predicates = pipe(
            api_class['predicates'],
            map(api_class_to_str),
            '\n\n'.join,
        ),
        name=api_class['name'], 
        attributes=attributes_str,
    ).replace('\n\n\n\n', '\n\n')

class JsonApi(T.TypedDict):
    definitions: T.Dict[str, JsonApiDefinition]

DefList = T.Tuple[T.Tuple[str, ApiClass]]
def api_def_to_class(json_api: JsonApi, def_name: str, def_list: DefList = ()):
    type_map = {
        'string': 'str',
        'integer': 'int',
        'int32': 'int',
        'int64': 'int',
        'boolean': 'bool',
        'number': 'float',
        'object': 'T.Any',
    }
    match json_api['definitions'][def_name]:
        case {'type': 'object', 'properties': properties}:
            predicates = []
            attributes = []
            for prop_name, property in properties.items():
                def_lut: T.Dict[str, ApiClass] = dict(def_list)
                example = property.get('example')
                example = '' if example is None else str(example)
                desc = property.get('description')
                desc = '' if desc is None else desc

                def check_new_ref(ref: str, def_list: DefList):
                    if ref in def_lut:
                        return def_lut[ref], def_list
                    else:
                        ref_name = ref.split('/')[-1]
                        log.info(f'Generating {prop_name} {ref} {ref_name}')
                        api_class = api_def_to_class(
                            json_api, ref_name, def_list,
                        )
                        predicates.append(api_class)
                        return api_class, concatv_t(
                            def_list,
                            [(ref, api_class)],
                        )

                match property:
                    case {'type': 'array',
                          'items': {'type': array_type}}:
                        attributes.append(
                            (prop_name, 
                             f'T.Sequence[{type_map[array_type]}]',
                             example,
                             desc)
                        )
                    case {'type': 'array', 
                          'items': {'$ref': "#/definitions/Link"}}:
                        attributes.append(
                            (prop_name, 
                             f'LinkList',
                             example,
                             desc)
                        )
                    case {"$ref": "#/definitions/Vulnerabilities"}:
                        attributes.append(
                            (prop_name, 
                             f'Vulnerabilities',
                             example,
                             desc)
                        )
                    case {'type': 'array', 
                          'items': {'$ref': ref}}:
                        api_class, def_list = check_new_ref(ref, def_list)
                        attributes.append(
                            (prop_name,
                             f"T.Sequence[{api_class['name']}]",
                             example,
                             desc)
                        )
                        
                    case {'type': type}:
                        attributes.append((
                            prop_name, type_map[type], example, desc
                        ))
                    case {'$ref': ref}:
                        api_class, def_list = check_new_ref(ref, def_list)
                        attributes.append(
                            (prop_name, 
                             api_class['name'],
                             example,
                             desc)
                        )
                    case unhandled:
                        log.error(
                            f"Could not handle this object:\n{pprint.pformat(unhandled)}"
                        )

            return ApiClass({
                'name': def_name,
                'attributes': attributes,
                'predicates': predicates,
            })



class Link(T.TypedDict):
    href: Url
    rel: str

LinkList = T.Sequence[Link]

class Vulnerabilities(T.TypedDict):
    # The number of critical vulnerabilities.
    # 
    # Example: 16
    critical: int
    # The number of moderate vulnerabilities.
    # 
    # Example: 3
    moderate: int
    # The number of severe vulnerabilities.
    # 
    # Example: 76
    severe: int
    # The total number of vulnerabilities.
    # 
    # Example: 95
    total: int



# -----------------------------------------------------------------------------
# Tag
# -----------------------------------------------------------------------------

class SwaggerSearchCriteriaFilter(T.TypedDict):
    # The filter field for the search criteria.
    field: str
    # The lower value to match in a range criteria.
    lower: str
    # The operator on how to match the search criteria.
    operator: str
    # The upper value to match in a range criteria.
    upper: str
    # The single value to match using the operator.
    value: str
    # An array of values to match using the operator.
    values: T.Sequence[str]


class SearchCriteria(T.TypedDict):
    # Filters used to match assets. See <a href="#section/Responses/SearchCriteria">Search Criteria</a> for more information on the structure and format.
    filters: T.Sequence[SwaggerSearchCriteriaFilter]
    # Operator to determine how to match filters. `all` requires that all filters match for an asset to be included. `any` requires only one filter to match for an asset to be included.
    # 
    # Example: all
    match: str


class Tag(T.TypedDict):
    # The color to use when rendering the tag in a user interface.
    # 
    # Example: default
    color: str
    # The date and time the tag was created.
    # 
    # Example: 2017-10-07T23:50:01.205Z
    created: str
    # The identifier of the tag.
    # 
    # Example: 6
    id: int

    links: LinkList
    # The name (label) of the tab.
    # 
    # Example: Very High
    name: str
    # The amount to adjust risk of an asset tagged with this tag. 
    # 
    # Example: 2.0
    riskModifier: float

    searchCriteria: SearchCriteria
    # The source of the tag.
    # 
    # Example: built-in
    source: str
    # The type of the tag.
    # 
    # Example: criticality
    type: str

TagName = T.NewType('TagName', str)
TagList = T.Sequence[TagName]
TagNexposeId = T.NewType('TagNexposeId', int)
TagId = T.Union[str, TagNexposeId]



# -----------------------------------------------------------------------------
# Vulnerability (i.e. finding)
# -----------------------------------------------------------------------------

VulnerabilityNexposeId = T.NewType('VulnerabilityNexposeId', str)
VulnerabilityId = VulnerabilityNexposeId

class VulnerabilityCvssV2(T.TypedDict):
    # Access Complexity (AC) component which measures the complexity of the attack required to exploit the vulnerability once an attacker has gained access to the target system. 
    # | Access Complexity       | Description                                                              | 
    # | ----------------------- | ------------------------------------------------------------------------ | 
    # | High (`"H"`)            | Specialized access conditions exist.                                     | 
    # | Medium (`"M"`)          | The access conditions are somewhat specialized.                          | 
    # | Low (`"L"`)             | Specialized access conditions or extenuating circumstances do not exist. |
    # 
    # Example: M
    accessComplexity: str
    # Access Vector (Av) component which reflects how the vulnerability is exploited. 
    # | Access Vector              | Description | 
    # | -------------------------- | ----------- | 
    # | Local (`"L"`)              | A vulnerability exploitable with only local access requires the attacker to have either physical access to the vulnerable system or a local (shell) account. | 
    # | Adjacent Network (`"A"`)   | A vulnerability exploitable with adjacent network access requires the attacker to have access to either the broadcast or collision domain of the vulnerable software. | 
    # | Network (`"N"`)            | A vulnerability exploitable with network access means the vulnerable software is bound to the network stack and the attacker does not require local network access or local access. Such a vulnerability is often termed "remotely exploitable". | 
    # 
    # Example: L
    accessVector: str
    # Authentication (Au) component which measures the number of times an attacker must authenticate to a target in order to exploit a vulnerability. 
    # | Authentication       | Description | 
    # | -------------------- | ----------- | 
    # | Multiple (`"M"`)     | Exploiting the vulnerability requires that the attacker authenticate two or more times, even if the same credentials are used each time. | 
    # | Single (`"S"`)       | The vulnerability requires an attacker to be logged into the system.                                                                     | 
    # | None (`"N"`)         | Authentication is not required to exploit the vulnerability.                                                                             |
    # 
    # Example: N
    authentication: str
    # Availability Impact (A) component which measures the impact to availability of a successfully exploited vulnerability. 
    # | Availability Impact        | Description  | 
    # | -------------------------- | ------------ | 
    # | None (`"N"`)               | There is no impact to the availability of the system. | 
    # | Partial (`"P"`)            | There is reduced performance or interruptions in resource availability. | 
    # | Complete (`"C"`)           | There is a total shutdown of the affected resource. The attacker can render the resource completely unavailable. |
    # 
    # Example: P
    availabilityImpact: str
    # Confidentiality Impact (C) component which measures the impact on confidentiality of a successfully exploited vulnerability. 
    # | Confidentiality Impact     | Description  | 
    # | -------------------------- | ------------ | 
    # | None (`"N"`)               | There is no impact to the confidentiality of the system. | 
    # | Partial (`"P"`)            | There is considerable informational disclosure. Access to some system files is possible, but the attacker does not have control over what is obtained, or the scope of the loss is constrained. | 
    # | Complete (`"C"`)           | There is total information disclosure, resulting in all system files being revealed. The attacker is able to read all of the system's data (memory, files, etc.) | 
    # 
    # Example: P
    confidentialityImpact: str
    # The CVSS exploit score.
    # 
    # Example: 3.3926
    exploitScore: float
    # The CVSS impact score.
    # 
    # Example: 6.443
    impactScore: float
    # Integrity Impact (I) component measures the impact to integrity of a successfully exploited vulnerability. 
    # | Integrity Impact           | Description  | 
    # | -------------------------- | ------------ | 
    # | None (`"N"`)               | There is no impact to the integrity of the system. | 
    # | Partial (`"P"`)            | Modification of some system files or information is possible, but the attacker does not have control over what can be modified, or the scope of what the attacker can affect is limited. | 
    # | Complete (`"C"`)           | There is a total compromise of system integrity. There is a complete loss of system protection, resulting in the entire system being compromised. The attacker is able to modify any files on the target system. |
    # 
    # Example: P
    integrityImpact: str
    # The CVSS score, which ranges from 0-10.
    # 
    # Example: 4.4
    score: float
    # The <a target="_blank" href="https://www.first.org/cvss/v2/guide">CVSS v2</a> vector.
    # 
    # Example: AV:L/AC:M/Au:N/C:P/I:P/A:P
    vector: str


class VulnerabilityCvssV3(T.TypedDict):
    # Access Complexity (AC) component with measures the conditions beyond the attacker's control that must exist in order to exploit the vulnerability. 
    # | Access Complexity      | Description                                                              | 
    # | ---------------------- | ------------------------------------------------------------------------ | 
    # | Low (`"L"`)            | Specialized access conditions or extenuating circumstances do not exist. | 
    # | High (`"H"`)           | A successful attack depends on conditions beyond the attacker's control. |
    # 
    # Example: H
    attackComplexity: str
    # Attack Vector (AV) component which measures context by which vulnerability exploitation is possible. 
    # | Access Vector          | Description                                                              | 
    # | ---------------------- | ------------------------------------------------------------------------ | 
    # | Local (`"L"`)          | A vulnerability exploitable with only local access requires the attacker to have either physical access to the vulnerable system or a local (shell) account. | 
    # | Adjacent (`"A"`)       | A vulnerability exploitable with adjacent network access requires the attacker to have access to either the broadcast or collision domain of the vulnerable software. | 
    # | Network (`"N"`)        | A vulnerability exploitable with network access means the vulnerable software is bound to the network stack and the attacker does not require local network access or local access. Such a vulnerability is often termed "remotely exploitable". | 
    # 
    # Example: N
    attackVector: str
    # Availability Impact (A) measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability. 
    # | Availability Impact        | Description  | 
    # | -------------------------- | ------------ | 
    # | High (`"H"`)               | There is total loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component; this loss is either sustained (while the attacker continues to deliver the attack) or persistent (the condition persists even after the attack has completed). | 
    # | Low (`"L"`)                | There is reduced performance or interruptions in resource availability. Even if repeated exploitation of the vulnerability is possible, the attacker does not have the ability to completely deny service to legitimate users. | 
    # | None (`"N"`)               | There is no impact to availability within the impacted component. |
    # 
    # Example: H
    availabilityImpact: str
    # Confidentiality Impact (C) component which measures the impact on confidentiality of a successfully exploited vulnerability. 
    # | Confidentiality Impact     | Description  | 
    # | -------------------------- | ------------ | 
    # | High (`"H"`)               | There is total loss of confidentiality, resulting in all resources within the impacted component being divulged to the attacker. | 
    # | Low (`"L"`)                | There is some loss of confidentiality. Access to some restricted information is obtained, but the attacker does not have control over what information is obtained, or the amount or kind of loss is constrained. | 
    # | None (`"N"`)               | There is no loss of confidentiality within the impacted component. |
    # 
    # Example: H
    confidentialityImpact: str
    # The CVSS impact score.
    # 
    # Example: 1.6201
    exploitScore: float
    # The CVSS exploit score.
    # 
    # Example: 5.8731
    impactScore: float
    # Integrity Impact (I) measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information. 
    # | Integrity Impact    | Description  | 
    # | ------------------- | ------------ | 
    # | High (`"H"`)        | There is a total loss of integrity, or a complete loss of protection. | 
    # | Low (`"L"`)         | Modification of data is possible, but the attacker does not have control over the consequence of a modification, or the amount of modification is constrained. | 
    # | None (`"N"`)        | There is no loss of integrity within the impacted component. |
    # 
    # Example: H
    integrityImpact: str
    # Privileges Required (PR) measures the level of privileges an attacker must possess before successfully exploiting the vulnerability. 
    # | Privileges Required (PR)     | Description                                                              | 
    # | ---------------------------- | ------------------------------------------------------------------------ | 
    # | None (`"N"`)                 | The attacker is unauthorized prior to attack, and therefore does not require any access to settings or files to carry out an attack. | 
    # | Low (`"L"`)                  | The attacker is authorized with (i.e. requires) privileges that provide basic user capabilities that could normally affect only settings and files owned by a user. | 
    # | High (`"H"`)                 | The attacker is authorized with (i.e. requires) privileges that provide significant (e.g. administrative) control over the vulnerable component that could affect component-wide settings and files. |
    # 
    # Example: N
    privilegeRequired: str
    # Scope (S) measures the collection of privileges defined by a computing authority (e.g. an application, an operating system, or a sandbox environment) when granting access to computing resources (e.g. files, CPU, memory, etc). These privileges are assigned based on some method of identification and authorization. 
    # | Scope (S)            | Description                                                              | 
    # | -------------------- | ------------------------------------------------------------------------ | 
    # | Unchanged (`"U"`)    | An exploited vulnerability can only affect resources managed by the same authority. In this case the vulnerable component and the impacted component are the same. | 
    # | Changed (`"C"`)      | An exploited vulnerability can affect resources beyond the authorization privileges intended by the vulnerable component. In this case the vulnerable component and the impacted component are different. |
    # 
    # Example: U
    scope: str
    # The CVSS score, which ranges from 0-10.
    # 
    # Example: 7.5
    score: float
    # User Interaction (UI) measures the requirement for a user, other than the attacker, to participate in the successful compromise of the vulnerable component. 
    # | User Interaction (UI)        | Description                                                               | 
    # | ---------------------------- | ------------------------------------------------------------------------- | 
    # | None (`"N"`)                 | The vulnerable system can be exploited without interaction from any user. | 
    # | Required (`"R"`)             | Successful exploitation of this vulnerability requires a user to take some action before the vulnerability can be exploited. |
    # 
    # Example: R
    userInteraction: str
    # The <a target="_blank" href="https://www.first.org/cvss/specification-document">CVSS v3</a> vector.
    # 
    # Example: CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H
    vector: str


class VulnerabilityCvss(T.TypedDict):
    # Hypermedia links to corresponding or related resources.
    links: LinkList
    # The Common Vulnerability Scoring System (<a href="https://www.first.org/cvss/v2/guide">CVSS v2</a>) information for the vulnerability.
    v2: VulnerabilityCvssV2
    # The Common Vulnerability Scoring System (<a target="_blank" href="https://www.first.org/cvss/specification-document">CVSS v3</a>) information for the vulnerability.
    v3: VulnerabilityCvssV3


class ContentDescription(T.TypedDict):
    # Hypertext Markup Language (HTML) representation of the content.
    # 
    # Example: A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Microsoft Edge. ...
    html: str
    # Textual representation of the content.
    # 
    # Example: <p>A remote code execution vulnerability exists in the way that the scripting engine handles objects in memory in Microsoft Edge. ...</p>
    text: str


class PCI(T.TypedDict):
    # The CVSS score of the vulnerability, adjusted for PCI rules and exceptions, on a scale of 0-10.
    # 
    # Example: 4
    adjustedCVSSScore: int
    # The severity score of the vulnerability, adjusted for PCI rules and exceptions, on a scale of 0-10.
    # 
    # Example: 3
    adjustedSeverityScore: int
    # Whether if present on a host this vulnerability would cause a PCI failure. `true` if "status" is `"Fail"`, `false` otherwise.
    # 
    # Example: True
    fail: bool
    # Any special notes or remarks about the vulnerability that pertain to PCI compliance.
    specialNotes: str
    # The PCI compliance status of the vulnerability. One of: `"Pass"`, `"Fail"`.
    # 
    # Example: Fail
    status: str


class Vulnerability(T.TypedDict):
    # The date the vulnerability coverage was added. The format is an ISO 8601 date, `YYYY-MM-DD`.
    # 
    # Example: 2017-10-10
    added: str
    # All vulnerability categories assigned to this vulnerability.
    categories: T.Sequence[str]
    # All <a target="_blank" href="https://cve.mitre.org/">CVE</a>s assigned to this vulnerability.
    cves: T.Sequence[str]
    # The CVSS vector(s) for the vulnerability.
    cvss: VulnerabilityCvss
    # Whether the vulnerability can lead to Denial of Service (DoS).
    # 
    # Example: False
    denialOfService: bool
    # The description of the vulnerability.
    description: ContentDescription
    # The exploits that can be used to exploit a vulnerability.
    exploits: int
    # The identifier of the vulnerability.
    # 
    # Example: msft-cve-2017-11804
    id: str
    # Hypermedia links to corresponding or related resources.
    links: LinkList
    # The malware kits that are known to be used to exploit the vulnerability.
    malwareKits: int
    # The last date the vulnerability was modified. The format is an ISO 8601 date, `YYYY-MM-DD`.
    # 
    # Example: 2017-10-10
    modified: str
    # Details the <a target="_blank" href="https://www.pcisecuritystandards.org/">Payment Card Industry (PCI)</a> details of the vulnerability.
    pci: PCI
    # The date the vulnerability was first published or announced. The format is an ISO 8601 date, `YYYY-MM-DD`.
    # 
    # Example: 2017-10-10
    published: str
    # The risk score of the vulnerability, rounded to a maximum of to digits of precision. If using the default Rapid7 Real Risk™ model, this value ranges from 0-1000.
    # 
    # Example: 123.69
    riskScore: float
    # The severity of the vulnerability, one of: `"Moderate"`, `"Severe"`, `"Critical"`.
    # 
    # Example: Severe
    severity: str
    # The severity score of the vulnerability, on a scale of 0-10.
    # 
    # Example: 4
    severityScore: int
    # The title (summary) of the vulnerability.
    # 
    # Example: Microsoft CVE-2017-11804: Scripting Engine Memory Corruption Vulnerability
    title: str



# -----------------------------------------------------------------------------
# Site
# -----------------------------------------------------------------------------

class Site(T.TypedDict):
    # The number of assets that belong to the site.
    # 
    # Example: 768
    assets: int
    # The type of discovery connection configured for the site. This property only applies to dynamic sites.
    connectionType: str
    # The site description.
    description: str
    # The identifier of the site.
    id: int
    # The site importance.
    importance: str
    # The date and time of the site's last scan.
    lastScanTime: str
    # Hypermedia links to corresponding or related resources.
    links: LinkList
    # The site name.
    name: str
    # The risk score (with criticality adjustments) of the site.
    # 
    # Example: 4457823.78
    riskScore: float
    # The identifier of the scan engine configured in the site.
    scanEngine: int
    # The identifier of the scan template configured in the site.
    scanTemplate: str
    # The type of the site.
    type: str
    # Summary information for distinct vulnerabilities found on the assets.
    vulnerabilities: Vulnerabilities


SiteNexposeId = T.NewType('SiteNexposeId', int)
SiteId = T.Union[str, SiteNexposeId]
SiteList = T.Iterable[SiteId]
SiteMap = T.Dict[SiteId, Site]



# -----------------------------------------------------------------------------
# Scan
# -----------------------------------------------------------------------------

class AssetGroup(T.TypedDict):
    # The number of assets that belong to the asset group.
    # 
    # Example: 768
    assets: int
    # The description of the asset group.
    # 
    # Example: Assets with unacceptable high risk required immediate remediation.
    description: str
    # The identifier of the asset group.
    # 
    # Example: 61
    id: int
    # Hypermedia links to corresponding or related resources.
    links: LinkList
    # The name of the asset group.
    # 
    # Example: High Risk Assets
    name: str
    # The total risk score of all assets that belong to the asset group.
    # 
    # Example: 4457823.78
    riskScore: float
    # Search criteria used to determine dynamic membership, if `type` is `"dynamic"`. 
    searchCriteria: SearchCriteria
    # The type of the asset group.
    # 
    # Example: dynamic
    type: str
    # Summary information for distinct vulnerabilities found on the assets.
    vulnerabilities: Vulnerabilities

AssetGroupId = T.Union[str, int]
AssetGroupMap = T.Dict[AssetGroupId, AssetGroup]

class Scan(T.TypedDict):
    # The number of assets found in the scan.
    assets: int
    # The duration of the scan in ISO8601 format.
    duration: str
    # The end time of the scan in ISO8601 format.
    endTime: str
    # The identifier of the scan engine.
    engineId: int
    # The name of the scan engine.
    engineName: str
    # The identifier of the scan.
    id: int
    # Hypermedia links to corresponding or related resources.
    links: LinkList
    # The reason for the scan status.
    message: str
    # The user-driven scan name for the scan.
    scanName: str
    # The scan type (automated, manual, scheduled). 
    scanType: str
    # The start time of the scan in ISO8601 format.
    startTime: str
    # The name of the user that started the scan.
    startedBy: str
    # The scan status.
    status: str
    # The vulnerability synopsis of the scan.
    vulnerabilities: Vulnerabilities

ScanNextposeId = T.NewType('ScanNexposeId', int)
ScanId = T.Union[T.Tuple[SiteId, str], ScanNextposeId]
ScanMap = T.Dict[ScanId, Scan]
ScanList = T.Iterable[ScanId]



# -----------------------------------------------------------------------------
# ScanEngine
# -----------------------------------------------------------------------------

class ScanEngine(T.TypedDict):
    # The address the scan engine is hosted.
    # 
    # Example: corporate-scan-engine-001.acme.com
    address: str
    # The content version of the scan engine.
    contentVersion: str
    # A list of identifiers of engine pools this engine is included in.
    enginePools: T.Sequence[int]
    # The identifier of the scan engine.
    # 
    # Example: 6
    id: int
    # The date the engine was last refreshed. Date format is in ISO 8601.
    lastRefreshedDate: str
    # The date the engine was last updated. Date format is in ISO 8601.
    lastUpdatedDate: str
    # Hypermedia links to corresponding or related resources.
    links: LinkList
    # The name of the scan engine.
    # 
    # Example: Corporate Scan Engine 001
    name: str
    # The port used by the scan engine to communicate with the Security Console.
    # 
    # Example: 40894
    port: int
    # The product version of the scan engine.
    productVersion: str
    # A list of identifiers of each site the scan engine is assigned to.
    sites: T.Sequence[int]

ScanEngineNexposeId = T.NewType('ScanEngineNexposeId', int)
ScanEngineId = T.Union[str, ScanEngineNexposeId]
ScanEngineMap = T.Dict[ScanEngineId, ScanEngine]



# -----------------------------------------------------------------------------
# ScanTemplate
# -----------------------------------------------------------------------------

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


class ScanTemplateVulnerabilityChecks(T.TypedDict):
    # The vulnerability check categories enabled or disabled during a scan.
    categories: ScanTemplateVulnerabilityCheckCategories
    # Whether an extra step is performed at the end of the scan where more trust is put in OS patch checks to attempt to override the results of other checks which could be less reliable.
    # 
    # Example: False
    correlate: bool
    # The individual vulnerability checks enabled or disabled during a scan.
    individual: ScanTemplateVulnerabilityCheckIndividual
    # Hypermedia links to corresponding or related resources.
    links: LinkList
    # Whether checks that result in potential vulnerabilities are assessed during a scan.
    # 
    # Example: False
    potential: bool
    # The vulnerability check types enabled or disabled during a scan.
    types: VulnerabilityCheckType
    # Whether checks considered "unsafe" are assessed during a scan.
    # 
    # Example: False
    unsafe: bool


class ScanTemplateDatabase(T.TypedDict):
    # Database name for DB2 database instance.
    # 
    # Example: database
    db2: str
    # Hypermedia links to corresponding or related resources.
    links: LinkList
    # Database name (SID) for an Oracle database instance.
    # 
    # Example: default
    oracle: T.Sequence[str]
    # Database name for PostgesSQL database instance.
    # 
    # Example: postgres
    postgres: str


class ScanTemplateAssetDiscovery(T.TypedDict):
    # Whether to query Whois during discovery. Defaults to `false`.
    # 
    # Example: False
    collectWhoisInformation: bool
    # The minimum certainty required for a fingerprint to be considered valid during a scan. Defaults to `0.16`.
    # 
    # Example: 0.16
    fingerprintMinimumCertainty: float
    # The number of fingerprinting attempts made to determine the operating system fingerprint. Defaults to `4`.
    # 
    # Example: 0
    fingerprintRetries: int
    # Whether to fingerprint TCP/IP stacks for hardware, operating system and software information.
    # 
    # Example: True
    ipFingerprintingEnabled: bool
    # Whether ARP pings are sent during asset discovery. Defaults to `true`.
    # 
    # Example: True
    sendArpPings: bool
    # Whether ICMP pings are sent during asset discovery. Defaults to `false`.
    # 
    # Example: True
    sendIcmpPings: bool
    # TCP ports to send packets and perform discovery. Defaults to no ports.
    tcpPorts: T.Sequence[int]
    # Whether TCP reset responses are treated as live assets. Defaults to `true`.
    # 
    # Example: True
    treatTcpResetAsAsset: bool
    # UDP ports to send packets and perform discovery. Defaults to no ports.
    udpPorts: T.Sequence[int]


class ScanTemplateDiscoveryPerformancePacketsRate(T.TypedDict):
    # Whether defeat rate limit (defeat-rst-ratelimit) is enforced on the minimum packet setting, which can improve scan speed. If it is disabled, the minimum packet rate setting may be ignored when a target limits its rate of RST (reset) responses to a port scan. This can increase scan accuracy by preventing the scan from missing ports. Defaults to `true`.
    # 
    # Example: True
    defeatRateLimit: bool
    # The minimum number of packets to send each second during discovery attempts. Defaults to `0`.
    # 
    # Example: 15000
    maximum: int
    # The minimum number of packets to send each second during discovery attempts. Defaults to `0`.
    # 
    # Example: 450
    minimum: int


class ScanTemplateDiscoveryPerformanceParallelism(T.TypedDict):
    # The maximum number of discovery connection requests send in parallel. Defaults to `0`.
    # 
    # Example: 0
    maximum: int
    # The minimum number of discovery connection requests send in parallel. Defaults to `0`.
    # 
    # Example: 0
    minimum: int


class ScanTemplateDiscoveryPerformanceScanDelay(T.TypedDict):
    # The minimum duration to wait between sending packets to each target host. The value is specified as a ISO8601 duration and can range from `PT0S` (0ms) to `P30S` (30s). Defaults to `PT0S`.
    # 
    # Example: PT0S
    maximum: str
    # The maximum duration to wait between sending packets to each target host. The value is specified as a ISO8601 duration and can range from `PT0S` (0ms) to `P30S` (30s). Defaults to `PT0S`.
    # 
    # Example: PT0S
    minimum: str


class ScanTemplateDiscoveryPerformanceTimeout(T.TypedDict):
    # The initial timeout to wait between retry attempts. The value is specified as a ISO8601 duration and can range from `PT0.5S` (500ms) to `P30S` (30s). Defaults to `PT0.5S`.
    # 
    # Example: PT0.5S
    initial: str
    # The maximum time to wait between retries. The value is specified as a ISO8601 duration and can range from `PT0.5S` (500ms) to `P30S` (30s). Defaults to `PT3S`.
    # 
    # Example: PT3S
    maximum: str
    # The minimum time to wait between retries. The value is specified as a ISO8601 duration and can range from `PT0.5S` (500ms) to `P30S` (30s). Defaults to `PT0.5S`.
    # 
    # Example: PT0S
    minimum: str


class ScanTemplateDiscoveryPerformance(T.TypedDict):
    # The number of packets to send per second during scanning.
    packetRate: ScanTemplateDiscoveryPerformancePacketsRate
    # The number of discovery connection requests to be sent to target host simultaneously. These settings has no effect if values have been set for `scanDelay`.
    parallelism: ScanTemplateDiscoveryPerformanceParallelism
    # The maximum number of attempts to contact target assets. If the limit is exceeded with no response, the given asset is not scanned. Defaults to `3`.
    # 
    # Example: 3
    retryLimit: int
    # The duration to wait between sending packets to each target host during a scan.
    scanDelay: ScanTemplateDiscoveryPerformanceScanDelay
    # The duration to wait between retry attempts.
    timeout: ScanTemplateDiscoveryPerformanceTimeout


class ScanTemplateServiceDiscoveryTcp(T.TypedDict):
    # Additional TCP ports to scan. Individual ports can be specified as numbers or a string, but port ranges must be strings (e.g. `"7892-7898"`). Defaults to empty.
    # 
    # Example: 3078,8000-8080
    additionalPorts: T.Sequence[T.Any]
    # TCP ports to exclude from scanning. Individual ports can be specified as numbers or a string, but port ranges must be strings (e.g. `"7892-7898"`). Defaults to empty.
    # 
    # Example: 1024
    excludedPorts: T.Sequence[T.Any]
    # Hypermedia links to corresponding or related resources.
    links: LinkList
    # The method of TCP discovery. Defaults to `SYN`.
    # 
    # Example: SYN
    method: str
    # The TCP ports to scan. Defaults to `well-known`.
    # 
    # Example: well-known
    ports: str


class ScanTemplateServiceDiscoveryUdp(T.TypedDict):
    # Additional UDP ports to scan. Individual ports can be specified as numbers or a string, but port ranges must be strings (e.g. `"7892-7898"`). Defaults to empty.
    # 
    # Example: 4020-4032
    additionalPorts: T.Sequence[T.Any]
    # UDP ports to exclude from scanning. Individual ports can be specified as numbers or a string, but port ranges must be strings (e.g. `"7892-7898"`). Defaults to empty.
    # 
    # Example: 9899
    excludedPorts: T.Sequence[T.Any]
    # Hypermedia links to corresponding or related resources.
    links: LinkList
    # The UDP ports to scan. Defaults to `well-known`.
    # 
    # Example: well-known
    ports: str


class ScanTemplateServiceDiscovery(T.TypedDict):
    # An optional file that lists each port and the service that commonly resides on it. If scans cannot identify actual services on ports, service names will be derived from this file in scan results. Defaults to empty.
    serviceNameFile: str
    # TCP service discovery settings.
    tcp: ScanTemplateServiceDiscoveryTcp
    # UDP service discovery settings.
    udp: ScanTemplateServiceDiscoveryUdp


class ScanTemplateDiscovery(T.TypedDict):
    # Asset discovery settings used during a scan.
    asset: ScanTemplateAssetDiscovery
    # Discovery performance settings used during a scan.
    perfomance: ScanTemplateDiscoveryPerformance
    # Service discovery settings used during a scan.
    service: ScanTemplateServiceDiscovery


class Policy(T.TypedDict):
    # The identifiers of the policies enabled to be checked during a scan. No policies are enabled by default.
    enabled: T.Sequence[int]
    # Hypermedia links to corresponding or related resources.
    links: LinkList
    # Whether recursive windows file searches are enabled, if your internal security practices require this capability. Recursive file searches can increase scan times by several hours, depending on the number of files and other factors, so this setting is disabled for Windows systems by default. Defaults to `false`.
    # 
    # Example: False
    recursiveWindowsFSSearch: bool
    # Whether Asset Reporting Format (ARF) results are stored. If you are required to submit reports of your policy scan results to the U.S. government in ARF for SCAP certification, you will need to store SCAP data so that it can be exported in this format. Note that stored SCAP data can accumulate rapidly, which can have a significant impact on file storage. Defaults to `false`.
    # 
    # Example: False
    storeSCAP: bool


class Telnet(T.TypedDict):
    # The character set to use.
    # 
    # Example: ASCII
    characterSet: str
    # Regular expression to match a failed login response.
    # 
    # Example: (?:[i,I]ncorrect|[u,U]nknown|[f,F]ail|[i,I]nvalid|[l,L]ogin|[p,P]assword|[p,P]asswd|[u,U]sername|[u,U]nable|[e,E]rror|[d,D]enied|[r,R]eject|[r,R]efuse|[c,C]lose|[c,C]losing|Not on system console|% Bad)
    failedLoginRegex: str
    # Hypermedia links to corresponding or related resources.
    links: LinkList
    # Regular expression to match a login response.
    # 
    # Example: (?:[l,L]ogin|[u,U]ser.?[nN]ame) *\:
    loginRegex: str
    # Regular expression to match a password prompt.
    # 
    # Example: (?:[p,P]assword|[p,P]asswd) *\:
    passwordPromptRegex: str
    # Regular expression to match a potential false negative login response.
    # 
    # Example: (?:[l,L]ast [l,L]ogin *\:|allows only .* Telnet Client License)
    questionableLoginRegex: str


class ScanTemplateWebSpiderPaths(T.TypedDict):
    # Paths to bootstrap spidering with.
    # 
    # Example: /root
    boostrap: str
    # Paths excluded from spidering.
    # 
    # Example: /root/sensitive.html
    excluded: str
    # ${scan.template.web.spider.paths.robot.directives.description}
    # 
    # Example: False
    honorRobotDirectives: bool


class ScanTemplateWebSpiderPatterns(T.TypedDict):
    # A regular expression that is used to find sensitive content on a page.
    sensitiveContent: str
    # A regular expression that is used to find fields that may contain sensitive input. Defaults to `"(p|pass)(word|phrase|wd|code)"`.
    # 
    # Example: (p|pass)(word|phrase|wd|code)
    sensitiveField: str


class ScanTemplateWebSpiderPerformance(T.TypedDict):
    # The names of HTTP Daemons (HTTPd) to skip when spidering. For example, `"CUPS"`.
    httpDaemonsToSkip: T.Sequence[str]
    # The directory depth limit for web spidering. Limiting directory depth can save significant time, especially with large sites. A value of `0` signifies unlimited directory traversal. Defaults to `6`.
    # 
    # Example: 6
    maximumDirectoryLevels: int
    # The maximum number of unique host names that the spider may resolve. This function adds substantial time to the spidering process, especially with large Web sites, because of frequent cross-link checking involved. Defaults to `100`.
    # 
    # Example: 100
    maximumForeignHosts: int
    # The maximum depth of links to traverse when spidering. Defaults to `6`.
    # 
    # Example: 6
    maximumLinkDepth: int
    # The maximum the number of pages that are spidered. This is a time-saving measure for large sites. Defaults to `3000`.
    # 
    # Example: 3000
    maximumPages: int
    # The maximum the number of times to retry a request after a failure. A value of `0` means no retry attempts are made. Defaults to `2`.
    # 
    # Example: 2
    maximumRetries: int
    # The maximum length of time to web spider. This limit prevents scans from taking longer than the allotted scan schedule. A value of `PT0S` means no limit is applied. The acceptable range is `PT1M` to `PT16666.6667H`.
    # 
    # Example: PT0S
    maximumTime: str
    # The duration to wait for a response from a target web server. The value is specified as a ISO8601 duration and can range from `PT0S` (0ms) to `P1H` (1 hour). Defaults to `PT2M`.
    # 
    # Example: PT2M
    responseTimeout: str
    # The number of threads to use per web server being spidered. Defaults to `3`.
    # 
    # Example: 3
    threadsPerServer: int


class ScanTemplateWebSpider(T.TypedDict):
    # Whether scanning of multi-use devices, such as printers or print servers should be avoided.
    # 
    # Example: True
    dontScanMultiUseDevices: bool
    # Whether query strings are using in URLs when web spidering. This causes the web spider to make many more requests to the Web server. This will increase overall scan time and possibly affect the Web server's performance for legitimate users.
    # 
    # Example: False
    includeQueryStrings: bool
    # Paths to use when web spidering.
    paths: ScanTemplateWebSpiderPaths
    # Patterns to match responses during web spidering.
    patterns: ScanTemplateWebSpiderPatterns
    # Performance settings used during web spidering.
    performance: ScanTemplateWebSpiderPerformance
    # Whether to determine if discovered logon forms accept commonly used user names or passwords. The process may cause authentication services with certain security policies to lock out accounts with these credentials.
    # 
    # Example: False
    testCommonUsernamesAndPasswords: bool
    # Whether to test for persistent cross-site scripting during a single scan. This test helps to reduce the risk of dangerous attacks via malicious code stored on Web servers. Enabling it may increase Web spider scan times.
    # 
    # Example: False
    testXssInSingleScan: bool
    # The `User-Agent` to use when web spidering. Defaults to `"Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)"`.
    # 
    # Example: Mozilla/5.0 (compatible; MSIE 7.0; Windows NT 6.0; .NET CLR 1.1.4322; .NET CLR 2.0.50727)
    userAgent: str


class ScanTemplate(T.TypedDict):
    # Settings for which vulnerability checks to run during a scan. <br/> 
    # The rules for inclusion of checks is as follows: 
    # <ul> 
    # <li>Enabled checks by category and by check type are included</li> 
    # <li>Disabled checks in by category and by check type are removed</li> 
    # <li>Enabled checks in by individual check are added (even if they are disabled in by category or check type)</li> 
    # <li>Disabled checks in by individual check are removed</li> 
    # <li>If unsafe is disabled, unsafe checks are removed</li> 
    # <li>If potential is disabled, potential checks are removed</li> 
    # <ul>
    checks: ScanTemplateVulnerabilityChecks
    # Settings for discovery databases.
    database: ScanTemplateDatabase
    # A verbose description of the scan template..
    # 
    # Example: Performs a full network audit of all systems using only safe checks...
    description: str
    # Discovery settings used during a scan.
    discovery: ScanTemplateDiscovery
    # Whether only discovery is performed during a scan.
    # 
    # Example: False
    discoveryOnly: bool
    # Whether Windows services are enabled during a scan. Windows services will be temporarily reconfigured when this option is selected. Original settings will be restored after the scan completes, unless it is interrupted.
    # 
    # Example: False
    enableWindowsServices: bool
    # Whether enhanced logging is gathered during scanning. Collection of enhanced logs may greatly increase the disk space used by a scan.
    # 
    # Example: False
    enhancedLogging: bool
    # The identifier of the scan template
    # 
    # Example: full-audit-without-web-spider
    id: str
    # Hypermedia links to corresponding or related resources.
    links: LinkList
    # The maximum number of assets scanned simultaneously per scan engine during a scan.
    # 
    # Example: 10
    maxParallelAssets: int
    # The maximum number of scan processes simultaneously allowed against each asset during a scan.
    # 
    # Example: 10
    maxScanProcesses: int
    # A concise name for the scan template.
    # 
    # Example: Full audit
    name: str
    # Policy configuration settings used during a scan.
    policy: Policy
    # Whether policy assessment is performed during a scan.
    # 
    # Example: True
    policyEnabled: bool
    # Settings for interacting with the Telnet protocol.
    telnet: Telnet
    # Whether vulnerability assessment is performed during a scan.
    # 
    # Example: True
    vulnerabilityEnabled: bool
    # Web spider settings used during a scan.
    web: ScanTemplateWebSpider
    # Whether web spidering and assessment are performed during a scan.
    # 
    # Example: True
    webEnabled: bool

ScanTemplateNexposeId = T.NewType('ScanTemplateNexposeId', int)
ScanTemplateId = T.Union[str, ScanTemplateNexposeId]
ScanTemplateMap = T.Dict[ScanTemplateId, ScanTemplate]



# -----------------------------------------------------------------------------
# Asset
# -----------------------------------------------------------------------------

class Address(T.TypedDict):
    # The IPv4 or IPv6 address.
    # 
    # Example: 123.245.34.235
    ip: str
    # The Media Access Control (MAC) address. The format is six groups of two hexadecimal digits separated by colons.
    # 
    # Example: 12:34:56:78:90:AB
    mac: str


class Configuration(T.TypedDict):
    # The name of the configuration value.
    # 
    # Example: <name>
    name: str
    # The configuration value.
    # 
    # Example: <value>
    value: str


class Database(T.TypedDict):
    # The description of the database instance.
    # 
    # Example: Microsoft SQL Server
    description: str
    # The identifier of the database.
    # 
    # Example: 13
    id: int
    # The name of the database instance.
    # 
    # Example: MSSQL
    name: str


class File(T.TypedDict):
    # Attributes detected on the file.
    attributes: T.Sequence[Configuration]
    # The name of the file.
    # 
    # Example: ADMIN$
    name: str
    # The size of the regular file (in bytes). If the file is a directory, no value is returned.
    # 
    # Example: -1
    size: int
    # The type of the file.
    # 
    # Example: directory
    type: str


class AssetHistory(T.TypedDict):
    # The date the asset information was collected or changed.
    # 
    # Example: 2018-04-09T06:23:49Z
    date: str
    # Additional information describing the change.
    description: str
    # If a scan-oriented change, the identifier of the corresponding scan the asset was scanned in.
    # 
    # Example: 12
    scanId: int
    # The type of change. May be one of: 
    # | Type                                | Source of Data                                              | 
    # | ----------------------------------- | ----------------------------------------------------------- | 
    # | `ASSET-IMPORT`, `EXTERNAL-IMPORT`   | External source such as the API                             | 
    # | `EXTERNAL-IMPORT-APPSPIDER`         | Rapid7 InsightAppSec (previously known as AppSpider)        | 
    # | `SCAN`                              | Scan engine scan                                            | 
    # | `ACTIVE-SYNC`                       | ActiveSync                                                  | 
    # | `SCAN-LOG-IMPORT`                   | Manual import of a scan log                                 | 
    # | `VULNERABILITY_EXCEPTION_APPLIED`   | Vulnerability exception applied                             | 
    # | `VULNERABILITY_EXCEPTION_UNAPPLIED` | Vulnerability exception unapplied                           |
    # 
    # Example: SCAN
    type: str
    # If a vulnerability exception change, the login name of the user that performed the operation.
    user: str
    # The version number of the change (a chronological incrementing number starting from 1). 
    # 
    # Example: 8
    version: int
    # If a vulnerability exception change, the identifier of the vulnerability exception that caused the change.
    vulnerabilityExceptionId: int


class HostName(T.TypedDict):
    # The host name (local or FQDN).
    # 
    # Example: corporate-workstation-1102DC.acme.com
    name: str
    # The source used to detect the host name. `user` indicates the host name source is user-supplied (e.g. in a site target definition).
    # 
    # Example: DNS
    source: str


class UniqueId(T.TypedDict):
    # The unique identifier.
    # 
    # Example: c56b2c59-4e9b-4b89-85e2-13f8146eb071
    id: str
    # The source of the unique identifier.
    # 
    # Example: WQL
    source: str


OperatingSystemCpe = T.TypedDict('OperatingSystemCpe', {
    # Edition-related terms applied by the vendor to the product. 
    # 
    # Example: enterprise
    'edition': str,
    # Defines the language supported in the user interface of the product being described. The format is of the language tag adheres to <a target="_blank" href="https://tools.ietf.org/html/rfc5646">RFC5646</a>.
    'language': str,
    # Captures any other general descriptive or identifying information which is vendor- or product-specific and which does not logically fit in any other attribute value. 
    'other': str,
    # A single letter code that designates the particular platform part that is being identified.
    # 
    # Example: o
    'part': str,
    # the most common and recognizable title or name of the product.
    # 
    # Example: windows_server_2008
    'product': str,
    # Characterizes how the product is tailored to a particular market or class of end users. 
    'swEdition': str,
    # Characterize the instruction set architecture on which the product operates. 
    'targetHW': str,
    # Characterize the software computing environment within which the product operates.
    'targetSW': str,
    # Vendor-specific alphanumeric strings characterizing the particular update, service pack, or point release of the product.
    # 
    # Example: sp1
    'update': str,
    # The full CPE string in the <a target="_blank" href="https://cpe.mitre.org/files/cpe-specification_2.2.pdf">CPE 2.2</a> format.
    # 
    # Example: cpe:/o:microsoft:windows_server_2008:-:sp1:enterprise
    'v2.2': str,
    # The full CPE string in the <a target="_blank" href="http://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf">CPE 2.3</a> format.
    # 
    # Example: cpe:2.3:o:microsoft:windows_server_2008:-:sp1:enterprise:*:*:*:*:*
    'v2.3': str,
    # The person or organization that manufactured or created the product.
    # 
    # Example: microsoft
    'vendor': str,
    # Vendor-specific alphanumeric strings characterizing the particular release version of the product.
    # 
    # Example: -
    'version': str,
})


class OperatingSystem(T.TypedDict):
    # The architecture of the operating system.
    # 
    # Example: x86
    architecture: str
    # Configuration key-values pairs enumerated on the operating system.
    configurations: T.Sequence[Configuration]
    # The Common Platform Enumeration (CPE) of the operating system.
    cpe: OperatingSystemCpe
    # The description of the operating system (containing vendor, family, product, version and architecture in a single string).
    # 
    # Example: Microsoft Windows Server 2008 Enterprise Edition SP1
    description: str
    # The family of the operating system.
    # 
    # Example: Windows
    family: str
    # The identifier of the operating system.
    # 
    # Example: 35
    id: int
    # The name of the operating system.
    # 
    # Example: Windows Server 2008 Enterprise Edition
    product: str
    # A combination of vendor and family (with redundancies removed), suitable for grouping.
    # 
    # Example: Microsoft Windows
    systemName: str
    # The type of operating system.
    # 
    # Example: Workstation
    type: str
    # The vendor of the operating system.
    # 
    # Example: Microsoft
    vendor: str
    # The version of the operating system.
    # 
    # Example: SP1
    version: str


class GroupAccount(T.TypedDict):
    # The identifier of the user group.
    # 
    # Example: 972
    id: int
    # The name of the user group.
    # 
    # Example: Administrators
    name: str


class UserAccount(T.TypedDict):
    # The full name of the user account.
    # 
    # Example: Smith, John
    fullName: str
    # The identifier of the user account.
    # 
    # Example: 8952
    id: int
    # The name of the user account.
    # 
    # Example: john_smith
    name: str


class WebPage(T.TypedDict):
    # The type of link used to traverse or detect the page.
    # 
    # Example: html-ref
    linkType: str
    # The path to the page (URI).
    # 
    # Example: /docs/config/index.html
    path: str
    # The HTTP response code observed with retrieving the page.
    # 
    # Example: 200
    response: int


class WebApplication(T.TypedDict):
    # The identifier of the web application.
    # 
    # Example: 30712
    id: int
    # The pages discovered on the web application.
    pages: T.Sequence[WebPage]
    # The web root of the web application.
    # 
    # Example: /
    root: str
    # The virtual host of the web application.
    # 
    # Example: 102.89.22.253
    virtualHost: str


class Service(T.TypedDict):
    # Configuration key-values pairs enumerated on the service.
    configurations: T.Sequence[Configuration]
    # The databases enumerated on the service.
    databases: T.Sequence[Database]
    # The family of the service.
    family: str
    # Hypermedia links to corresponding or related resources.
    links: LinkList
    # The name of the service.
    # 
    # Example: CIFS Name Service
    name: str
    # The port of the service.
    # 
    # Example: 139
    port: int
    # The product running the service.
    # 
    # Example: Samba
    product: str
    # The protocol of the service.
    # 
    # Example: tcp
    protocol: str
    # The group accounts enumerated on the service.
    userGroups: T.Sequence[GroupAccount]
    # The user accounts enumerated on the service.
    users: T.Sequence[UserAccount]
    # The vendor of the service.
    vendor: str
    # The version of the service.
    # 
    # Example: 3.5.11
    version: str
    # The web applications found on the service.
    webApplications: T.Sequence[WebApplication]


SoftwareCpe = T.TypedDict('SoftwareCpe', {
    # Edition-related terms applied by the vendor to the product. 
    # 
    # Example: enterprise
    'edition': str,
    # Defines the language supported in the user interface of the product being described. The format is of the language tag adheres to <a target="_blank" href="https://tools.ietf.org/html/rfc5646">RFC5646</a>.
    'language': str,
    # Captures any other general descriptive or identifying information which is vendor- or product-specific and which does not logically fit in any other attribute value. 
    'other': str,
    # A single letter code that designates the particular platform part that is being identified.
    # 
    # Example: o
    'part': str,
    # the most common and recognizable title or name of the product.
    # 
    # Example: windows_server_2008
    'product': str,
    # Characterizes how the product is tailored to a particular market or class of end users. 
    'swEdition': str,
    # Characterize the instruction set architecture on which the product operates. 
    'targetHW': str,
    # Characterize the software computing environment within which the product operates.
    'targetSW': str,
    # Vendor-specific alphanumeric strings characterizing the particular update, service pack, or point release of the product.
    # 
    # Example: sp1
    'update': str,
    # The full CPE string in the <a target="_blank" href="https://cpe.mitre.org/files/cpe-specification_2.2.pdf">CPE 2.2</a> format.
    # 
    # Example: cpe:/o:microsoft:windows_server_2008:-:sp1:enterprise
    'v2.2': str,
    # The full CPE string in the <a target="_blank" href="http://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf">CPE 2.3</a> format.
    # 
    # Example: cpe:2.3:o:microsoft:windows_server_2008:-:sp1:enterprise:*:*:*:*:*
    'v2.3': str,
    # The person or organization that manufactured or created the product.
    # 
    # Example: microsoft
    'vendor': str,
    # Vendor-specific alphanumeric strings characterizing the particular release version of the product.
    # 
    # Example: -
    'version': str,
})


class Software(T.TypedDict):
    # ${software.attributes.description}
    configurations: T.Sequence[Configuration]
    # The Common Platform Enumeration (CPE) of the software.
    cpe: SoftwareCpe
    # The description of the software.
    # 
    # Example: Microsoft Outlook 2013 15.0.4867.1000
    description: str
    # The family of the software.
    # 
    # Example: Office 2013
    family: str

    id: int
    # The product of the software.
    # 
    # Example: Outlook 2013
    product: str
    # The version of the software.
    # 
    # Example: Productivity
    type: str
    # The vendor of the software.
    # 
    # Example: Microsoft
    vendor: str
    # The version of the software.
    # 
    # Example: 15.0.4867.1000
    version: str


class GroupAccount(T.TypedDict):
    # The identifier of the user group.
    # 
    # Example: 972
    id: int
    # The name of the user group.
    # 
    # Example: Administrators
    name: str


class UserAccount(T.TypedDict):
    # The full name of the user account.
    # 
    # Example: Smith, John
    fullName: str
    # The identifier of the user account.
    # 
    # Example: 8952
    id: int
    # The name of the user account.
    # 
    # Example: john_smith
    name: str


class AssetVulnerabilities(T.TypedDict):
    # The number of critical vulnerabilities.
    # 
    # Example: 16
    critical: int
    # The number of distinct exploits that can exploit any of the vulnerabilities on the asset.
    # 
    # Example: 4
    exploits: int
    # The number of distinct malware kits that vulnerabilities on the asset are susceptible to.
    # 
    # Example: 0
    malwareKits: int
    # The number of moderate vulnerabilities.
    # 
    # Example: 3
    moderate: int
    # The number of severe vulnerabilities.
    # 
    # Example: 76
    severe: int
    # The total number of vulnerabilities.
    # 
    # Example: 95
    total: int


class Asset(T.TypedDict):
    # All addresses discovered on the asset.
    addresses: T.Sequence[Address]
    # Whether the asset has been assessed for policies at least once.
    # 
    # Example: False
    assessedForPolicies: bool
    # Whether the asset has been assessed for vulnerabilities at least once.
    # 
    # Example: True
    assessedForVulnerabilities: bool
    # Configuration key-values pairs enumerated on the asset.
    configurations: T.Sequence[Configuration]
    # The databases enumerated on the asset.
    databases: T.Sequence[Database]
    # The files discovered with searching on the asset.
    files: T.Sequence[File]
    # The history of changes to the asset over time.
    history: T.Sequence[AssetHistory]
    # The primary host name (local or FQDN) of the asset.
    # 
    # Example: corporate-workstation-1102DC.acme.com
    hostName: str
    # All host names or aliases discovered on the asset.
    hostNames: T.Sequence[HostName]
    # The identifier of the asset.
    # 
    # Example: 282
    id: int
    # Unique identifiers found on the asset, such as hardware or operating system identifiers.
    ids: T.Sequence[UniqueId]
    # The primary IPv4 or IPv6 address of the asset.
    # 
    # Example: 182.34.74.202
    ip: str
    # Hypermedia links to corresponding or related resources.
    links: LinkList
    # The primary Media Access Control (MAC) address of the asset. The format is six groups of two hexadecimal digits separated by colons.
    # 
    # Example: AB:12:CD:34:EF:56
    mac: str
    # The full description of the operating system of the asset.
    # 
    # Example: Microsoft Windows Server 2008 Enterprise Edition SP1
    os: str
    # The details of the operating system of the asset.
    osFingerprint: OperatingSystem
    # The base risk score of the asset.
    # 
    # Example: 31214.3
    rawRiskScore: float
    # The risk score (with criticality adjustments) of the asset.
    # 
    # Example: 37457.16
    riskScore: float
    # The services discovered on the asset.
    services: T.Sequence[Service]
    # The software discovered on the asset.
    software: T.Sequence[Software]
    # The type of asset.
    type: str
    # The group accounts enumerated on the asset.
    userGroups: T.Sequence[GroupAccount]
    # The user accounts enumerated on the asset.
    users: T.Sequence[UserAccount]
    # Summary information for vulnerabilities on the asset.
    vulnerabilities: AssetVulnerabilities

AssetNextposeId = T.NewType('AssetNexposeId', int)

AssetId = T.Union[Ip, AssetNextposeId]
AssetList = T.Iterable[AssetId]
AssetMap = T.Dict[AssetId, Asset]



# -----------------------------------------------------------------------------
# User
# -----------------------------------------------------------------------------



class CreateAuthenticationSource(T.TypedDict):
    # The type of the authentication source to use to authenticate the user. Defaults to `normal`.
    type: str


class LocalePreferences(T.TypedDict):
    # The default language to use. The format is a <a target="_blank" href="https://tools.ietf.org/html/bcp47">IETF BCP 47</a> language tag.
    default: str

    links: LinkList
    # The language to use to generate reports. The format is a <a target="_blank" href="https://tools.ietf.org/html/bcp47">IETF BCP 47</a> language tag.
    reports: str


class UserCreateRole(T.TypedDict):
    # Whether to grant the user access to all asset groups. Defaults to `false`.
    # 
    # Example: False
    allAssetGroups: bool
    # Whether to grant the user access to all sites. Defaults to `false`.
    # 
    # Example: False
    allSites: bool
    # The identifier of the role the user is assigned to.
    id: str
    # Whether the user is a superuser. Defaults to `false`.
    # 
    # Example: False
    superuser: bool


class User(T.TypedDict):
    # The details of the authentication source used to authenticate the user.
    authentication: CreateAuthenticationSource
    # The email address of the user.
    email: str
    # Whether the user account is enabled. Defaults to `true`.
    # 
    # Example: False
    enabled: bool
    # The identifier of the user.
    id: int
    # Hypermedia links to corresponding or related resources.
    links: LinkList
    # The locale and language preferences for the user.
    locale: LocalePreferences
    # Whether the user account is locked (exceeded maximum password retry attempts).
    # 
    # Example: False
    locked: bool
    # The login name of the user.
    login: str
    # The full name of the user.
    name: str
    # The password to use for the user.
    password: str
    # Whether to require a reset of the user's password upon first login. Defaults to `false`.
    # 
    # Example: False
    passwordResetOnLogin: bool
    # The privileges and role to assign the user.
    role: UserCreateRole

UserNexposeId = T.NewType('UserNexposeId', int)
UserId = T.Union[UserNexposeId, str]




# -----------------------------------------------------------------------------
# Report
# -----------------------------------------------------------------------------

class ReportConfigDatabaseCredentialsResource(T.TypedDict):
    # ${report.config.database.credential.password.description}
    # 
    # Example: ******
    password: str
    # ${report.config.database.credential.username.description}
    # 
    # Example: admin
    username: str


class ReportConfigDatabaseResource(T.TypedDict):
    # ${report.config.database.credentials.description}
    credentials: ReportConfigDatabaseCredentialsResource
    # The database server host to export to.
    # 
    # Example: database.acme.com
    host: str
    # The name of the database to export to.
    # 
    # Example: database
    name: str
    # The database server port to export to.
    # 
    # Example: 3306
    port: int
    # The type of the database server.
    # 
    # Example: mysql
    vendor: str


ReportEmailSmtp = T.TypedDict('ReportEmailSmtp', {
    # Whether to use global SMTP settings. If enabled, `sender` and `relay` may not be specified.
    # 
    # Example: True
    'global': bool,
    # SMTP relay host or IP address.
    # 
    # Example: mail.acme.com
    'relay': str,
    # SMTP sender address.
    # 
    # Example: john_smith@acme.com
    'sender': str,
})


class ReportEmail(T.TypedDict):
    # The format to distribute the report in when sending to users who have explicit access to the report.
    # 
    # Example: zip
    access: str
    # The format to distribute the report to additional recipients.
    # 
    # Example: file
    additional: str
    # The email address of additional recipients to distribute the report to.
    additionalRecipients: T.Sequence[str]
    # ${report.config.email.additional.asset.access.description}
    # 
    # Example: True
    assetAccess: bool
    # The format to distribute the report to the owner.
    # 
    # Example: file
    owner: str
    # SMTP delivery settings.
    smtp: ReportEmailSmtp


class ReportConfigCategoryFilters(T.TypedDict):
    # The vulnerability categories to exclude. Defaults to no categories.
    excluded: T.Sequence[str]
    # The vulnerability categories to include. Defaults to all categories.
    included: T.Sequence[str]

    links: LinkList


class ReportConfigFiltersResource(T.TypedDict):
    # Vulnerability categories to include or exclude. Only `included` or `excluded` may be specified, but not both.
    categories: ReportConfigCategoryFilters
    # The vulnerability severities to include. Defaults to `all`.
    severity: str
    # The vulnerability statuses to include. Defaults to [ `vulnerable`, `vulnerable-version`, `potentially-vulnerable` ].
    statuses: T.Sequence[str]


class RepeatSchedule(T.TypedDict):
    # The day of the week the scheduled task should repeat. This property only applies to schedules with a `every` value of `"day-of-month"`.
    dayOfWeek: str
    # The frequency schedule repeats. Each value represents a different unit of time and is used in conjunction with the property `interval`. For example, a schedule can repeat hourly, daily, monthly, etc. The following table describes each supported value: 
    # | Value | Description | 
    # | ---------- | ---------------- | 
    # | hour | Specifies the schedule repeats in hourly increments. | 
    # | day | Specifies the schedule repeats in daily increments. | 
    # | week | Specifies the schedule repeats in weekly increments. | 
    # | date-of-month | Specifies the schedule repeats nth day of the `interval` month. Requires the property `dateOfMonth` to be specified. For example, if `dateOfMonth` is `17` and the `interval` is `2`, then the schedule will repeat every 2 months on the 17th day of the month. | 
    # | day-of-month | Specifies the schedule repeats on a monthly interval but instead of a specific date being specified, the day of the week and week of the month are specified. Requires the properties `dayOfWeek` and `weekOfMonth` to be specified. For example, if `dayOfWeek` is `"friday"`, `weekOfMonth` is `3`, and the `interval` is `4`, then the schedule will repeat every 4 months on the 3rd Friday of the month. | 
    # 
    # Example: date-of-month
    every: str
    # The interval time the schedule should repeat. The is depends on the value set in `every`. For example, if the value in property `every` is set to `"day"` and `interval` is set to `2`, then the schedule will repeat every 2 days.
    # 
    # Example: 1
    interval: int

    lastDayOfMonth: bool
    # The week of the month the scheduled task should repeat. For This property only applies to schedules with a `every` value of `"day-of-month"`. Each week of the month is counted in 7-day increments. For example, week 1 consists of days 1-7 of the month while week 2 consists of days 8-14 of the month and so forth.
    weekOfMonth: int


class ReportFrequency(T.TypedDict):
    # List the next 10 dates in the future the schedule will launch. 
    nextRuntimes: T.Sequence[str]
    # Settings for repeating a scheduled task.
    repeat: RepeatSchedule
    # The scheduled start date and time. Date is represented in ISO 8601 format. Repeating schedules will determine the next schedule to begin based on this date and time.
    # 
    # Example: 2018-03-01T04:31:56Z
    start: str


class ReportConfigScopeResource(T.TypedDict):
    # ${report.config.asset.groups.description}
    assetGroups: T.Sequence[int]
    # ${report.config.assets.description}
    assets: T.Sequence[int]
    # ${report.config.scans.description}
    # 
    # Example: 68
    scan: int
    # ${report.config.sites.description}
    sites: T.Sequence[int]
    # ${report.config.tags.description}
    tags: T.Sequence[int]


class ReportStorage(T.TypedDict):
    # The location to storage an additional copy of the report. This is a sub-path post-fixed to `$(install_dir)/nsc/reports/$(user)/`.
    # 
    # Example: monthly_reports/site/corporate
    location: str
    # The full path to the additional copy storage location.
    # 
    # Example: $(install_dir)/nsc/reports/$(user)/monthly_reports/site/corporate
    path: str


class Report(T.TypedDict):
    # The name of the bureau for a CyberScope report. Only used when the format is `"cyberscope-xml"`.
    # 
    # Example: Bureau
    bureau: str
    # The name of the component for a CyberScope report. Only used when the format is `"cyberscope-xml"`.
    # 
    # Example: Component
    component: str
    # Configuration for database export. Only used when the format is `"database-export"`.
    database: ReportConfigDatabaseResource
    # Email distribution settings for the report.
    email: ReportEmail
    # The name of the enclave for a CyberScope report. Only used when the format is `"cyberscope-xml"`.
    # 
    # Example: Enclave
    enclave: str
    # Filters applied to the contents of the report. The supported filters for a report vary 
    # by format and template. 
    # <div class="properties"> 
    # <div class="property-info"> 
    # <span class="property-name">categories</span> <span class="param-type complex">Object</span> 
    # <div class="redoc-markdown-block">The vulnerability categories to include or exclude in the report. Only included or excluded may be specified, not both.</div>
    # </div> 
    # <div class="properties nested"> 
    # <div class="property-info"> 
    # <span class="property-name">included</span> <span class="param-type param-array-format integer">Array[string]</span> 
    # <div class="redoc-markdown-block">The identifiers of the vulnerability categories to included in the report.</div> 
    # </div> 
    # <div class="property-info"> 
    # <span class="property-name">excluded</span> <span class="param-type param-array-format integer">Array[string]</span> 
    # <div class="redoc-markdown-block">The identifiers of the vulnerability categories to exclude in the report.</div> 
    # </div> 
    # </div> 
    # <div class="property-info"> 
    # <span class="property-name">severity</span> <span class="param-type">string</span> 
    # <div class="param-enum"> 
    # <span class="param-enum-value string">"all"</span> 
    # <span class="param-enum-value string">"critical"</span> 
    # <span class="param-enum-value string">"critical-and-severe"</span> 
    # </div> 
    # <div class="redoc-markdown-block">The vulnerability severities to include in the report.</div>
    # </div> 
    # <div class="property-info"> 
    # <span class="property-name">statuses</span> <span class="param-type param-array-format integer">Array[string]</span> 
    # <div class="param-enum"> 
    # <span class="param-enum-value string">"vulnerable"</span> 
    # <span class="param-enum-value string">"vulnerable-version"</span> 
    # <span class="param-enum-value string">"potentially-vulnerable"</span> 
    # <span class="param-enum-value string">"vulnerable-and-validated"</span> 
    # </div> 
    # <div class="redoc-markdown-block">The vulnerability statuses to include in the report. If <code>"vulnerable-and-validated"</code> is selected 
    # no other values can be specified.
    # </div> 
    # </div> 
    # </div>
    # 
    # The following filter elements may be defined for non-templatized report formats: 
    # | Format                                | Categories     | Severity   | Statuses   | 
    # | ------------------------------------- |:--------------:|:----------:|:----------:| 
    # | `arf-xml`                             |                |            |            | 
    # | `csv-export`                          | &check;        | &check;    | &check;    | 
    # | `cyberscope-xml`                      |                |            |            | 
    # | `database-export`                     |                |            |            | 
    # | `nexpose-simple-xml`                  | &check;        | &check;    |            | 
    # | `oval-xml`                            |                |            |            | 
    # | `qualys-xml`                          | &check;        | &check;    |            | 
    # | `scap-xml`                            | &check;        | &check;    |            | 
    # | `sql-query`                           | &check;        | &check;    | &check;    | 
    # | `xccdf-csv`                           |                |            |            | 
    # | `xccdf-xml`                           | &check;        | &check;    |            | 
    # | `xml-export`                          | &check;        | &check;    | &check;    | 
    # | `xml-export-v2`                       | &check;        | &check;    | &check;    | 
    # 
    # The following filter elements may be defined for templatized report formats: 
    # | Template                                | Categories     | Severity   | Statuses   | 
    # | --------------------------------------- |:--------------:|:----------:|:----------:| 
    # | `audit-report`                          | &check;        | &check;    |            | 
    # | `baseline-comparison`                   |                |            |            | 
    # | `basic-vulnerability-check-results`     | &check;        | &check;    | &check;    | 
    # | `executive-overview`                    |                |            |            | 
    # | `highest-risk-vulns`                    |                |            |            | 
    # | `pci-attestation-v12`                   |                |            |            | 
    # | `pci-executive-summary-v12`             |                |            |            | 
    # | `pci-vuln-details-v12`                  |                |            |            | 
    # | `policy-details`                        | &check;        | &check;    | &check;    | 
    # | `policy-eval`                           |                |            |            | 
    # | `policy-summary`                        | &check;        | &check;    | &check;    | 
    # | `prioritized-remediations`              | &check;        | &check;    | &check;    | 
    # | `prioritized-remediations-with-details` | &check;        | &check;    | &check;    | 
    # | `r7-discovered-assets`                  | &check;        | &check;    | &check;    | 
    # | `r7-vulnerability-exceptions`           | &check;        | &check;    | &check;    | 
    # | `remediation-plan`                      | &check;        | &check;    |            | 
    # | `report-card`                           | &check;        | &check;    |            | 
    # | `risk-scorecard`                        | &check;        | &check;    | &check;    | 
    # | `rule-breakdown-summary`                | &check;        | &check;    | &check;    | 
    # | `top-policy-remediations`               | &check;        | &check;    | &check;    | 
    # | `top-policy-remediations-with-details`  | &check;        | &check;    | &check;    | 
    # | `top-riskiest-assets`                   | &check;        | &check;    | &check;    | 
    # | `top-vulnerable-assets`                 | &check;        | &check;    | &check;    | 
    # | `vulnerability-trends`                  | &check;        | &check;    | &check;    | 
    filters: ReportConfigFiltersResource
    # The output format of the report. The format will restrict the available templates and parameters that can be specified.
    # 
    # Example: pdf
    format: str
    # The recurring frequency with which to generate the report.
    frequency: ReportFrequency
    # The identifier of the report.
    # 
    # Example: 17
    id: int
    # The locale (language) in which the report is generated
    # 
    # Example: en-US
    language: str
    # Hypermedia links to corresponding or related resources.
    links: LinkList
    # The name of the report.
    # 
    # Example: Monthly Corporate Site Summary
    name: str
    # The organization used for a XCCDF XML report. Only used when the format is `"xccdf-xml"`.
    # 
    # Example: Acme, Inc.
    organization: str
    # The identifier of the report owner.
    # 
    # Example: 1
    owner: int
    # The policy to report on. Only used when the format is `"oval-xml"`, `""xccdf-csv"`, or `"xccdf-xml"`.
    # 
    # Example: 789
    policy: int
    # SQL query to run against the Reporting Data Model. Only used when the format is `"sql-query"`.
    # 
    # Example: SELECT * FROM dim_asset ORDER BY ip_address ASC
    query: str
    # The scope of the report. Scope is an object that has the following properties that vary by format and template: 
    # <div class="properties"> 
    # <div class="property-info"> 
    # <span class="property-name">assets</span> <span class="param-type param-array-format integer">Array[integer &lt;int32&gt;]</span> 
    # <div class="redoc-markdown-block">The identifiers of the assets to report on.</div> 
    # </div> 
    # <div class="property-info"> 
    # <span class="property-name">sites</span> <span class="param-type param-array-format integer">Array[integer &lt;int32&gt;]</span> 
    # <div class="redoc-markdown-block">The identifiers of the sites to report on.</div> 
    # </div> 
    # <div class="property-info"> 
    # <span class="property-name">assetGroups</span> <span class="param-type param-array-format integer">Array[integer &lt;int32&gt;]</span> 
    # <div class="redoc-markdown-block">The identifiers of the asset to report on.</div> 
    # </div> 
    # <div class="property-info"> 
    # <span class="property-name">tags</span> <span class="param-type param-array-format integer">Array[integer &lt;int32&gt;]</span> 
    # <div class="redoc-markdown-block">The identifiers of the tag to report on.</div> 
    # </div> 
    # <div class="property-info"> 
    # <span class="property-name">scan</span> <span class="param-type param-array-format integer">integer &lt;int32&gt;</span> 
    # <div class="redoc-markdown-block">The identifier of the scan to report on.</div> 
    # </div> 
    # </div>
    # 
    # The following scope elements may be defined for non-templatized report formats: 
    # | Format                                | Assets     | Sites   | Asset Groups | Tags    | Scan      | 
    # | ------------------------------------- |:----------:|:-------:|:------------:|:-------:|:---------:| 
    # | `arf-xml`                             | &check;    | &check; | &check;      | &check; |           | 
    # | `csv-export`                          | &check;    | &check; | &check;      | &check; | &check;   | 
    # | `cyberscope-xml`                      | &check;    | &check; | &check;      | &check; | &check;   | 
    # | `database-export`                     |            | &check; |              |         |           | 
    # | `nexpose-simple-xml`                  | &check;    | &check; | &check;      | &check; | &check;   | 
    # | `oval-xml`                            | &check;    | &check; | &check;      | &check; |           | 
    # | `qualys-xml`                          | &check;    | &check; | &check;      | &check; | &check;   | 
    # | `scap-xml`                            | &check;    | &check; | &check;      | &check; | &check;   | 
    # | `sql-query`                           | &check;    | &check; | &check;      | &check; | &check;   | 
    # | `xccdf-csv`                           | &check;    |         |              |         |           | 
    # | `xccdf-xml`                           | &check;    | &check; | &check;      | &check; | &check;   | 
    # | `xml-export`                          | &check;    | &check; | &check;      | &check; | &check;   | 
    # | `xml-export-v2`                       | &check;    | &check; | &check;      | &check; | &check;   | 
    # 
    # The following scope elements may be defined for templatized report formats: 
    # | Template                                 | Assets     | Sites   | Asset Groups | Tags    | Scan    | 
    # | -----------------------------------------|:----------:|:-------:|:------------:|:-------:|:-------:| 
    # | `audit-report`                           | &check;    | &check; |  &check;     | &check; | &check; | 
    # | `baseline-comparison`                    | &check;    | &check; |  &check;     | &check; |         | 
    # | `basic-vulnerability-check-results`      | &check;    | &check; |  &check;     | &check; | &check; | 
    # | `executive-overview`                     | &check;    | &check; |  &check;     | &check; |         | 
    # | `highest-risk-vulns`                     | &check;    | &check; |  &check;     | &check; |         | 
    # | `pci-attestation-v12`                    | &check;    | &check; |  &check;     | &check; | &check; | 
    # | `pci-executive-summary-v12`              | &check;    | &check; |  &check;     | &check; | &check; | 
    # | `pci-vuln-details-v12`                   | &check;    | &check; |  &check;     | &check; | &check; | 
    # | `policy-details`                         | &check;    | &check; |  &check;     | &check; |         | 
    # | `policy-eval`                            | &check;    | &check; |  &check;     | &check; |         | 
    # | `policy-summary`                         | &check;    | &check; |  &check;     | &check; | &check; | 
    # | `prioritized-remediations`               | &check;    | &check; |  &check;     | &check; | &check; | 
    # | `prioritized-remediations-with-details`  | &check;    | &check; |  &check;     | &check; | &check; | 
    # | `r7-discovered-assets`                   | &check;    | &check; |  &check;     | &check; | &check; | 
    # | `r7-vulnerability-exceptions`            | &check;    | &check; |  &check;     | &check; | &check; | 
    # | `remediation-plan`                       | &check;    | &check; |  &check;     | &check; | &check; | 
    # | `report-card`                            | &check;    | &check; |  &check;     | &check; | &check; | 
    # | `risk-scorecard`                         | &check;    | &check; |  &check;     | &check; |         | 
    # | `rule-breakdown-summary`                 | &check;    | &check; |  &check;     | &check; |         | 
    # | `top-policy-remediations`                | &check;    | &check; |  &check;     | &check; |         | 
    # | `top-policy-remediations-with-details`   | &check;    | &check; |  &check;     | &check; |         | 
    # | `top-riskiest-assets`                    | &check;    | &check; |  &check;     | &check; | &check; | 
    # | `top-vulnerable-assets`                  | &check;    | &check; |  &check;     | &check; | &check; | 
    # | `vulnerability-trends`                   | &check;    | &check; |  &check;     | &check; |         | 
    # If a report supports specifying a scan as the scope and a scan is specified, no other scope elements may be defined. 
    # In all other cases as many different types of supported scope elements can be specified in any combination. All 
    # reports except the `sql-query` format require at least one element to be specified as the scope.
    scope: ReportConfigScopeResource
    # The additional storage location and path.
    storage: ReportStorage
    # The template for the report (only required if the format is templatized).
    # 
    # Example: executive-overview
    template: str
    # The timezone the report generates in, such as `"America/Los_Angeles"`.
    # 
    # Example: America/Los_Angeles
    timezone: str
    # The identifiers of the users granted explicit access to the report.
    # 
    # Example: 7
    users: T.Sequence[int]
    # The version of the report Data Model to report against. Only used when the format is `"sql-query"`.
    # 
    # Example: 2.3.0
    version: str

ReportNexposeId = T.NewType('ReportNexposeId', int)
ReportId = T.Union[ReportNexposeId, str]
ReportList = T.Iterable[ReportId]
ReportMap = T.Dict[ReportId, Report]

