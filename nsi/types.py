from pathlib import Path
import typing as T

from . import logging

log = logging.new_log(__name__)

Url = T.NewType('Url', str)
Ip = T.NewType('Ip', str)
IpList = T.NewType('IpList', T.Sequence[Ip])
Regex = T.NewType('Regex', str)
RegexList = T.NewType('RegexList', T.Sequence[Regex])
Mac = T.NewType('Mac', str)
Port = T.NewType('Port', int)
Protocol = T.NewType('Protocol', str)
Timestamp = T.NewType('Timestamp', str)
Int = T.NewType("Int", str)
Float = T.NewType('Float', str)
Html = T.NewType('Html', str)

class ErrorJson(T.TypedDict):
    reason: T.Set[str] # slugs for error
    message: str # detailed message for failure

Outcome = T.Tuple[bool, T.Any | ErrorJson]