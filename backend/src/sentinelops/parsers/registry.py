"""Lookup of parsers by ``log.source_type``."""

from __future__ import annotations

from collections.abc import Mapping

from sentinelops.normalize.schema import SourceType
from sentinelops.parsers.base import Parser
from sentinelops.parsers.journald import JournaldJsonParser
from sentinelops.parsers.json_mapped import JsonMappedParser, MappingProfile
from sentinelops.parsers.syslog_rfc3164 import SyslogRfc3164Parser
from sentinelops.parsers.syslog_rfc5424 import SyslogRfc5424Parser
from sentinelops.parsers.windows_evtx import WindowsEvtxParser
from sentinelops.parsers.windows_json import WindowsJsonParser
from sentinelops.parsers.windows_xml import WindowsXmlParser

_FIXED: dict[str, type[Parser]] = {
    SourceType.WINDOWS_EVTX.value: WindowsEvtxParser,
    SourceType.WINDOWS_XML.value: WindowsXmlParser,
    SourceType.WINDOWS_JSON.value: WindowsJsonParser,
    SourceType.SYSLOG_3164.value: SyslogRfc3164Parser,
    SourceType.SYSLOG_5424.value: SyslogRfc5424Parser,
    SourceType.JOURNALD_JSON.value: JournaldJsonParser,
}


class UnknownSourceTypeError(LookupError):
    pass


def source_types(profiles: Mapping[str, MappingProfile]) -> list[str]:
    return sorted([*_FIXED, *(p.source_type for p in profiles.values())])


def get_parser(source_type: str, profiles: Mapping[str, MappingProfile]) -> Parser:
    fixed = _FIXED.get(source_type)
    if fixed is not None:
        return fixed()
    if source_type.startswith("json:"):
        profile = profiles.get(source_type.removeprefix("json:"))
        if profile is not None:
            return JsonMappedParser(profile)
    raise UnknownSourceTypeError(source_type)
