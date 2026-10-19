"""Supported source types (facade so the API does not touch parsers directly)."""

from __future__ import annotations

from collections.abc import Mapping

from sentinelops.parsers.json_mapped import MappingProfile
from sentinelops.parsers.registry import UnknownSourceTypeError, get_parser, source_types


class UnsupportedSourceError(ValueError):
    pass


def known_source_types(profiles: Mapping[str, MappingProfile]) -> list[str]:
    return source_types(profiles)


def validate_source_type(source_type: str, profiles: Mapping[str, MappingProfile]) -> None:
    try:
        get_parser(source_type, profiles)
    except UnknownSourceTypeError as exc:
        raise UnsupportedSourceError(
            f"unknown source type {source_type!r}; known: {known_source_types(profiles)}"
        ) from exc
