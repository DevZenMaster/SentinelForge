"""Parser registry for SentinelForge event normalization.

Maintains the prioritized catalog of source-specific parsers and evaluates
incoming raw event payloads to select the most specialized parser available.
"""

import logging
from typing import Any

from app.normalization.base import EventParser
from app.normalization.parsers.generic import GenericParser
from app.normalization.parsers.linux_auth import LinuxAuthParser
from app.normalization.parsers.web import WebParser

logger = logging.getLogger("sentinelforge.normalization")


class ParserRegistry:
    """Registry maintaining ordered parsers with universal fallback."""

    def __init__(self) -> None:
        self._parsers: list[EventParser] = []
        self._fallback_parser: EventParser = GenericParser()

    def register(self, parser: EventParser) -> None:
        """Register a parser before the fallback parser."""
        self._parsers.append(parser)

    def get_parser(self, source_type: str, raw_payload: dict[str, Any]) -> EventParser:
        """Find the first parser capable of handling the event, or return fallback."""
        for parser in self._parsers:
            try:
                if parser.can_parse(source_type=source_type, raw_payload=raw_payload):
                    return parser
            except Exception as exc:
                # Defensive check: faulty can_parse should not abort selection
                logger.warning(
                    "Parser '%s' can_parse raised exception: %s",
                    parser.parser_name,
                    exc,
                )
                continue
        return self._fallback_parser

    def get_parser_by_name(self, name: str) -> EventParser | None:
        """Look up a parser by its unique name."""
        if self._fallback_parser.parser_name == name:
            return self._fallback_parser
        for p in self._parsers:
            if p.parser_name == name:
                return p
        return None

    def list_parsers(self) -> list[dict[str, str]]:
        """List registered parser metadata."""
        all_parsers = [*self._parsers, self._fallback_parser]
        return [
            {
                "name": p.parser_name,
                "version": p.parser_version,
                "normalization_version": p.normalization_version,
            }
            for p in all_parsers
        ]


def build_default_registry() -> ParserRegistry:
    """Construct the standard production parser registry in priority order."""
    registry = ParserRegistry()
    registry.register(LinuxAuthParser())
    registry.register(WebParser())
    return registry


# Singleton default registry for standard normalization pipeline
default_registry: ParserRegistry = build_default_registry()
