"""
parsers/registry.py — Protocol Parser Registry
===============================================
Central dispatch for modular protocol parsers.

Design
------
- ParserRegistry holds an ordered list of registered parsers
- dispatch() tries each parser in priority order
- Falls back to UnknownProtocolParser if nothing matches
- Preserves the layer dict schema from the main script

ParseContext carries all state a parser needs, avoiding global state.
"""

from __future__ import annotations
import struct
from dataclasses import dataclass, field
from typing import Optional


# ── ParseContext ──────────────────────────────────────────────────────────────

@dataclass
class ParseContext:
    """All state needed by any protocol parser during a single packet parse."""
    raw: bytes                          # original raw payload at current layer
    pkt: dict                           # accumulating packet dict (mutated in-place)
    eth_type: int = 0                   # current EtherType / next-protocol value
    src_mac: str = ''
    dst_mac: str = ''
    src_ip: str = ''
    dst_ip: str = ''
    src_port: int = 0
    dst_port: int = 0
    transport_proto: str = ''           # 'TCP' | 'UDP' | ''
    vlan_id: Optional[int] = None
    depth: int = 0                      # recursion guard
    extra: dict = field(default_factory=dict)   # parser-specific scratch space


# ── Base Parser ───────────────────────────────────────────────────────────────

class BaseParser:
    """
    All protocol parsers inherit from this.

    Subclasses must implement:
        can_parse(ctx)  → bool
        parse(ctx)      → (proto_name, summary, layers, updated_ctx)
    """
    priority: int = 100   # lower = tried first

    def can_parse(self, ctx: ParseContext) -> bool:  # pragma: no cover
        raise NotImplementedError

    def parse(self, ctx: ParseContext):  # pragma: no cover
        """Returns (proto_name: str, summary: str, layers: list[dict], ctx: ParseContext)."""
        raise NotImplementedError

    # ── Helpers shared by all parsers ─────────────────────────────────────

    @staticmethod
    def _mac(b: bytes) -> str:
        return ':'.join(f'{x:02x}' for x in b)

    @staticmethod
    def _ip4(b: bytes) -> str:
        return '.'.join(str(x) for x in b)

    @staticmethod
    def _layer(title: str, color: str, fields: list) -> dict:
        return {'title': title, 'color': color, 'fields': fields}

    @staticmethod
    def _field(name: str, value, note: str = '') -> dict:
        return {'n': name, 'v': str(value), 'note': note}

    @staticmethod
    def _error_layer(proto: str, reason: str) -> dict:
        return {
            'title': f'{proto} — Parse Error',
            'color': '#ef4444',
            'fields': [{'n': 'Error', 'v': reason, 'note': 'Parser caught an exception'}],
        }


# ── Parser Registry ───────────────────────────────────────────────────────────

class ParserRegistry:
    """
    Ordered registry of protocol parsers.

    Usage
    -----
        registry = ParserRegistry()
        registry.register(MyParser())
        proto, summary, layers, ctx = registry.dispatch(ctx)
    """

    def __init__(self):
        self._parsers: list[BaseParser] = []
        self._register_defaults()

    def register(self, parser: BaseParser):
        """Add a parser and keep the list sorted by priority."""
        self._parsers.append(parser)
        self._parsers.sort(key=lambda p: p.priority)

    def dispatch(self, ctx: ParseContext):
        """
        Try each registered parser in priority order.
        Returns (proto, summary, layers, ctx).
        Falls back to UnknownProtocolParser if nothing matches.
        """
        for parser in self._parsers:
            try:
                if parser.can_parse(ctx):
                    return parser.parse(ctx)
            except Exception as e:
                # Never crash — return error layer and continue
                return (
                    'ParseError',
                    f'Parser {type(parser).__name__} failed: {e}',
                    [BaseParser._error_layer(type(parser).__name__, str(e))],
                    ctx,
                )
        # Nothing matched
        from parsers.unknown import UnknownProtocolParser
        return UnknownProtocolParser().parse(ctx)

    def _register_defaults(self):
        """Register all built-in parsers in correct priority order."""
        from parsers.l2 import (
            ARPParser, VLANParser, LLDPParser, EAPoLParser, STPParser,
            PPPoEDiscoveryParser, PPPoESessionParser,
        )
        from parsers.l3 import (
            IPv4Parser, IPv6Parser, IGMPParser,
        )
        from parsers.l4 import TCPParser, UDPParser
        from parsers.app import DNSParser, DHCPParser, SNMPParser
        from parsers.unknown import UnknownProtocolParser

        for p in [
            VLANParser(),       # priority 10 — must strip VLAN before L3
            PPPoEDiscoveryParser(),
            PPPoESessionParser(),
            ARPParser(),
            LLDPParser(),
            EAPoLParser(),
            STPParser(),
            IPv4Parser(),
            IPv6Parser(),
            IGMPParser(),
            TCPParser(),
            UDPParser(),
            DNSParser(),
            DHCPParser(),
            SNMPParser(),
            UnknownProtocolParser(),
        ]:
            self.register(p)


# ── Convenience function ──────────────────────────────────────────────────────

_default_registry: Optional[ParserRegistry] = None


def registry_dispatch(raw: bytes, pkt: dict) -> tuple:
    """
    Top-level helper for optional integration with _parse_one().

    Usage in AI_PCAP_new_Apr27.py:
        try:
            from parsers import registry_dispatch
            proto, summary, layers, _ = registry_dispatch(d[14:], pkt)
            pkt['proto'] = proto
            pkt['summary'] = summary
            pkt['layers'].extend(layers)
        except ImportError:
            pass   # fall back to inline parsing
    """
    global _default_registry
    if _default_registry is None:
        _default_registry = ParserRegistry()

    ctx = ParseContext(raw=raw, pkt=pkt)
    if len(raw) >= 2:
        ctx.eth_type = struct.unpack('!H', raw[12:14])[0] if len(raw) >= 14 else 0
    return _default_registry.dispatch(ctx)
