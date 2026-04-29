"""
parsers/ — Modular Protocol Parser Package
==========================================
Incremental refactoring of AI_PCAP_new_Apr27.py protocol parsing logic.

Two complementary APIs are available:

1. Registry API (original)
   -----------------------
   Dispatch-based pattern using BaseParser subclasses and ParseContext.
   Best for the full pipeline where the registry selects the right parser.

       from parsers import ParserRegistry, ParseContext, registry_dispatch
       proto, summary, layers, ctx = registry_dispatch(raw[14:], pkt)

2. Standalone API (new — individual protocol modules)
   ----------------------------------------------------
   Simple functions extracted directly from _parse_one() logic.
   Best for targeted use, testing, or incremental integration.

       from parsers.ethernet import parse_ethernet
       from parsers.vlan     import parse_vlan
       from parsers.arp      import parse_arp
       from parsers.ipv4     import parse_ipv4, parse_icmp, parse_igmp
       from parsers.tcp      import parse_tcp
       from parsers.udp      import parse_udp

   Each function:
     - Accepts (payload: bytes, pkt: dict, **kwargs)
     - Mutates pkt in-place (same schema as _parse_one())
     - Appends layer dicts to pkt['layers']
     - Returns None on malformed/short input — never raises

3. Shared constants (new)
   -----------------------
       from parsers.constants import SERVICES, RFC_REF, DSCP_NAMES, ...

Integration with AI_PCAP_new_Apr27.py
--------------------------------------
Add the following guard to _parse_one() to optionally use individual parsers:

    try:
        from parsers.ethernet import parse_ethernet
        from parsers.vlan     import parse_vlan
        from parsers.arp      import parse_arp
        from parsers.ipv4     import parse_ipv4, parse_icmp, parse_igmp
        from parsers.tcp      import parse_tcp
        from parsers.udp      import parse_udp
        _MODULAR_PARSERS = True
    except ImportError:
        _MODULAR_PARSERS = False   # fall back to inline parsing

Backward Compatibility
----------------------
All functions reuse the same field/layer dict schema used by _parse_one().
The registry falls back gracefully to UnknownProtocolParser for
unrecognised protocols.

Module overview
---------------
  constants.py  Shared lookup tables and utility helpers (no side-effects)
  registry.py   ParseContext, BaseParser, ParserRegistry
  ethernet.py   Ethernet II frame parser
  vlan.py       IEEE 802.1Q VLAN tag parser
  arp.py        ARP parser (RFC 826)
  ipv4.py       IPv4, ICMP, IGMP parsers (RFC 791, 792, 3376)
  tcp.py        TCP segment parser with options (RFC 793, 7323)
  udp.py        UDP datagram + SNMP detection (RFC 768, 3411)
  l2.py         Registry parsers: ARP, VLAN, LLDP, EAPoL, STP, PPPoE
  l3.py         Registry parsers: IPv4, IPv6, ICMP, IGMP
  l4.py         Registry parsers: TCP, UDP
  app.py        Registry parsers: DNS, DHCP, SNMP
  unknown.py    Fallback / heuristic parser + enrich_unknown_packet()
"""

# ── Registry API ──────────────────────────────────────────────────────────────
from parsers.registry import ParserRegistry, ParseContext, registry_dispatch

# ── Standalone protocol parsers ───────────────────────────────────────────────
from parsers.ethernet import parse_ethernet
from parsers.vlan     import parse_vlan
from parsers.arp      import parse_arp
from parsers.ipv4     import parse_ipv4, parse_icmp, parse_igmp
from parsers.tcp      import parse_tcp
from parsers.udp      import parse_udp

__all__ = [
    # Registry API
    "ParserRegistry",
    "ParseContext",
    "registry_dispatch",
    # Standalone parsers
    "parse_ethernet",
    "parse_vlan",
    "parse_arp",
    "parse_ipv4",
    "parse_icmp",
    "parse_igmp",
    "parse_tcp",
    "parse_udp",
]
