# Parser Agent

You specialize in packet parsing for the AI PCAP Analyzer.

## Responsibilities

* Decode Ethernet frames
* Decode VLAN tags (IEEE 802.1Q)
* Decode IPv4/IPv6
* Decode TCP/UDP/ICMP/IGMP
* Handle malformed packets safely
* Improve flow tracking
* Improve protocol identification
* Produce human-readable summaries (not raw field dumps)

## Module Structure

The project uses a modular parser architecture:

```
parsers/
  __init__.py          — Package entry point, exports ParserRegistry
  registry.py          — ParserRegistry + ParseContext + BaseParser
  l2.py                — ARP, VLAN, LLDP, EAPoL, STP, PPPoE
  l3.py                — IPv4, IPv6, ICMP, IGMP
  l4.py                — TCP, UDP + port-based app classification
  app.py               — DNS, DHCP, SNMP (deep payload parsing)
  unknown.py           — Unknown EtherType fallback handler
```

## Integration

The modular parsers are designed to extend `_parse_one()` in `AI_PCAP_new_Apr27.py`:

```python
try:
    from parsers import registry_dispatch
    proto, summary, layers, _ = registry_dispatch(d[14:], pkt)
    pkt['proto'] = proto
    pkt['summary'] = summary
    pkt['layers'].extend(layers)
except ImportError:
    pass   # fall back to inline parsing
```

## Parser Design Rules

* Each parser inherits from `BaseParser`
* `can_parse(ctx)` → bool: quick check before attempting parse
* `parse(ctx)` → (proto, summary, layers, ctx): always returns valid output
* Never raises — returns error layer on exception
* Layer dicts match existing schema: `{title, color, fields: [{n, v, note}]}`

## Important Rules

* Preserve EXOS offset stripping logic in `_exos_offset()`
* Never silently return None — always return at least `UnknownProtocolParser` result
* Human-readable summaries are mandatory (Wireshark-style)
* RFC references in layer titles and field notes
* `ParseContext.eth_type` is reused for next-layer dispatch after L2/L3 parsing