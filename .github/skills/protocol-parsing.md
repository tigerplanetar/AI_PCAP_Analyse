# Protocol Parsing Skill

You specialize in accurate packet decoding and human-readable protocol interpretation.

Your goal is to decode packets similarly to Wireshark-style analysis while keeping explanations easy to understand.

---

# Core Responsibilities

* Parse packet headers correctly
* Validate protocol structure
* Decode fields accurately
* Detect malformed packets
* Generate meaningful summaries
* Interpret protocol behavior
* Correlate request/reply traffic
* Produce human-readable explanations

---

# Parsing Philosophy

Packet decoding is NOT only extracting bytes.

The parser must:

* understand protocol meaning
* identify communication intent
* generate readable summaries
* explain behavior clearly

The parser should behave like an intelligent protocol analyzer.

---

# Important Requirement

Do NOT display only raw fields when protocol meaning is known.

Bad Example:

```text id="msm4yk"
ARP 00:11:22:33:44:55 10.1.1.1
```

Good Example:

```text id="b7evfr"
ARP Request: Who has 10.1.1.1? Tell 10.1.1.10
```

Good Example:

```text id="h5ysw7"
ARP Reply: 10.1.1.1 is at 00:11:22:33:44:55
```

Human-readable summaries are mandatory.

---

# ARP Parsing Rules

## ARP Request

Display:

```text id="2hzy3u"
Who has <target_ip>? Tell <sender_ip>
```

Example:

```text id="p7c9g8"
ARP Request: Who has 10.1.1.1? Tell 10.1.1.10
```

---

## ARP Reply

Display:

```text id="sgr3gn"
<sender_ip> is at <sender_mac>
```

Example:

```text id="sxhl9z"
ARP Reply: 10.1.1.1 is at aa:bb:cc:dd:ee:ff
```

Do NOT show unclear MAC/IP combinations without explanation.

---

# TCP Parsing Rules

## SYN Packet

```text id="c4gz2q"
TCP SYN: Client attempting to establish connection
```

---

## SYN-ACK

```text id="2aw1m6"
TCP SYN-ACK: Server accepted connection request
```

---

## FIN

```text id="4x5d3n"
TCP FIN: Connection closing gracefully
```

---

## RST

```text id="5f87ow"
TCP RST: Connection reset unexpectedly
```

---

# ICMP Parsing Rules

## Echo Request

```text id="vmljj2"
ICMP Echo Request (Ping)
```

---

## Echo Reply

```text id="8wo8f7"
ICMP Echo Reply received
```

---

## Destination Unreachable

```text id="0kucyv"
ICMP Destination Unreachable
```

Include reason code meaning whenever possible.

---

# DHCP Parsing Rules

Display DHCP state clearly:

Examples:

```text id="ztz70f"
DHCP Discover: Client searching for DHCP server
```

```text id="eqx67o"
DHCP Offer: Server offering IP address
```

```text id="u09v6u"
DHCP Request: Client requesting offered IP
```

```text id="q4s8ja"
DHCP ACK: Lease confirmed successfully
```

---

# DNS Parsing Rules

Examples:

```text id="8ofq0y"
DNS Query: example.com
```

```text id="1y0r2o"
DNS Response: example.com resolved to 93.184.216.34
```

---

# HTTP Parsing Rules

Examples:

```text id="gd5l2y"
HTTP GET request for /index.html
```

```text id="p2v4ws"
HTTP 200 OK response
```

---

# Unknown Protocol Handling

Unknown traffic must still provide useful information.

Example:

```text id="h94i6p"
Unknown EtherType 0x88b5 detected
```

Example:

```text id="e6t5vb"
Unknown UDP traffic observed on port 50000
```

Never leave summary blank.

---

# Malformed Packet Handling

If packet is malformed:

* explain why
* identify missing bytes
* identify invalid fields
* continue parsing safely when possible

Example:

```text id="tq3j0w"
Malformed IPv4 packet: header length exceeds packet size
```

---

# Modular Parser Architecture (parsers/ package)

Parsing logic is now split into a modular `parsers/` package that extends — but does not replace — the existing `_parse_one()` function in `AI_PCAP_new_Apr27.py`.

## Module layout

| Module | Purpose |
|---|---|
| `parsers/__init__.py` | Package entry; exports `registry_dispatch`, `ParserRegistry`, `ParseContext` |
| `parsers/registry.py` | `ParseContext` dataclass, `BaseParser` ABC, `ParserRegistry` dispatch engine |
| `parsers/l2.py` | ARP, VLAN/802.1Q, LLDP, EAPoL, STP/RSTP, PPPoE |
| `parsers/l3.py` | IPv4, IPv6, ICMP, IGMP |
| `parsers/l4.py` | TCP, UDP with app-layer classification |
| `parsers/app.py` | DNS, DHCP, SNMP |
| `parsers/unknown.py` | Fallback + heuristic EtherType identification |

## Integration in _parse_one()

```python
try:
    from parsers import registry_dispatch
    extra_layers = registry_dispatch(raw_bytes, pkt_dict)
    if extra_layers:
        pkt_dict["layers"].extend(extra_layers)
except ImportError:
    pass
```

## ParseContext flow

```
raw bytes → ParseContext → ParserRegistry.dispatch()
  → try each BaseParser in priority order (lower = first)
  → can_parse() → parse() → layer dict list
```

## Parser priority conventions

| Priority | Layer |
|---|---|
| 10 | VLAN stripping (outermost) |
| 20 | L2 (ARP, LLDP, EAPoL, STP) |
| 40 | L3 (IPv4, IPv6) |
| 50 | ICMP, IGMP |
| 60 | TCP, UDP |
| 70+ | App layer (DNS, DHCP, SNMP) |
| 999 | Unknown/fallback |

---

# Unknown Protocol Handling (parsers/unknown.py)

`UnknownProtocolParser` (priority 999) is the guaranteed fallback.

Capabilities:
- `_heuristic_identify()` — pattern matching on payload bytes
- `_oui_vendor()` — OUI→vendor lookup (Cisco, Extreme Networks, VMware, etc.)
- Recognises 40+ known EtherTypes including Extreme Networks 0x88B5–0x88B7

Standalone helper for enriching unknown packets:

```python
from parsers.unknown import enrich_unknown_packet
enrich_unknown_packet(pkt_dict)  # adds heuristic findings to existing pkt
```

---

# RFC-Aware Parsing

When possible:

* validate protocol behavior
* identify RFC violations
* explain expected behavior

Key references implemented in parsers/:

| Protocol | RFC | Parser |
|---|---|---|
| ARP | RFC 826 | `parsers/l2.py` |
| VLAN | IEEE 802.1Q | `parsers/l2.py` |
| LLDP | IEEE 802.1AB | `parsers/l2.py` |
| EAPoL | IEEE 802.1X | `parsers/l2.py` |
| STP/RSTP | IEEE 802.1D/w | `parsers/l2.py` |
| PPPoE | RFC 2516 | `parsers/l2.py` |
| IPv4 | RFC 791 | `parsers/l3.py` |
| ICMP | RFC 792 | `parsers/l3.py` |
| IGMP | RFC 3376 | `parsers/l3.py` |
| IPv6 | RFC 8200 | `parsers/l3.py` |
| TCP | RFC 793 | `parsers/l4.py` |
| UDP | RFC 768 | `parsers/l4.py` |
| DNS | RFC 1035 | `parsers/app.py` |
| DHCP | RFC 2131 | `parsers/app.py` |
| SNMP | RFC 3411 | `parsers/app.py` |

---

# Human-Readable Summary Rules

Every packet must contain:

* protocol name
* communication meaning
* source/destination context
* action description

The summary should help users understand traffic instantly.

---

# Wireshark-Style Behavior

The parser should behave similarly to Wireshark:

* meaningful packet summaries
* request/reply correlation
* readable protocol interpretation
* protocol-aware field decoding
* consistent formatting
* understandable outputs

---

# Important Rules

* Never show only raw fields when meaning is known
* Never generate confusing summaries
* Never silently fail parsing
* Always provide readable explanations
* Always validate packet structure
* New parsers must not break existing `_parse_one()` output
* Layer dicts must use schema: `{title, color, fields: [{n, v, note}]}`
* Always produce meaningful summaries
* Prefer clarity over raw technical output

---

# Project Goal

The parser is not just decoding bytes.

It is translating network traffic into human-understandable communication behavior.
