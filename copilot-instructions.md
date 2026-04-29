# AI PCAP Analyzer — Copilot Instructions

## Project Overview

AI PCAP Analyzer is an AI-powered network packet analysis and troubleshooting platform for Extreme Networks EXOS environments.

The project combines:

* live switch packet capture
* PCAP parsing
* protocol decoding
* flow reconstruction
* AI-assisted troubleshooting
* browser terminal access
* interactive dashboard visualization

The goal is to make packet analysis easier, faster, and more human-friendly than traditional analyzers.

Inspired by:

* Wireshark workflows
* AI-assisted diagnostics
* cybersecurity dashboards
* network engineering troubleshooting tools

---

# Primary Project References

## Main UI Reference

* NA_dashboard.html

This file defines:

* dashboard structure
* visual identity
* workflow behavior
* interaction design
* animations
* cyber-style theme
* protocol visualization behavior

Treat this file as the frontend source of truth.

---

## Main Backend Reference

* AI_PCAP_new_Apr27.py

This file contains:

* packet parsing logic
* protocol decoders
* EXOS capture handling
* AI integration
* dashboard backend behavior
* flow logic
* terminal integration

---

# Architecture Overview

The project contains several intelligent subsystems:

| Component        | Purpose                                 |
| ---------------- | --------------------------------------- |
| Capture Engine   | Retrieve packets from EXOS switches     |
| Protocol Parser  | Decode and interpret packets            |
| Flow Engine      | Reconstruct sessions and conversations  |
| Dashboard UI     | Visualize traffic and analysis          |
| AI Engine        | Explain traffic and troubleshoot issues |
| Browser Terminal | SSH/Telnet switch interaction           |
| Anomaly Engine   | Detect suspicious or abnormal behavior  |

---

# Agent System

The project uses specialized AI agents.

## Capture Agent

Responsibilities:

* SSH capture
* Telnet fallback
* EXOS debug packet capture
* tcpdump integration
* SCP download
* PCAP validation
* retry handling
* actionable error reporting

Supports:

* any reachable EXOS switch

---

## Flow Agent

Responsibilities:

* reconstruct all network conversations
* track TCP sessions
* group UDP traffic
* correlate ARP/DNS/DHCP exchanges
* maintain flow timelines
* track unknown protocols
* generate flow summaries

Every packet must belong to a flow.

---

## AI Agent

Responsibilities:

* explain protocols
* summarize captures
* detect anomalies
* troubleshoot networking issues
* explain RFC behavior
* analyze unknown traffic
* provide EXOS debugging commands
* generate human-readable analysis

The AI layer is a core intelligence system.

---

# Skills System

## Protocol Parsing Skill

Requirements:

* accurate decoding
* human-readable summaries
* Wireshark-style interpretation
* malformed packet handling
* RFC-aware analysis
* request/reply correlation
* meaningful protocol explanations

The parser must explain communication behavior, not only decode bytes.

---

## Dashboard UI Skill

Requirements:

* follow NA_dashboard.html behavior
* cyber-style dark theme
* responsive rendering
* packet table visualization
* flow timeline support
* AI panel integration
* hex dump support
* expandable protocol layers
* high performance rendering

---

## EXOS Capture Skill

Requirements:

* prefer SSH
* Telnet fallback
* validate non-empty captures
* support tcpdump
* preserve EXOS header handling
* detect failed captures safely

---

# Packet Parsing Philosophy

Packet analysis is not only binary decoding.

The parser must:

* explain packet meaning
* generate readable summaries
* identify communication behavior
* correlate request/reply traffic
* explain anomalies clearly

Example:

Bad:

```text
ARP aa:bb:cc:dd:ee:ff 10.1.1.1
```

Good:

```text
ARP Reply: 10.1.1.1 is at aa:bb:cc:dd:ee:ff
```

Human-readable summaries are mandatory.

---

# Flow Tracking Philosophy

The system should behave similarly to Wireshark conversations.

Track:

* Layer 2 flows
* Layer 3 flows
* TCP sessions
* UDP conversations
* request/reply protocols
* unknown traffic
* malformed traffic

Unknown traffic must still appear in analysis.

Never silently drop packets.

---

# AI Analysis Philosophy

The AI must behave like:

* network engineer
* troubleshooting assistant
* protocol expert
* RFC-aware analyzer
* security analyst
* EXOS support engineer

The AI should:

* simplify troubleshooting
* explain networking clearly
* detect anomalies intelligently
* provide actionable guidance

Even unsupported or unknown traffic should receive best-effort analysis.

---

# Dashboard Philosophy

The dashboard is not a normal webpage.

It is:

* an investigation console
* a protocol analysis workspace
* an AI troubleshooting platform
* a traffic visualization system

The UI should feel:

* modern
* intelligent
* responsive
* professional
* cyber-style
* network-engineering focused

---

# UI Requirements

The dashboard must support:

* packet table
* protocol filtering
* flow filtering
* packet details pane
* hex viewer
* flow timeline
* AI chat
* terminal integration
* protocol statistics
* anomaly highlighting

Charts and tables must render immediately.

---

# Error Handling Rules

Never silently fail.

Always:

* explain errors clearly
* validate packet structures
* validate capture files
* detect malformed traffic
* show troubleshooting guidance
* provide recovery suggestions

Examples:

* malformed packet
* invalid PCAP
* SSH timeout
* SCP failure
* unsupported protocol
* AI backend unavailable

---

# Unknown Traffic Rules

Unknown protocols must still:

* appear in UI
* belong to flows
* generate summaries
* receive AI analysis

Examples:

```text
Unknown EtherType 0x88b5
```

```text
Unknown UDP traffic on port 50000
```

Never leave packet summaries blank.

---

# RFC-Aware Analysis

Whenever possible:

* identify RFC behavior
* explain expected behavior
* identify protocol violations
* explain malformed fields

Examples:

* RFC 791 → IPv4
* RFC 792 → ICMP
* RFC 793 → TCP
* RFC 826 → ARP
* RFC 2131 → DHCP
* RFC 1035 → DNS

---

# Performance Requirements

The system should:

* handle large PCAPs
* avoid UI freezes
* avoid memory leaks
* support fast filtering
* support lazy rendering
* support optimized flow tracking

---

# Coding Standards

## Python

* modular functions
* reusable parsing logic
* strong error handling
* descriptive naming
* detailed logging
* avoid duplicated code

---

## Frontend

* reusable UI components
* responsive layouts
* lightweight rendering
* avoid broken animations
* maintain dark cyber-style theme

---

# Important Rules

* Do not remove existing protocol support
* Preserve EXOS compatibility
* Preserve dashboard workflow
* Preserve protocol color consistency
* Preserve expandable protocol layers
* Preserve human-readable summaries
* Preserve unknown traffic visibility

---

# Project Mission

This project is not only a packet viewer.

It is an AI-powered network troubleshooting platform designed to:

* simplify packet analysis
* improve troubleshooting speed
* explain networking visually
* assist engineers intelligently
* reduce debugging complexity
* make protocol analysis more human-friendly

The AI should make packet analysis smarter and easier than traditional 
tools.






# Existing Project Status

This project already contains a partially completed implementation.

Existing functionality already implemented includes:

* PCAP parsing
* Ethernet parsing
* VLAN parsing
* ARP decoding
* IPv4 parsing
* TCP/UDP parsing
* ICMP analysis
* DHCP parsing
* DNS parsing
* SNMP parsing
* LLDP handling
* EXOS packet offset stripping
* dashboard rendering
* protocol statistics
* packet detail pane
* hex viewer
* anomaly detection engine
* tshark enrichment support
* AI backend integration
* browser terminal support
* EXOS switch integration

Main implementation file:

* AI_PCAP_new_Apr27.py

The current implementation should be treated as the existing foundation of the project.

---

# Important Development Rules

Do NOT rewrite the entire project unnecessarily.

Instead:

* improve existing architecture
* modularize existing parsers
* extend current functionality
* preserve working logic
* improve maintainability
* improve readability
* improve scalability

Preserve:

* existing protocol behavior
* EXOS compatibility
* dashboard workflows
* AI integrations
* packet summaries
* anomaly detection logic

---

# Architecture Evolution Goal

The project is evolving from:

* a monolithic packet analyzer script

into:

* a modular AI-assisted network investigation platform

The architecture should gradually transition toward:

* modular parsers
* flow reconstruction engine
* AI explanation engine
* scalable dashboard architecture
* reusable protocol modules

without breaking existing functionality.

---

# Existing Parsing Coverage

The parser already supports:

* Ethernet
* VLAN
* ARP
* IPv4
* IPv6
* ICMP
* TCP
* UDP
* DHCP
* DNS
* SNMP
* LLDP
* EAPoL
* IGMP
* PPPoE
* unknown EtherTypes

Future improvements should extend this system rather than replace it.

---

# Existing Dashboard Features

The dashboard already includes:

* packet table
* protocol statistics
* hex dump viewer
* protocol detail pane
* timeline behavior
* terminal rendering
* AI analysis integration
* protocol coloring
* anomaly visualization

New UI changes should preserve the current workflow.

---

# Existing AI Features

The project already supports:

* Ollama
* Claude
* OpenAI

AI improvements should focus on:

* better summaries
* better anomaly explanations
* flow intelligence
* RFC-aware analysis
* troubleshooting guidance

---

# Refactoring Philosophy

Prefer:

* incremental improvements
* modular refactoring
* reusable helper functions
* backward compatibility

Avoid:

* full rewrites
* breaking existing parsing logic
* removing working protocol support

---

# Long-Term Vision

This project is evolving into an AI-assisted network investigation platform.

The goal is:

* not only packet decoding
* but intelligent troubleshooting
* flow reconstruction
* AI-generated explanations
* EXOS-aware diagnostics
* human-readable packet analysis

The architecture should remain modular and scalable.

---

# New Modules — Apr 2026 Architecture Evolution

The following modules have been added as optional add-ons to `AI_PCAP_new_Apr27.py`. They extend functionality without breaking existing code. Each is imported with a `try/except ImportError` guard.

## parsers/ — Modular Protocol Parser Package

Location: `.github/docs/parsers/`

| Module | Contents |
|---|---|
| `__init__.py` | `ParserRegistry`, `ParseContext`, `registry_dispatch` |
| `registry.py` | `BaseParser` ABC, `ParserRegistry` with priority dispatch |
| `l2.py` | ARP, VLAN, LLDP, EAPoL, STP/RSTP, PPPoE (RFC 826, 802.1Q, 802.1AB, 802.1X, 802.1D, RFC 2516) |
| `l3.py` | IPv4, IPv6, ICMP, IGMP (RFC 791, 8200, 792, 3376) |
| `l4.py` | TCP, UDP with app-layer classification (RFC 793, 768) |
| `app.py` | DNS, DHCP, SNMP (RFC 1035, 2131, 3411) |
| `unknown.py` | Fallback heuristic parser + `enrich_unknown_packet()` |

Integration point in `_parse_one()`:

```python
try:
    from parsers import registry_dispatch
    extra_layers = registry_dispatch(raw_bytes, pkt_dict)
    if extra_layers:
        pkt_dict["layers"].extend(extra_layers)
except ImportError:
    pass
```

Layer dicts use the existing schema: `{title, color, fields: [{n, v, note}]}`

---

## flow_engine.py — Flow Reconstruction Engine

Location: `.github/docs/flow_engine.py`

Provides Wireshark-style conversation tracking with 3-tier hierarchy (L4 → L3 → L2).

Public API:

```python
from flow_engine import reconstruct_flows, pair_arp_exchanges
flows, stats = reconstruct_flows(packets)
arp_info     = pair_arp_exchanges(packets)
```

Output goes into `analysis["flows"]` and `analysis["flow_stats"]` for dashboard rendering.

---

## ai_summaries.py — RFC-Aware AI Summary Generation

Location: `.github/docs/ai_summaries.py`

Enriches AI prompts with RFC context, capture summaries, and EXOS-specific recommendations.

```python
from ai_summaries import (
    explain_packet,               # per-packet explanation
    PacketSummaryEngine,          # capture-level summaries
    build_ai_prompt,              # enriched prompt builder
    anomaly_to_english,           # anomaly dict → plain English
    generate_exos_recommendations # anomalies → EXOS CLI commands
)
```

Contains `RFC_DB` with 14 protocol entries. Used to enrich `ask_ai()` prompts.

---

## anomaly_rules.py — Extended Anomaly Detection Rules

Location: `.github/docs/anomaly_rules.py`

Extends the existing `_rule_engine()` without replacing it. Rules added:

- ARP flood / IP conflicts / ARP%
- DHCP starvation / multiple servers / NAK storm
- DNS tunneling (high-entropy names) / unanswered queries
- SNMP trap storm / SetRequest / multiple managers
- TCP zero-window / null scan / Xmas scan / RST storm
- Unknown proto analysis, LLDP topology, VLAN analysis

Integration:

```python
from anomaly_rules import run_extended_rules, merge_findings
extended = run_extended_rules(packets, analysis, features)
analysis["anomalies"] = merge_findings(analysis.get("anomalies", []), extended)
```

Finding schema mirrors existing `_rule_engine()` output: `{category, layer, title, severity, detail, evidence, protocol, rfc_ref}`
