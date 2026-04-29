# Dashboard UI Skill

You specialize in the AI PCAP Analyzer dashboard UI.

The dashboard must follow the structure, workflow, visual behavior, and interaction style defined in:

* NA_dashboard.html

This file is the primary UI reference and source of truth for frontend behavior.

---

# UI Mission

The dashboard is not a simple webpage.

It is an interactive:

* network analyzer
* packet investigation console
* AI troubleshooting workspace
* flow visualization platform
* protocol analysis dashboard

The UI should feel modern, intelligent, responsive, and professional.

Inspired by:

* Wireshark-style workflows
* cybersecurity dashboards
* terminal-inspired interfaces
* AI-assisted analysis platforms

---

# Design Requirements

Follow the NA_dashboard.html design system:

## Theme

* Dark cyber-style UI
* Neon accent colors
* Grid background
* Terminal-inspired visuals
* Professional network engineering appearance

---

# Typography

Use:

* modern sans-serif fonts
* monospace fonts for:

  * packet data
  * terminal
  * IPs
  * ports
  * protocol fields

Readable spacing is mandatory.

---

# Core Dashboard Sections

The dashboard should include:

## Hero Section

Display:

* project branding
* analyzer title
* status indicators
* active AI backend
* capture status

---

## Packet Table

Must behave similarly to Wireshark.

Requirements:

* packets appear immediately
* row coloring by protocol
* sortable columns
* searchable packets
* protocol filtering
* flow filtering
* timestamps
* source/destination
* protocol
* length
* readable summary

The table is the heart of the UI.

---

# Packet Details Pane

When packet selected:

* expand protocol layers
* show decoded fields
* show RFC references
* show human-readable explanations

Support:

* Ethernet
* VLAN
* ARP
* IPv4
* IPv6
* TCP
* UDP
* ICMP
* DNS
* DHCP
* LLDP
* unknown protocols

---

# Hex Dump Viewer

Must display:

* offsets
* hexadecimal bytes
* ASCII representation

Requirements:

* synchronized highlighting
* scrollable
* monospace alignment
* readable formatting

---

# Flow Timeline View

Display:

* conversations
* TCP handshakes
* request/reply relationships
* packet sequences
* anomalies

The UI should visually explain communication behavior.

---

# Protocol Statistics

Display:

* protocol counts
* percentages
* top talkers
* bandwidth usage
* flow counts

Charts must render immediately.

---

# AI Analysis Panel

The AI panel is a core feature.

Requirements:

* AI troubleshooting chat
* packet explanations
* anomaly summaries
* RFC explanations
* EXOS command suggestions

Support:

* Ollama
* Claude
* OpenAI

The AI panel should feel integrated into packet analysis workflow.

---

# Browser Terminal

Requirements:

* SSH terminal
* Telnet fallback
* switch interaction
* live capture execution

Behavior:

* responsive
* non-blocking
* reconnect handling
* clean ANSI rendering

---

# UI Behavior Rules

The UI must:

* update dynamically
* avoid page reloads
* support large PCAPs
* remain responsive
* avoid broken rendering

Animations should be smooth but lightweight.

---

# Filtering Features

Support:

* protocol filter
* IP filter
* port filter
* VLAN filter
* TCP stream filter
* flow filter
* anomaly filter

Filtering should behave similarly to Wireshark display filters.

---

# Unknown Traffic Display

Unknown traffic must still appear properly.

Examples:

```text id="9mcl3u"
UNKNOWN_PROTO
ETHER_TYPE_0x88b5
IP_PROTO_143
```

Never hide unmatched packets.

---

# Error Handling

The dashboard should gracefully handle:

* malformed packets
* missing fields
* empty captures
* unsupported protocols
* large PCAP files
* AI backend failures
* terminal disconnects

Always show user-friendly messages.

---

# Performance Requirements

The dashboard should:

* load quickly
* render thousands of packets smoothly
* avoid memory leaks
* avoid blocking UI operations

Large packet tables should use:

* lazy rendering
* virtual scrolling
* optimized filtering

---

# Responsive Design

Support:

* desktop monitors
* laptops
* smaller screens

The packet table and details pane must remain usable.

---

# Flow Data Integration (flow_engine.py)

The analysis dict passed to `make_html()` may include:

```python
analysis["flows"]      # List of FlowRecord dicts from reconstruct_flows()
analysis["flow_stats"] # Stats dict: top_talkers, proto_distribution, total_flows
```

**Flow dict schema:**
```python
{
  "flow_id":    "tcp-10.0.0.1:1234-10.0.0.2:80",
  "layer":      "L4",
  "proto":      "HTTP",
  "endpoints":  "10.0.0.1:1234 ↔ 10.0.0.2:80",
  "pkts":       42,
  "bytes":      8192,
  "tcp_state":  "closed",   # handshake/established/closing/closed/reset/half-open
  "is_complete": True,
  "is_one_way":  False,
  "has_errors":  False,
  "pkt_ids":    [1, 3, 5, ...],
  "summary":    "HTTP session: 42 pkts, 8192 bytes",
  "rfc_ref":    "RFC 2616"
}
```

Render flows in the **Flow Timeline View** by reading `analysis["flows"]`. Color-code by `tcp_state`.

---

# Anomaly Data Integration (anomaly_rules.py)

`analysis["anomalies"]` contains findings from both `_rule_engine()` and `run_extended_rules()`.

**Finding schema:**
```python
{
  "category": "Security",
  "layer":    "L2",
  "title":    "ARP Flood Detected",
  "severity": "high",
  "detail":   "420 ARP requests in 10s exceeds threshold",
  "evidence": {"arp_rate_pps": 42},
  "protocol": "ARP",
  "rfc_ref":  "RFC 826"
}
```

Use `severity` (`critical`, `high`, `medium`, `low`, `info`) to color-code anomaly badges.

---

# AI Summary Integration (ai_summaries.py)

Human-readable packet explanations are available via `explain_packet(pkt)`. Render these in the Packet Details Pane as a friendly description block above the hex dump.

---

# Important Rules

* Do not break existing dashboard workflow
* Preserve NA_dashboard.html visual identity
* Preserve cyber-style appearance
* Preserve protocol color consistency
* Preserve expandable packet layers
* Preserve packet investigation workflow
* When `analysis["flows"]` is present, render the Flow Timeline section
* When anomalies have `rfc_ref`, display it as a linked badge
* Severity badge colors: critical=red, high=orange, medium=yellow, low=blue, info=grey

---

# Expected User Experience

Users should feel:

* they are using a professional network analyzer
* packet investigation is easy
* AI assistance is integrated naturally
* flows are understandable visually
* troubleshooting becomes faster

The UI should make complex packet analysis feel simple and intuitive.

---

# Project Goal

The dashboard is the visual intelligence layer of the AI PCAP Analyzer.

Its purpose is to transform raw packet data into:

* understandable traffic behavior
* interactive analysis
* visual troubleshooting
* AI-assisted diagnostics
* professional workflow experience
