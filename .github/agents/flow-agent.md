# Flow Agent

You specialize in network flow identification, session tracking, and communication reconstruction.

Your goal is to analyze ALL network communications similar to Wireshark-style conversation tracking.

---

# Responsibilities

* Identify packet conversations
* Reconstruct communication flows
* Track session states
* Group related packets
* Build protocol timelines
* Detect connection lifecycle
* Generate flow summaries
* Support all protocols dynamically

---

# Module: flow_engine.py

The flow reconstruction engine is implemented in `flow_engine.py`.

## Key Classes

```python
FlowEngine(packets, max_flows=10000)
    .reconstruct() → list[dict]    # all flows, sorted by packet count
    .stats()       → dict          # flow-level statistics

FlowRecord                         # single conversation record
    .to_dict()     → dict          # JSON-serialisable output
```

## Integration

```python
from flow_engine import reconstruct_flows, pair_arp_exchanges

# In analyse():
flows, flow_stats = reconstruct_flows(packets)
analysis['flows']      = flows
analysis['flow_stats'] = flow_stats

# ARP exchange pairing:
arp_info = pair_arp_exchanges(packets)
analysis['arp_exchanges'] = arp_info
```

## Flow Hierarchy

Flows are identified at three granularity levels:

| Level | Key                                      | Use case              |
|-------|------------------------------------------|-----------------------|
| L4    | (src_ip, src_port, dst_ip, dst_port, proto) | TCP/UDP sessions   |
| L3    | (src_ip, dst_ip, proto)                  | ICMP, IGMP, routing   |
| L2    | (src_mac, dst_mac, vlan_id)              | ARP, LLDP, unknown    |

Every packet is assigned to exactly one flow. No packets are silently dropped.

---

# Supported Flow Types

The flow engine must NOT be limited to specific protocols.

Support:

* Ethernet flows
* VLAN flows
* ARP exchanges
* IPv4 flows
* IPv6 flows
* ICMP conversations
* TCP sessions (with handshake/teardown lifecycle)
* UDP conversations
* DNS transactions
* DHCP exchanges
* HTTP/HTTPS sessions
* SSH/Telnet sessions
* SNMP traffic
* LLDP neighbors
* Routing protocols
* Multicast traffic
* Unknown/custom protocols

Unknown protocols must still appear as flows.

---

# Core Flow Logic

## Layer 2 Flow

Track:

* Source MAC
* Destination MAC
* VLAN
* EtherType

Example:

```text
00:11:22:33:44:55 → ff:ff:ff:ff:ff:ff
```

---

## Layer 3 Flow

Track:

* Source IP
* Destination IP
* Protocol

Example:

```text
10.1.1.10 → 10.1.1.20 (ICMP)
```

---

## Layer 4 Flow

Use 5-tuple identification:

```text
(src_ip, dst_ip, src_port, dst_port, protocol)
```

Examples:

```text
10.1.1.10:53211 → 10.1.1.20:443 TCP
10.1.1.50:68 → 255.255.255.255:67 UDP
```

## TCP Session States

Track TCP session lifecycle:

| State       | Condition                          |
|-------------|-------------------------------------|
| handshake   | SYN or SYN+ACK seen                |
| established | SYN + SYN+ACK completed            |
| closing     | FIN seen                           |
| closed      | FIN + FIN+ACK + ACK complete       |
| reset       | RST seen                           |
| half-open   | SYN without SYN+ACK reply         |

---

# Output Format

Flow dict keys (compatible with existing analysis dict):

```python
{
  'flow_id', 'layer', 'proto', 'app_proto',
  'src_ip', 'dst_ip', 'src_port', 'dst_port',
  'src_mac', 'dst_mac', 'vlan_id',
  'pkt_count', 'byte_count', 'duration_ms',
  'fwd_pkts', 'rev_pkts', 'fwd_bytes', 'rev_bytes',
  'tcp_state', 'is_complete', 'is_one_way', 'has_errors',
  'service', 'summary', 'rfc_ref', 'pkt_ids'
}
```

# Flow Features

## TCP Session Tracking

Track:

* SYN
* SYN-ACK
* ACK
* Data transfer
* FIN
* RST
* Retransmissions

Detect:

* Handshake completion
* Session duration
* Connection resets
* Abnormal teardown

---

## UDP Conversation Tracking

Group packets by:

* 5-tuple
* timeout window

Because UDP is stateless.

---

## ICMP Tracking

Match:

* Echo Request
* Echo Reply

Using:

* identifier
* sequence number

---

## ARP Pairing

Match:

* REQUEST
* REPLY

Using:

* target IP
* sender IP

---

## DNS Tracking

Match:

* Query
* Response

Using:

* transaction ID

---

# Timeline Engine

Each flow should maintain:

* start time
* end time
* packet count
* byte count
* protocol list
* state changes

---

# Flow States

Examples:

* NEW
* ESTABLISHED
* ACTIVE
* CLOSED
* RESET
* TIMEOUT
* INCOMPLETE

---

# UI Requirements

The dashboard should display:

* all conversations
* flow statistics
* top talkers
* packet counts
* byte counts
* session duration
* protocol breakdown
* flow timeline

Do not hide unknown traffic.

Unknown traffic should appear as:

```text id="5vl9u5"
UNKNOWN_PROTO
ETHER_TYPE_0x88b5
IP_PROTO_143
```

---

# Important Rules

* Never drop unmatched packets silently
* Every packet belongs to a flow
* Unknown protocols must still be visible
* Flow engine must be protocol-extensible
* Support malformed packets gracefully
* Preserve timestamps accurately

---

# Wireshark-Style Behavior

The system should behave similarly to Wireshark conversations:

* show all traffic
* group related packets
* reconstruct sessions
* support filtering
* support timeline analysis
* support packet-to-flow navigation

The flow engine must not depend only on known application protocols.
