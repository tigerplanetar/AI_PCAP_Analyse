"""
flow/ — Modular Flow Reconstruction Package
============================================
Wireshark-style conversation tracking for the AI PCAP Analyzer.

This package is a modular replacement and extension of flow_engine.py.
It is fully backward-compatible: reconstruct_flows() and pair_arp_exchanges()
have identical signatures and output schemas to the originals in flow_engine.py.

Module layout
-------------
  keys.py        Flow key computation (L2 / L3 / L4 bidirectional 5-tuple)
  record.py      FlowRecord dataclass + flow_summary() + RFC_MAP
  tcp_tracker.py TCP state machine, retransmission and dup-ACK detection
  udp_tracker.py UDP conversation timeout + request/reply pairing
  arp_tracker.py ARP request/reply matching, conflict and gratuitous detection
  engine.py      FlowEngine orchestrator — delegates to sub-trackers

Quick start
-----------
    # Drop-in replacement for flow_engine.py:
    try:
        from flow import reconstruct_flows, pair_arp_exchanges
    except ImportError:
        from flow_engine import reconstruct_flows, pair_arp_exchanges

    flows, flow_stats = reconstruct_flows(packets)
    arp_info          = pair_arp_exchanges(packets)

    analysis['flows']         = flows
    analysis['flow_stats']    = flow_stats
    analysis['arp_exchanges'] = arp_info

New capabilities over flow_engine.py
--------------------------------------
  - Retransmission detection per TCP flow (flow['retransmissions'])
  - Duplicate ACK counting per TCP flow (flow['dup_acks'])
  - Zero-window event counting per TCP flow (flow['zero_windows'])
  - UDP conversation timeout flagging (flow['udp_timeout'])
  - ARP conflict detection (two different MACs claim the same IP)
  - Gratuitous ARP identification (separate list in arp_exchanges)
  - IP→MAC table built from ARP replies ('ip_mac_table' in arp_exchanges)
  - Modular sub-trackers importable independently for unit testing
"""

from flow.engine      import FlowEngine, reconstruct_flows
from flow.arp_tracker import pair_arp_exchanges
from flow.record      import FlowRecord, flow_summary, human_bytes, RFC_MAP
from flow.keys        import l4_key, l3_key, l2_key, base_proto

__all__ = [
    # Primary API (drop-in for flow_engine.py)
    'reconstruct_flows',
    'pair_arp_exchanges',
    # Engine class
    'FlowEngine',
    # Data model
    'FlowRecord',
    'flow_summary',
    'human_bytes',
    'RFC_MAP',
    # Key helpers
    'l4_key',
    'l3_key',
    'l2_key',
    'base_proto',
]
