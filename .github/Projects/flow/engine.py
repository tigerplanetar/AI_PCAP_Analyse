"""
flow/engine.py — Modular Flow Reconstruction Engine
====================================================
Orchestrates the modular flow subsystem components to process a list of
parsed packets and produce FlowRecord dicts compatible with the dashboard
and AI pipeline.

Architecture
------------
FlowEngine delegates to three sub-trackers:

  TCPSession    (flow/tcp_tracker.py)
    Tracks SYN/SYN-ACK/FIN/RST state, retransmissions, dup-ACKs,
    and zero-window events per TCP flow.

  UDPConversation  (flow/udp_tracker.py)
    Groups UDP packets into conversations using 5-tuple + idle timeout.
    Pairs request/reply for DNS, NTP, DHCP, SNMP.

  pair_arp_exchanges  (flow/arp_tracker.py)
    Matches ARP request/reply pairs, detects conflicts and gratuitous ARPs.
    Runs once as a separate pass after flow reconstruction.

Flow hierarchy (L4 > L3 > L2)
------------------------------
  1. L4 key — 5-tuple (src_ip, src_port, dst_ip, dst_port, base_proto)
               for all TCP and UDP traffic.
  2. L3 key — IP pair + protocol, for ICMP, IGMP, IPv6, and any IP
               traffic without ports.
  3. L2 key — MAC pair + VLAN, for ARP, LLDP, and unknown EtherTypes.

Every packet is assigned to exactly one flow.  No packets are silently
dropped.

Integration with AI_PCAP_new_Apr27.py
--------------------------------------
Drop-in replacement for the existing flow_engine.reconstruct_flows():

    # Option A — use modular engine (recommended)
    try:
        from flow import reconstruct_flows, pair_arp_exchanges
    except ImportError:
        from flow_engine import reconstruct_flows, pair_arp_exchanges

    flows, flow_stats = reconstruct_flows(packets)
    analysis['flows']          = flows
    analysis['flow_stats']     = flow_stats
    analysis['arp_exchanges']  = pair_arp_exchanges(packets)

Output format
-------------
reconstruct_flows() → (list[dict], dict)
  - list[dict]: FlowRecord.to_dict() for each flow, sorted by pkt_count desc
  - dict: statistics — see FlowEngine.stats()

Both outputs are JSON-serialisable.
"""

from __future__ import annotations
from collections import defaultdict
from typing import Optional

from flow.keys   import l4_key, l3_key, l2_key, base_proto, packet_direction
from flow.record import FlowRecord, flow_summary, RFC_MAP
from flow.tcp_tracker import TCPSession, update_tcp_flow, finalise_tcp_state
from flow.udp_tracker import UDPConversation, update_udp_flow, finalise_udp_state


# ── Flow Engine ───────────────────────────────────────────────────────────────

class FlowEngine:
    """
    Modular flow reconstruction engine.

    Parameters
    ----------
    packets : list
        Parsed packet list from parse_all() / AI_PCAP_new_Apr27.py.
    max_flows : int
        Hard cap on the number of active flows.  Excess flows are grouped
        into a single overflow sentinel flow.  Default: 10 000.
    """

    def __init__(self, packets: list, max_flows: int = 10_000):
        self.packets   = packets
        self.max_flows = max_flows

        self._flows:        dict[tuple, FlowRecord]      = {}
        self._tcp_sessions: dict[tuple, TCPSession]      = {}
        self._udp_convs:    dict[tuple, UDPConversation] = {}
        self._pkt_to_flow:  dict[int, str]               = {}
        self._counter = 0
        self._stats: dict = {}

    # ── Public API ────────────────────────────────────────────────────────

    def reconstruct(self) -> list[dict]:
        """
        Process all packets, assign each to a flow, and return a sorted
        list of FlowRecord dicts (most packets first).
        """
        for pkt in self.packets:
            self._process_packet(pkt)

        capture_end_ts = (
            max((p.get('ts', 0) for p in self.packets), default=0.0)
        )
        self._finalise(capture_end_ts)
        self._compute_stats()

        return [f.to_dict() for f in sorted(
            self._flows.values(),
            key=lambda f: f.pkt_count,
            reverse=True,
        )]

    def stats(self) -> dict:
        """Return flow-level statistics dict for the analysis pipeline."""
        return self._stats

    # ── Internal ─────────────────────────────────────────────────────────

    def _next_id(self, prefix: str = 'F') -> str:
        self._counter += 1
        return f'{prefix}{self._counter:05d}'

    def _process_packet(self, pkt: dict):
        ts     = pkt.get('ts', 0.0)
        length = pkt.get('frame_len', len(pkt.get('hex_data', [])))
        pkt_id = pkt.get('id', 0)

        # Try L4 first (TCP / UDP with ports)
        key = l4_key(pkt)
        if key:
            flow = self._get_or_create(key, pkt, 'L4')
            self._update_common(flow, pkt, ts, length)
            self._update_l4(key, flow, pkt, ts, length)
            self._pkt_to_flow[pkt_id] = flow.flow_id
            return

        # Try L3 (IP, no ports — ICMP, IGMP, etc.)
        key = l3_key(pkt)
        if key:
            flow = self._get_or_create(key, pkt, 'L3')
            self._update_common(flow, pkt, ts, length)
            self._update_l3(flow, pkt, ts, length)
            self._pkt_to_flow[pkt_id] = flow.flow_id
            return

        # Fall back to L2 (ARP, LLDP, unknown)
        key = l2_key(pkt)
        flow = self._get_or_create(key, pkt, 'L2')
        self._update_common(flow, pkt, ts, length)
        self._update_l2(flow, pkt, ts, length)
        self._pkt_to_flow[pkt_id] = flow.flow_id

    def _get_or_create(self, key: tuple, pkt: dict, layer: str) -> FlowRecord:
        if key in self._flows:
            return self._flows[key]

        if len(self._flows) >= self.max_flows:
            ovf_key = ('__OVERFLOW__',)
            if ovf_key not in self._flows:
                self._flows[ovf_key] = FlowRecord(
                    flow_id=self._next_id('OVF'),
                    layer='L4', proto='(overflow)',
                    summary='Overflow: flow limit reached',
                )
            return self._flows[ovf_key]

        proto = pkt.get('proto', '?')
        flow  = FlowRecord(
            flow_id=self._next_id(),
            layer=layer,
            proto=proto,
            app_proto=proto,
            start_ts=pkt.get('ts', 0.0),
            src_mac=pkt.get('src_mac', ''),
            dst_mac=pkt.get('dst_mac', ''),
            vlan_id=pkt.get('vlan_id'),
            src_ip=pkt.get('src_ip', ''),
            dst_ip=pkt.get('dst_ip', ''),
            src_port=pkt.get('src_port', 0) or 0,
            dst_port=pkt.get('dst_port', 0) or 0,
            service=pkt.get('service', ''),
            rfc_ref=RFC_MAP.get(proto, ''),
        )
        self._flows[key] = flow
        return flow

    def _update_common(
        self, flow: FlowRecord, pkt: dict, ts: float, length: int
    ):
        """Bookkeeping common to all layers."""
        flow.pkt_count  += 1
        flow.byte_count += length
        if ts > 0:
            if flow.start_ts == 0 or ts < flow.start_ts:
                flow.start_ts = ts
            if ts > flow.end_ts:
                flow.end_ts = ts
            flow.last_ts = ts
        pkt_id = pkt.get('id', 0)
        if len(flow.pkt_ids) < 100:
            flow.pkt_ids.append(pkt_id)

    def _update_l4(
        self, key: tuple, flow: FlowRecord, pkt: dict, ts: float, length: int
    ):
        """L4-specific updates: direction, TCP session, UDP conversation."""
        is_fwd = packet_direction(pkt, flow.src_ip, flow.src_port) == 'fwd'
        if is_fwd:
            flow.fwd_pkts  += 1;  flow.fwd_bytes += length
        else:
            flow.rev_pkts  += 1;  flow.rev_bytes += length

        proto    = pkt.get('proto', '')
        bp       = base_proto(proto)

        if bp == 'TCP':
            # Initialise TCPSession on first packet for this flow key
            if key not in self._tcp_sessions:
                self._tcp_sessions[key] = TCPSession()
            update_tcp_flow(self._tcp_sessions[key], pkt, flow)

        elif bp == 'UDP':
            if key not in self._udp_convs:
                self._udp_convs[key] = UDPConversation()
            update_udp_flow(self._udp_convs[key], pkt, flow)

        # Promote app proto from packet if more specific
        if proto and proto != '?' and proto not in ('TCP', 'UDP', 'IPv4'):
            flow.app_proto = proto
            flow.rfc_ref   = RFC_MAP.get(proto, flow.rfc_ref)

    def _update_l3(
        self, flow: FlowRecord, pkt: dict, ts: float, length: int
    ):
        """L3-specific updates: direction + ICMP error signals."""
        is_fwd = packet_direction(pkt, flow.src_ip) == 'fwd'
        if is_fwd:
            flow.fwd_pkts  += 1;  flow.fwd_bytes += length
        else:
            flow.rev_pkts  += 1;  flow.rev_bytes += length

        if pkt.get('proto') == 'ICMP' and pkt.get('icmp_type') in (3, 11):
            flow.has_errors = True

    def _update_l2(
        self, flow: FlowRecord, pkt: dict, ts: float, length: int
    ):
        """L2-specific updates: direction by MAC."""
        is_fwd = pkt.get('src_mac', '') == flow.src_mac
        if is_fwd:
            flow.fwd_pkts  += 1;  flow.fwd_bytes += length
        else:
            flow.rev_pkts  += 1;  flow.rev_bytes += length

        proto = pkt.get('proto', flow.proto)
        if proto and proto != '?':
            flow.proto     = proto
            flow.app_proto = proto
            flow.rfc_ref   = RFC_MAP.get(proto, flow.rfc_ref)

    def _finalise(self, capture_end_ts: float):
        """Post-process: TCP state, UDP timeout, one-way flag, summaries."""
        for key, flow in self._flows.items():
            # TCP finalisation
            if key in self._tcp_sessions:
                finalise_tcp_state(flow)

            # UDP finalisation
            if key in self._udp_convs:
                finalise_udp_state(
                    self._udp_convs[key], flow, capture_end_ts
                )

            # One-way flag: traffic only from originator
            flow.is_one_way = (flow.rev_pkts == 0 and flow.fwd_pkts > 2)

            # Generate human-readable summary
            flow.summary = flow_summary(flow)

    def _compute_stats(self):
        """Build flow-level statistics for the analysis dict."""
        flows = list(self._flows.values())
        total      = len(flows)
        complete   = sum(1 for f in flows if f.is_complete)
        half_open  = sum(1 for f in flows if f.tcp_state == 'half-open')
        one_way    = sum(1 for f in flows if f.is_one_way)
        with_errs  = sum(1 for f in flows if f.has_errors)
        resets     = sum(1 for f in flows if f.tcp_state == 'reset')
        retx_flows = sum(1 for f in flows if f.retransmissions > 0)

        # Top talkers (by byte count)
        top_by_bytes = sorted(flows, key=lambda f: f.byte_count, reverse=True)[:10]

        # Protocol distribution
        proto_counts: dict[str, int] = defaultdict(int)
        for f in flows:
            proto_counts[f.app_proto or f.proto] += 1

        self._stats = {
            'total_flows':          total,
            'complete_flows':       complete,
            'half_open_flows':      half_open,
            'one_way_flows':        one_way,
            'flows_with_errors':    with_errs,
            'reset_flows':          resets,
            'retransmission_flows': retx_flows,
            'top_talkers':          [f.to_dict() for f in top_by_bytes],
            'proto_distribution':   dict(
                sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)[:20]
            ),
            'packets_tracked':      len(self._pkt_to_flow),
        }


# ── Convenience functions (drop-in for flow_engine.py) ───────────────────────

def reconstruct_flows(packets: list) -> tuple[list[dict], dict]:
    """
    Top-level helper, drop-in replacement for flow_engine.reconstruct_flows().

    Usage in AI_PCAP_new_Apr27.py analyse():

        try:
            from flow import reconstruct_flows, pair_arp_exchanges
        except ImportError:
            from flow_engine import reconstruct_flows, pair_arp_exchanges

        flows, flow_stats = reconstruct_flows(packets)
        analysis['flows']      = flows
        analysis['flow_stats'] = flow_stats

    Returns
    -------
    (flows_list, stats_dict)
    """
    engine = FlowEngine(packets)
    flows  = engine.reconstruct()
    stats  = engine.stats()
    return flows, stats
