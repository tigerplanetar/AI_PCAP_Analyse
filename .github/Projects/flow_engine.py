"""
flow_engine.py — Enhanced Flow Reconstruction Engine
=====================================================
Wireshark-style conversation tracking for the AI PCAP Analyzer.

This module reconstructs network conversations from parsed packet lists
produced by AI_PCAP_new_Apr27.py's parse_all() function.

Design Principles
-----------------
- Every packet must belong to exactly one flow (no silently dropped packets)
- Flows are identified at L2, L3, and L4 granularity
- TCP sessions track handshake/teardown lifecycle
- Unknown protocols still appear as flows
- All flows carry human-readable summaries

Integration
-----------
Call from AI_PCAP_new_Apr27.py after parse_all():

    from flow_engine import FlowEngine
    fe = FlowEngine(packets)
    flows = fe.reconstruct()
    analysis['flows'] = flows
    analysis['flow_stats'] = fe.stats()

Output format (flows list) is compatible with the AI pipeline steps
and the make_html() dashboard renderer.
"""

from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional
import time


# ── Flow key helpers ──────────────────────────────────────────────────────────

def _l2_key(pkt: dict) -> tuple:
    """Layer 2 flow key: MAC pair + VLAN."""
    src = pkt.get('src_mac', '')
    dst = pkt.get('dst_mac', '')
    vlan = pkt.get('vlan_id')
    return ('L2', min(src, dst), max(src, dst), vlan)


def _l3_key(pkt: dict) -> Optional[tuple]:
    """Layer 3 flow key: IP pair + protocol."""
    src = pkt.get('src_ip', '')
    dst = pkt.get('dst_ip', '')
    if not src or not dst:
        return None
    proto = pkt.get('proto', '')
    # Use base protocol for grouping
    base = _base_proto(proto)
    return ('L3', min(src, dst), max(src, dst), base)


def _l4_key(pkt: dict) -> Optional[tuple]:
    """Layer 4 flow key: 5-tuple (bidirectional)."""
    src_ip  = pkt.get('src_ip', '')
    dst_ip  = pkt.get('dst_ip', '')
    src_port = pkt.get('src_port')
    dst_port = pkt.get('dst_port')
    if not src_ip or not dst_ip or src_port is None or dst_port is None:
        return None
    proto = pkt.get('proto', '')
    base  = _base_proto(proto)

    # Normalise direction so (A→B) and (B→A) map to same key
    ep1 = (src_ip, src_port)
    ep2 = (dst_ip, dst_port)
    lo, hi = (ep1, ep2) if ep1 <= ep2 else (ep2, ep1)
    return ('L4', lo[0], lo[1], hi[0], hi[1], base)


def _base_proto(proto: str) -> str:
    """Normalise application proto names to their transport base for flow grouping."""
    _TCP_APP = {
        'HTTP', 'HTTPS', 'HTTP-Alt', 'HTTPS-Alt', 'SSH', 'Telnet',
        'FTP', 'FTP-Data', 'SMTP', 'SMTPS', 'POP3', 'POP3S',
        'IMAP', 'IMAPS', 'LDAP', 'LDAPS', 'SMB', 'NetBIOS-SSN',
        'RDP', 'SIP', 'SIPS', 'MSSQL', 'Oracle', 'MySQL',
        'PostgreSQL', 'MongoDB', 'Redis', 'VNC', 'Kerberos',
    }
    _UDP_APP = {
        'DNS', 'DHCP-Server', 'DHCP-Client', 'TFTP', 'NBNS',
        'NetBIOS-DGM', 'NTP', 'SNMP', 'SNMP-Trap', 'Syslog',
        'RIP', 'OpenVPN', 'RTP', 'SIP', 'RADIUS-Auth', 'RADIUS-Acct',
        'RADIUS-CoA', 'VXLAN',
    }
    if proto in _TCP_APP:
        return 'TCP'
    if proto in _UDP_APP:
        return 'UDP'
    return proto


# ── Flow state ────────────────────────────────────────────────────────────────

@dataclass
class FlowRecord:
    """
    Represents a single network conversation.
    Compatible with the existing analysis dict structure.
    """
    flow_id:    str
    layer:      str         # 'L2' | 'L3' | 'L4'
    proto:      str         # protocol name
    src_ip:     str = ''
    dst_ip:     str = ''
    src_port:   int = 0
    dst_port:   int = 0
    src_mac:    str = ''
    dst_mac:    str = ''
    vlan_id:    Optional[int] = None

    pkt_count:  int   = 0
    byte_count: int   = 0
    start_ts:   float = 0.0
    end_ts:     float = 0.0
    last_ts:    float = 0.0

    # Direction tracking
    fwd_pkts:   int   = 0   # src→dst
    rev_pkts:   int   = 0   # dst→src
    fwd_bytes:  int   = 0
    rev_bytes:  int   = 0

    # TCP session state
    tcp_state:  str = ''    # 'handshake' | 'established' | 'closing' | 'reset' | 'half-open'
    tcp_syn:    int = 0
    tcp_synack: int = 0
    tcp_fin:    int = 0
    tcp_rst:    int = 0

    # Application layer
    app_proto:  str = ''    # e.g. 'HTTP', 'DNS', 'DHCP'
    service:    str = ''    # well-known service name

    # Quality signals
    is_complete:    bool = False  # saw full handshake + teardown (TCP)
    is_one_way:     bool = False  # only traffic in one direction
    has_errors:     bool = False  # RST, ICMP unreachable, etc.

    # Packet references (IDs for lookup)
    pkt_ids: list = field(default_factory=list)

    # Human-readable fields
    summary: str = ''
    rfc_ref: str = ''

    def duration(self) -> float:
        return max(0.0, self.end_ts - self.start_ts)

    def to_dict(self) -> dict:
        return {
            'flow_id':      self.flow_id,
            'layer':        self.layer,
            'proto':        self.proto,
            'app_proto':    self.app_proto or self.proto,
            'src_ip':       self.src_ip,
            'dst_ip':       self.dst_ip,
            'src_port':     self.src_port,
            'dst_port':     self.dst_port,
            'src_mac':      self.src_mac,
            'dst_mac':      self.dst_mac,
            'vlan_id':      self.vlan_id,
            'pkt_count':    self.pkt_count,
            'byte_count':   self.byte_count,
            'duration_ms':  round(self.duration() * 1000, 2),
            'start_ts':     round(self.start_ts, 6),
            'end_ts':       round(self.end_ts, 6),
            'fwd_pkts':     self.fwd_pkts,
            'rev_pkts':     self.rev_pkts,
            'fwd_bytes':    self.fwd_bytes,
            'rev_bytes':    self.rev_bytes,
            'tcp_state':    self.tcp_state,
            'tcp_syn':      self.tcp_syn,
            'tcp_synack':   self.tcp_synack,
            'tcp_fin':      self.tcp_fin,
            'tcp_rst':      self.tcp_rst,
            'is_complete':  self.is_complete,
            'is_one_way':   self.is_one_way,
            'has_errors':   self.has_errors,
            'service':      self.service,
            'summary':      self.summary,
            'rfc_ref':      self.rfc_ref,
            'pkt_ids':      self.pkt_ids[:20],  # limit for JSON size
        }


# ── RFC references ────────────────────────────────────────────────────────────
_RFC_MAP = {
    'TCP': 'RFC 793', 'UDP': 'RFC 768', 'ARP': 'RFC 826',
    'ICMP': 'RFC 792', 'IGMP': 'RFC 3376', 'DNS': 'RFC 1035',
    'DHCP': 'RFC 2131', 'SNMP': 'RFC 3411', 'HTTP': 'RFC 9110',
    'HTTPS': 'RFC 9110+TLS', 'SSH': 'RFC 4253', 'FTP': 'RFC 959',
    'NTP': 'RFC 5905', 'SIP': 'RFC 3261', 'RTP': 'RFC 3550',
    'LLDP': 'IEEE 802.1AB', 'STP': 'IEEE 802.1D', 'EAPoL': 'IEEE 802.1X',
    'BGP': 'RFC 4271', 'OSPF': 'RFC 5340', 'VRRP': 'RFC 5798',
    'IPv4': 'RFC 791', 'IPv6': 'RFC 8200',
}


# ── Flow Engine ───────────────────────────────────────────────────────────────

class FlowEngine:
    """
    Reconstruct network flows from a list of parsed packets.

    Hierarchy:
      L4 flows   — 5-tuple (src_ip, src_port, dst_ip, dst_port, proto)
      L3 flows   — IP pairs (src_ip, dst_ip, proto) — for ICMP, IGMP, etc.
      L2 flows   — MAC pairs (for ARP, LLDP, unknown EtherTypes)
    """

    def __init__(self, packets: list, max_flows: int = 10000):
        self.packets  = packets
        self.max_flows = max_flows
        self._flows:  dict[tuple, FlowRecord] = {}
        self._pkt_to_flow: dict[int, str] = {}   # pkt_id → flow_id
        self._flow_counter = 0
        self._stats: dict = {}

    def reconstruct(self) -> list[dict]:
        """
        Process all packets, assign each to a flow, and return
        sorted list of flow dicts (most active first).
        """
        for pkt in self.packets:
            self._process_packet(pkt)
        self._finalise_flows()
        self._compute_stats()
        return [f.to_dict() for f in sorted(
            self._flows.values(),
            key=lambda f: f.pkt_count,
            reverse=True
        )]

    def stats(self) -> dict:
        """Return flow-level statistics for analysis dict."""
        return self._stats

    # ── Internal ─────────────────────────────────────────────────────────────

    def _next_id(self, prefix: str = 'F') -> str:
        self._flow_counter += 1
        return f'{prefix}{self._flow_counter:05d}'

    def _process_packet(self, pkt: dict):
        ts     = pkt.get('ts', 0.0)
        length = pkt.get('frame_len', len(pkt.get('hex_data', [])))
        pkt_id = pkt.get('id', 0)

        # Try L4 first (most specific)
        key = _l4_key(pkt)
        if key:
            flow = self._get_or_create_flow(key, pkt)
            self._update_flow_l4(flow, pkt, ts, length)
            self._pkt_to_flow[pkt_id] = flow.flow_id
            return

        # Try L3 (IP-level, no ports)
        key = _l3_key(pkt)
        if key:
            flow = self._get_or_create_flow(key, pkt)
            self._update_flow_l3(flow, pkt, ts, length)
            self._pkt_to_flow[pkt_id] = flow.flow_id
            return

        # Fall back to L2 (MAC-level)
        key = _l2_key(pkt)
        flow = self._get_or_create_flow(key, pkt)
        self._update_flow_l2(flow, pkt, ts, length)
        self._pkt_to_flow[pkt_id] = flow.flow_id

    def _get_or_create_flow(self, key: tuple, pkt: dict) -> FlowRecord:
        if key in self._flows:
            return self._flows[key]
        if len(self._flows) >= self.max_flows:
            # Drop overflow; use a sink flow
            overflow_key = ('OVERFLOW',)
            if overflow_key not in self._flows:
                self._flows[overflow_key] = FlowRecord(
                    flow_id=self._next_id('OVF'),
                    layer='L4', proto='(overflow)',
                    summary='Overflow: flow limit reached',
                )
            return self._flows[overflow_key]

        layer = key[0]
        proto = pkt.get('proto', '?')
        flow  = FlowRecord(
            flow_id=self._next_id(),
            layer=layer,
            proto=proto,
            start_ts=pkt.get('ts', 0.0),
            src_mac=pkt.get('src_mac', ''),
            dst_mac=pkt.get('dst_mac', ''),
            vlan_id=pkt.get('vlan_id'),
            src_ip=pkt.get('src_ip', ''),
            dst_ip=pkt.get('dst_ip', ''),
            src_port=pkt.get('src_port', 0),
            dst_port=pkt.get('dst_port', 0),
            service=pkt.get('service', ''),
            app_proto=proto,
            rfc_ref=_RFC_MAP.get(proto, ''),
        )
        self._flows[key] = flow
        return flow

    def _update_common(self, flow: FlowRecord, pkt: dict, ts: float, length: int):
        """Update fields shared across all layers."""
        flow.pkt_count += 1
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

    def _update_flow_l4(self, flow: FlowRecord, pkt: dict, ts: float, length: int):
        self._update_common(flow, pkt, ts, length)

        # Direction tracking (compare src to flow's src)
        is_forward = (pkt.get('src_ip', '') == flow.src_ip and
                      pkt.get('src_port', 0) == flow.src_port)
        if is_forward:
            flow.fwd_pkts  += 1
            flow.fwd_bytes += length
        else:
            flow.rev_pkts  += 1
            flow.rev_bytes += length

        # TCP state tracking
        flags = pkt.get('tcp_flags', '')
        if 'SYN' in flags and 'ACK' not in flags:
            flow.tcp_syn  += 1
            flow.tcp_state = 'handshake'
        if 'SYN' in flags and 'ACK' in flags:
            flow.tcp_synack += 1
            flow.tcp_state   = 'handshake'
        if 'FIN' in flags:
            flow.tcp_fin  += 1
            flow.tcp_state = 'closing'
        if 'RST' in flags:
            flow.tcp_rst  += 1
            flow.tcp_state = 'reset'
            flow.has_errors = True

        # Update proto if app layer now known
        proto = pkt.get('proto', flow.proto)
        if proto and proto != '?':
            flow.proto     = proto
            flow.app_proto = proto
            flow.rfc_ref   = _RFC_MAP.get(proto, flow.rfc_ref)

    def _update_flow_l3(self, flow: FlowRecord, pkt: dict, ts: float, length: int):
        self._update_common(flow, pkt, ts, length)
        is_forward = pkt.get('src_ip', '') == flow.src_ip
        if is_forward:
            flow.fwd_pkts  += 1; flow.fwd_bytes += length
        else:
            flow.rev_pkts  += 1; flow.rev_bytes += length

        # ICMP error detection
        if pkt.get('proto') == 'ICMP' and pkt.get('icmp_type') in (3, 11):
            flow.has_errors = True

    def _update_flow_l2(self, flow: FlowRecord, pkt: dict, ts: float, length: int):
        self._update_common(flow, pkt, ts, length)
        is_forward = pkt.get('src_mac', '') == flow.src_mac
        if is_forward:
            flow.fwd_pkts  += 1; flow.fwd_bytes += length
        else:
            flow.rev_pkts  += 1; flow.rev_bytes += length

    def _finalise_flows(self):
        """Post-process flows: compute states, one-way flags, summaries."""
        for flow in self._flows.values():
            flow.is_one_way = flow.rev_pkts == 0 and flow.fwd_pkts > 2

            # TCP completion: SYN + SYN-ACK + FIN seen
            if flow.proto in ('TCP',) or _base_proto(flow.proto) == 'TCP':
                if flow.tcp_syn > 0 and flow.tcp_synack > 0 and flow.tcp_fin > 0:
                    flow.is_complete = True
                    flow.tcp_state   = 'closed'
                elif flow.tcp_rst > 0:
                    flow.tcp_state   = 'reset'
                elif flow.tcp_syn > 0 and flow.tcp_synack == 0:
                    flow.tcp_state   = 'half-open'
                elif flow.tcp_syn > 0 and flow.tcp_synack > 0:
                    flow.tcp_state   = 'established'

            flow.summary = _flow_summary(flow)

    def _compute_stats(self):
        """Build flow-level statistics for the analysis dict."""
        flows = list(self._flows.values())
        total = len(flows)
        complete  = sum(1 for f in flows if f.is_complete)
        half_open = sum(1 for f in flows if f.tcp_state == 'half-open')
        one_way   = sum(1 for f in flows if f.is_one_way)
        with_errors = sum(1 for f in flows if f.has_errors)
        resets    = sum(1 for f in flows if f.tcp_state == 'reset')

        # Top talkers by byte count
        top_by_bytes = sorted(flows, key=lambda f: f.byte_count, reverse=True)[:10]

        # Protocol distribution
        proto_counts: dict[str, int] = defaultdict(int)
        for f in flows:
            proto_counts[f.app_proto or f.proto] += 1

        self._stats = {
            'total_flows':       total,
            'complete_flows':    complete,
            'half_open_flows':   half_open,
            'one_way_flows':     one_way,
            'flows_with_errors': with_errors,
            'reset_flows':       resets,
            'top_talkers':       [f.to_dict() for f in top_by_bytes],
            'proto_distribution': dict(sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)[:20]),
            'packets_tracked':   len(self._pkt_to_flow),
        }


# ── Flow summary generator ────────────────────────────────────────────────────

def _flow_summary(flow: FlowRecord) -> str:
    """Generate a human-readable summary for a flow."""
    proto = flow.app_proto or flow.proto

    # TCP session summaries
    if flow.tcp_state:
        state_map = {
            'handshake':   'handshake in progress',
            'established': 'session established',
            'closing':     'graceful close',
            'closed':      'session completed',
            'reset':       'reset (RST)',
            'half-open':   'half-open (SYN without reply)',
        }
        state_desc = state_map.get(flow.tcp_state, flow.tcp_state)

    if flow.src_ip and flow.dst_ip and flow.src_port and flow.dst_port:
        base = f'{proto} {flow.src_ip}:{flow.src_port} ↔ {flow.dst_ip}:{flow.dst_port}'
        if flow.tcp_state:
            base += f' [{state_desc}]'
        detail = f'{flow.pkt_count} pkts / {_human_bytes(flow.byte_count)}'
        if flow.duration() > 0:
            detail += f' / {flow.duration()*1000:.0f}ms'
        return f'{base} — {detail}'

    if flow.src_ip and flow.dst_ip:
        base = f'{proto} {flow.src_ip} ↔ {flow.dst_ip}'
        return f'{base} — {flow.pkt_count} pkts / {_human_bytes(flow.byte_count)}'

    if flow.src_mac and flow.dst_mac:
        vlan = f' [VLAN {flow.vlan_id}]' if flow.vlan_id else ''
        return f'L2 {proto} {flow.src_mac} ↔ {flow.dst_mac}{vlan} — {flow.pkt_count} pkts'

    return f'{proto} flow — {flow.pkt_count} pkts / {_human_bytes(flow.byte_count)}'


def _human_bytes(n: int) -> str:
    if n < 1024:
        return f'{n}B'
    if n < 1024 ** 2:
        return f'{n / 1024:.1f}KB'
    return f'{n / 1024 ** 2:.1f}MB'


# ── Convenience integration function ─────────────────────────────────────────

def reconstruct_flows(packets: list) -> tuple[list[dict], dict]:
    """
    Top-level helper for integration with AI_PCAP_new_Apr27.py.

    Usage in analyse():
        from flow_engine import reconstruct_flows
        flows, flow_stats = reconstruct_flows(packets)
        result['flows'] = flows
        result['flow_stats'] = flow_stats

    Returns (flows_list, stats_dict).
    """
    engine = FlowEngine(packets)
    flows  = engine.reconstruct()
    stats  = engine.stats()
    return flows, stats


# ── ARP exchange pairing ──────────────────────────────────────────────────────

def pair_arp_exchanges(packets: list) -> dict:
    """
    Match ARP requests with their replies.
    Returns dict keyed by (requester_ip, target_ip) with timing info.
    """
    pending: dict[tuple, dict] = {}   # (src_ip, dst_ip) → {ts, pkt_id}
    pairs:   dict[tuple, dict] = {}

    for pkt in packets:
        if pkt.get('proto') != 'ARP':
            continue
        op     = pkt.get('arp_op', '')
        src_ip = pkt.get('src_ip', '')
        dst_ip = pkt.get('dst_ip', '')
        ts     = pkt.get('ts', 0.0)
        pkt_id = pkt.get('id', 0)

        if op == 'REQUEST':
            pending[(src_ip, dst_ip)] = {'ts': ts, 'pkt_id': pkt_id,
                                          'src_mac': pkt.get('arp_src_mac', '')}
        elif op == 'REPLY':
            req_key = (dst_ip, src_ip)  # swapped: requester was asking for src_ip
            if req_key in pending:
                req = pending.pop(req_key)
                rtt_ms = round((ts - req['ts']) * 1000, 2)
                pairs[req_key] = {
                    'requester_ip': req_key[0], 'target_ip': req_key[1],
                    'requester_mac': req['src_mac'],
                    'responder_mac': pkt.get('arp_src_mac', ''),
                    'req_pkt_id': req['pkt_id'], 'rep_pkt_id': pkt_id,
                    'rtt_ms': rtt_ms,
                    'summary': f'ARP resolved: {req_key[1]} is at {pkt.get("arp_src_mac", "?")} ({rtt_ms}ms)',
                }

    # Unanswered requests
    unanswered = [
        {'requester_ip': k[0], 'target_ip': k[1],
         'requester_mac': v['src_mac'], 'pkt_id': v['pkt_id'],
         'summary': f'ARP unanswered: who has {k[1]}? (from {k[0]})'}
        for k, v in pending.items()
    ]

    return {'pairs': list(pairs.values()), 'unanswered': unanswered,
            'total_requests': len(pairs) + len(unanswered),
            'response_rate_pct': round(len(pairs) / max(len(pairs) + len(unanswered), 1) * 100, 1)}
