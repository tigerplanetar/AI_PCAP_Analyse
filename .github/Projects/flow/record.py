"""
flow/record.py — FlowRecord and Summary Generation
=====================================================
Central data model for a single network conversation.

Every packet is assigned to exactly one FlowRecord.  The record tracks
all fields needed for the AI analysis pipeline and the dashboard renderer.

Public API
----------
    from flow.record import FlowRecord, flow_summary, human_bytes

Schema compatibility
--------------------
FlowRecord.to_dict() produces the same keys as the existing flow_engine.py
FlowRecord.to_dict() so the dashboard make_html() renderer needs no changes.

New fields added over the original:
    retransmissions  — count of detected TCP retransmitted segments
    dup_acks         — count of duplicate ACKs observed
    zero_windows     — count of TCP zero-window advertisements
    udp_timeout      — True when the UDP conversation was closed by timeout
    conversation_id  — numeric ID matching ARP pair / DNS transaction ids
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


# ── RFC reference lookup ──────────────────────────────────────────────────────

RFC_MAP: dict[str, str] = {
    'TCP':   'RFC 793',      'UDP':   'RFC 768',
    'ARP':   'RFC 826',      'ICMP':  'RFC 792',
    'IGMP':  'RFC 3376',     'IPv4':  'RFC 791',
    'IPv6':  'RFC 8200',     'DNS':   'RFC 1035',
    'DHCP':  'RFC 2131',     'DHCP-Server': 'RFC 2131',
    'DHCP-Client': 'RFC 2131',
    'NTP':   'RFC 5905',     'SNMP':  'RFC 3411',
    'SNMP-Trap': 'RFC 3411', 'HTTP':  'RFC 9110',
    'HTTPS': 'RFC 9110+TLS', 'SSH':   'RFC 4253',
    'FTP':   'RFC 959',      'SMTP':  'RFC 5321',
    'SIP':   'RFC 3261',     'RTP':   'RFC 3550',
    'LLDP':  'IEEE 802.1AB', 'STP':   'IEEE 802.1D',
    'EAPoL': 'IEEE 802.1X',  'BGP':   'RFC 4271',
    'OSPF':  'RFC 5340',     'VRRP':  'RFC 5798',
    'VXLAN': 'RFC 7348',     'RADIUS-Auth': 'RFC 2865',
}


# ── FlowRecord ────────────────────────────────────────────────────────────────

@dataclass
class FlowRecord:
    """
    Represents a single bidirectional network conversation.

    Compatible with the existing flow_engine.FlowRecord.to_dict() schema
    so the dashboard renderer and AI pipeline need no changes.
    """

    # Identity
    flow_id:    str
    layer:      str          # 'L2' | 'L3' | 'L4'
    proto:      str          # transport protocol
    app_proto:  str = ''     # application layer (HTTP, DNS, …)
    service:    str = ''     # well-known service label

    # Endpoints
    src_ip:   str = ''
    dst_ip:   str = ''
    src_port: int = 0
    dst_port: int = 0
    src_mac:  str = ''
    dst_mac:  str = ''
    vlan_id:  Optional[int] = None

    # Packet / byte accounting
    pkt_count:  int   = 0
    byte_count: int   = 0
    fwd_pkts:   int   = 0    # src→dst direction
    rev_pkts:   int   = 0    # dst→src direction
    fwd_bytes:  int   = 0
    rev_bytes:  int   = 0

    # Timestamps (Unix epoch floats)
    start_ts: float = 0.0
    end_ts:   float = 0.0
    last_ts:  float = 0.0

    # TCP session state machine
    tcp_state:  str = ''     # see TCPTracker for valid values
    tcp_syn:    int = 0
    tcp_synack: int = 0
    tcp_fin:    int = 0
    tcp_rst:    int = 0

    # TCP quality signals (new)
    retransmissions: int = 0   # segments with seq already seen
    dup_acks:        int = 0   # duplicate ACK count
    zero_windows:    int = 0   # window=0 advertisements

    # UDP conversation signals (new)
    udp_timeout: bool = False  # True when closed by idle timeout

    # Flow quality flags
    is_complete: bool = False  # full handshake + teardown (TCP)
    is_one_way:  bool = False  # no traffic in reverse direction
    has_errors:  bool = False  # RST, ICMP unreach, etc.

    # Packet references (first 100)
    pkt_ids: list = field(default_factory=list)

    # Human-readable fields
    summary: str = ''
    rfc_ref: str = ''

    # ── Computed properties ───────────────────────────────────────────────

    def duration(self) -> float:
        """Flow duration in seconds."""
        return max(0.0, self.end_ts - self.start_ts)

    def endpoints(self) -> str:
        """Human-readable endpoint string for display."""
        if self.src_ip and self.dst_ip and self.src_port and self.dst_port:
            return f'{self.src_ip}:{self.src_port} ↔ {self.dst_ip}:{self.dst_port}'
        if self.src_ip and self.dst_ip:
            return f'{self.src_ip} ↔ {self.dst_ip}'
        return f'{self.src_mac} ↔ {self.dst_mac}'

    def to_dict(self) -> dict:
        """
        JSON-serialisable dict matching the dashboard layer schema.
        Backward-compatible with flow_engine.FlowRecord.to_dict().
        """
        return {
            # Core identity
            'flow_id':       self.flow_id,
            'layer':         self.layer,
            'proto':         self.proto,
            'app_proto':     self.app_proto or self.proto,
            'service':       self.service,
            # Endpoints
            'src_ip':        self.src_ip,
            'dst_ip':        self.dst_ip,
            'src_port':      self.src_port,
            'dst_port':      self.dst_port,
            'src_mac':       self.src_mac,
            'dst_mac':       self.dst_mac,
            'vlan_id':       self.vlan_id,
            'endpoints':     self.endpoints(),
            # Traffic counts
            'pkt_count':     self.pkt_count,
            'byte_count':    self.byte_count,
            'fwd_pkts':      self.fwd_pkts,
            'rev_pkts':      self.rev_pkts,
            'fwd_bytes':     self.fwd_bytes,
            'rev_bytes':     self.rev_bytes,
            # Timing
            'start_ts':      round(self.start_ts, 6),
            'end_ts':        round(self.end_ts,   6),
            'duration_ms':   round(self.duration() * 1000, 2),
            # TCP state
            'tcp_state':     self.tcp_state,
            'tcp_syn':       self.tcp_syn,
            'tcp_synack':    self.tcp_synack,
            'tcp_fin':       self.tcp_fin,
            'tcp_rst':       self.tcp_rst,
            # TCP quality
            'retransmissions': self.retransmissions,
            'dup_acks':        self.dup_acks,
            'zero_windows':    self.zero_windows,
            # Flow flags
            'is_complete':   self.is_complete,
            'is_one_way':    self.is_one_way,
            'has_errors':    self.has_errors,
            'udp_timeout':   self.udp_timeout,
            # Annotations
            'summary':       self.summary,
            'rfc_ref':       self.rfc_ref,
            'pkt_ids':       self.pkt_ids[:20],
        }


# ── Summary generation ────────────────────────────────────────────────────────

def human_bytes(n: int) -> str:
    """Format byte count as human-readable string."""
    if n < 1024:
        return f'{n}B'
    if n < 1024 ** 2:
        return f'{n / 1024:.1f}KB'
    return f'{n / 1024 ** 2:.1f}MB'


_TCP_STATE_LABELS: dict[str, str] = {
    'handshake':   'handshake in progress',
    'established': 'session established',
    'closing':     'graceful close (FIN)',
    'closed':      'session completed',
    'reset':       'abruptly reset (RST)',
    'half-open':   'half-open (SYN without reply)',
}


def flow_summary(flow: FlowRecord) -> str:
    """
    Generate a human-readable one-line summary for a flow.

    Mirrors the format used by the existing flow_engine._flow_summary()
    so the dashboard and AI pipeline see the same style.
    """
    proto = flow.app_proto or flow.proto

    # Build quality annotation
    quality_parts = []
    if flow.retransmissions:
        quality_parts.append(f'{flow.retransmissions} retx')
    if flow.zero_windows:
        quality_parts.append('zero-window')
    if flow.has_errors:
        quality_parts.append('errors')
    quality = ' | '.join(quality_parts)

    # L4 (TCP/UDP with ports)
    if flow.src_ip and flow.dst_ip and flow.src_port and flow.dst_port:
        base = f'{proto} {flow.src_ip}:{flow.src_port} ↔ {flow.dst_ip}:{flow.dst_port}'
        if flow.tcp_state:
            state_desc = _TCP_STATE_LABELS.get(flow.tcp_state, flow.tcp_state)
            base += f' [{state_desc}]'
        detail = f'{flow.pkt_count} pkts / {human_bytes(flow.byte_count)}'
        if flow.duration() > 0:
            detail += f' / {flow.duration() * 1000:.0f}ms'
        if quality:
            detail += f' — {quality}'
        return f'{base} — {detail}'

    # L3 (IP, no ports)
    if flow.src_ip and flow.dst_ip:
        base = f'{proto} {flow.src_ip} ↔ {flow.dst_ip}'
        detail = f'{flow.pkt_count} pkts / {human_bytes(flow.byte_count)}'
        if quality:
            detail += f' — {quality}'
        return f'{base} — {detail}'

    # L2 (MAC only)
    if flow.src_mac and flow.dst_mac:
        vlan = f' [VLAN {flow.vlan_id}]' if flow.vlan_id else ''
        return (f'L2 {proto} {flow.src_mac} ↔ {flow.dst_mac}{vlan}'
                f' — {flow.pkt_count} pkts')

    return f'{proto} flow — {flow.pkt_count} pkts / {human_bytes(flow.byte_count)}'
