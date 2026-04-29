"""
flow/arp_tracker.py — ARP Request/Reply Pairing
=================================================
Matches ARP REQUEST packets with their corresponding REPLY packets,
computes round-trip times, and identifies unanswered requests.

Also detects:
  - Gratuitous ARP (sender IP == target IP) — RFC 826 §6
  - ARP reply conflicts (two different MACs reply for the same IP)
  - Unanswered ARP requests (potential host unreachability)

Public API
----------
    from flow.arp_tracker import pair_arp_exchanges, ARPExchangeResult

    result = pair_arp_exchanges(packets)
    result.pairs          # list of matched (request, reply) dicts
    result.unanswered     # list of requests with no reply
    result.conflicts      # list of IP→MAC conflicts (potential ARP spoofing)
    result.gratuitous     # list of gratuitous ARP packets
    result.to_dict()      # JSON-serialisable output for analysis dict

Backward compatibility
----------------------
pair_arp_exchanges() returns the same top-level keys as the original
flow_engine.pair_arp_exchanges() so existing dashboard code is unaffected:
    { 'pairs', 'unanswered', 'total_requests', 'response_rate_pct' }

The result also adds the new fields:
    { 'conflicts', 'gratuitous', 'ip_mac_table' }

RFC 826 — Address Resolution Protocol
"""

from __future__ import annotations
from dataclasses import dataclass, field


# ── ARP pair entry ────────────────────────────────────────────────────────────

def _arp_pair(req: dict, rep: dict, rtt_ms: float) -> dict:
    """Build a single matched ARP pair dict."""
    return {
        'requester_ip':  req['src_ip'],
        'target_ip':     req['dst_ip'],
        'requester_mac': req.get('arp_src_mac', ''),
        'responder_mac': rep.get('arp_src_mac', ''),
        'req_pkt_id':    req.get('id', 0),
        'rep_pkt_id':    rep.get('id', 0),
        'req_ts':        req.get('ts', 0.0),
        'rep_ts':        rep.get('ts', 0.0),
        'rtt_ms':        rtt_ms,
        'summary': (
            f'ARP resolved: {req["dst_ip"]} is at '
            f'{rep.get("arp_src_mac", "?")} ({rtt_ms}ms)'
        ),
    }


# ── ARPExchangeResult ────────────────────────────────────────────────────────

@dataclass
class ARPExchangeResult:
    """Container for all ARP pairing outcomes."""

    pairs:      list = field(default_factory=list)
    unanswered: list = field(default_factory=list)
    conflicts:  list = field(default_factory=list)
    gratuitous: list = field(default_factory=list)

    # IP → MAC mapping table learned from replies
    ip_mac_table: dict = field(default_factory=dict)

    @property
    def total_requests(self) -> int:
        return len(self.pairs) + len(self.unanswered)

    @property
    def response_rate_pct(self) -> float:
        total = self.total_requests
        if total == 0:
            return 100.0
        return round(len(self.pairs) / total * 100, 1)

    def to_dict(self) -> dict:
        return {
            # Backward-compatible keys
            'pairs':             self.pairs,
            'unanswered':        self.unanswered,
            'total_requests':    self.total_requests,
            'response_rate_pct': self.response_rate_pct,
            # New keys
            'conflicts':         self.conflicts,
            'gratuitous':        self.gratuitous,
            'ip_mac_table':      self.ip_mac_table,
        }


# ── Core matching logic ───────────────────────────────────────────────────────

def pair_arp_exchanges(packets: list) -> dict:
    """
    Scan *packets* for ARP traffic and match requests to replies.

    Parameters
    ----------
    packets : list
        Parsed packet list from parse_all() / AI_PCAP_new_Apr27.py.

    Returns
    -------
    dict compatible with the original flow_engine.pair_arp_exchanges()
    output schema, plus extra fields for conflicts and gratuitous ARPs.
    """
    result = ARPExchangeResult()

    # Pending requests: (requester_ip, target_ip) → packet dict
    pending: dict[tuple, dict] = {}

    for pkt in packets:
        if pkt.get('proto') != 'ARP':
            continue

        op      = pkt.get('arp_op', '')
        src_ip  = pkt.get('src_ip', '')
        dst_ip  = pkt.get('dst_ip', '')
        src_mac = pkt.get('arp_src_mac', '')
        ts      = pkt.get('ts', 0.0)

        # ── Gratuitous ARP detection ─────────────────────────────────────
        # Gratuitous ARP: sender announces/refreshes its own mapping.
        # Can be benign (IP change announcement) or malicious (spoofing).
        if src_ip == dst_ip and op in ('REQUEST', 'REPLY'):
            result.gratuitous.append({
                'ip':     src_ip,
                'mac':    src_mac,
                'op':     op,
                'pkt_id': pkt.get('id', 0),
                'ts':     ts,
                'summary': f'Gratuitous ARP: {src_ip} announces MAC {src_mac}',
            })

        # ── REQUEST processing ────────────────────────────────────────────
        if op == 'REQUEST':
            pending[(src_ip, dst_ip)] = pkt

        # ── REPLY processing ──────────────────────────────────────────────
        elif op == 'REPLY':
            # The replier's src_ip is the target_ip of the original request.
            # The replier's dst_ip (== target_ip of reply) is the requester.
            # So we look for a pending request keyed (dst_ip, src_ip).
            req_key = (dst_ip, src_ip)

            # ARP reply conflict detection:
            # If we already have an IP→MAC mapping for src_ip and this
            # reply carries a different MAC, it's a conflict (possible spoofing).
            if src_ip in result.ip_mac_table:
                known_mac = result.ip_mac_table[src_ip]
                if known_mac != src_mac:
                    result.conflicts.append({
                        'ip':         src_ip,
                        'known_mac':  known_mac,
                        'new_mac':    src_mac,
                        'pkt_id':     pkt.get('id', 0),
                        'ts':         ts,
                        'summary': (
                            f'ARP CONFLICT: {src_ip} was at {known_mac}, '
                            f'now claims {src_mac} — possible ARP spoofing'
                        ),
                    })
            else:
                result.ip_mac_table[src_ip] = src_mac

            # Match to pending request
            if req_key in pending:
                req    = pending.pop(req_key)
                rtt_ms = round((ts - req.get('ts', ts)) * 1000, 2)
                result.pairs.append(_arp_pair(req, pkt, rtt_ms))

    # ── Unanswered requests ───────────────────────────────────────────────
    for (req_ip, tgt_ip), pkt in pending.items():
        result.unanswered.append({
            'requester_ip':  req_ip,
            'target_ip':     tgt_ip,
            'requester_mac': pkt.get('arp_src_mac', ''),
            'pkt_id':        pkt.get('id', 0),
            'ts':            pkt.get('ts', 0.0),
            'summary':       f'ARP unanswered: who has {tgt_ip}? (from {req_ip})',
        })

    return result.to_dict()
