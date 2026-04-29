"""
flow/udp_tracker.py — UDP Conversation Tracking
=================================================
UDP is connectionless, so conversations are inferred by grouping packets
with the same 5-tuple within a configurable idle timeout window.

Additionally, request/response pairing is performed for well-known
request/reply protocols (DNS, NTP, DHCP, RADIUS, SNMP) by matching
transaction IDs embedded in the payload.

Public API
----------
    from flow.udp_tracker import UDPConversation, update_udp_flow, is_timed_out

    conv = UDPConversation()
    update_udp_flow(conv, pkt, flow)

    # After processing all packets:
    if is_timed_out(conv, capture_end_ts, timeout_secs=30):
        flow.udp_timeout = True

UDP conversation lifecycle
--------------------------
Unlike TCP, there is no handshake or teardown signal.  A UDP conversation
is considered:
  - OPEN:    packets still arriving within the idle timeout
  - TIMEOUT: no packets for `timeout_secs` since the last one
  - COMPLETE: a request/reply pair was matched (DNS, NTP, etc.)

Timeout defaults
----------------
  DNS:    5 seconds  — short, single query/response
  DHCP:  30 seconds  — DORA exchange can take time
  SNMP:  30 seconds  — polling interval varies
  NTP:    5 seconds  — request/response pair
  RTP:   60 seconds  — media streams are long-lived
  default: 30 seconds

DNS / NTP query-response pairing
---------------------------------
The DNS transaction ID is the first 2 bytes of the UDP payload (RFC 1035).
The NTP mode field distinguishes client (mode=3) from server (mode=4).
DHCP uses the 'xid' field at byte offset 4 of the BOOTP/DHCP header.
RADIUS uses the 'Identifier' field at byte 1 of the RADIUS header.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from flow.record import FlowRecord


# ── Idle timeout per protocol (seconds) ──────────────────────────────────────

UDP_TIMEOUTS: dict[str, float] = {
    'DNS':          5.0,
    'NTP':          5.0,
    'DHCP-Server': 30.0,
    'DHCP-Client': 30.0,
    'SNMP':        30.0,
    'SNMP-Trap':   30.0,
    'RADIUS-Auth': 30.0,
    'RADIUS-Acct': 30.0,
    'RTP':         60.0,
    'Syslog':      60.0,
    'default':     30.0,
}


def conversation_timeout(proto: str) -> float:
    """Return the idle timeout in seconds for the given UDP protocol."""
    return UDP_TIMEOUTS.get(proto, UDP_TIMEOUTS['default'])


# ── Transaction ID extraction ─────────────────────────────────────────────────

def _extract_txid(pkt: dict, proto: str) -> Optional[int]:
    """
    Extract a transaction ID from the pkt dict for request/reply matching.

    Supports:
      DNS  — 2-byte txid at offset 0 of UDP payload (RFC 1035 §4.1.1)
      NTP  — mode nibble in first byte (client=3, server=4, RFC 5905)
      DHCP — 4-byte 'xid' at offset 4 of BOOTP payload (RFC 2131 §2)
      SNMP — SNMP request-id parsed by _detect_snmp() in constants.py
    """
    # DNS txid is often stored by the DNS parser in pkt['dns_txid']
    if proto in ('DNS',):
        return pkt.get('dns_txid')

    # DHCP xid stored by DHCPParser in pkt['dhcp_xid']
    if proto in ('DHCP-Server', 'DHCP-Client', 'DHCP'):
        return pkt.get('dhcp_xid')

    # NTP: direction from pkt['ntp_mode'] if set
    if proto == 'NTP':
        return pkt.get('ntp_mode')

    return None


# ── UDPConversation ───────────────────────────────────────────────────────────

@dataclass
class UDPConversation:
    """
    Mutable per-flow state for a UDP conversation.

    Stores pending request transaction IDs and tracks the idle timeout.
    """

    # Pending requests keyed by (direction, txid) → timestamp
    _pending_reqs: dict = field(default_factory=dict)

    # Completed request/response pairs
    pairs: list = field(default_factory=list)

    # Unanswered requests at finalise time
    unanswered: list = field(default_factory=list)

    # Request and response counts
    req_count:  int = 0
    resp_count: int = 0

    # Last seen timestamp (for timeout detection)
    last_ts: float = 0.0


def update_udp_flow(
    conv: UDPConversation,
    pkt: dict,
    flow: FlowRecord,
) -> None:
    """
    Apply one UDP packet to the conversation tracker and FlowRecord.

    Parameters
    ----------
    conv : UDPConversation
        Mutable conversation state bound to the flow.
    pkt : dict
        Parsed packet dict from parse_all().
    flow : FlowRecord
        The flow record to update in-place.
    """
    ts    = pkt.get('ts', 0.0)
    proto = pkt.get('proto', flow.proto)
    is_fwd = (pkt.get('src_ip', '') == flow.src_ip and
              pkt.get('src_port', 0) == flow.src_port)

    conv.last_ts = ts

    # Update app proto
    if proto and proto != '?' and proto not in ('UDP',):
        flow.app_proto = proto
        from flow.record import RFC_MAP
        flow.rfc_ref   = RFC_MAP.get(proto, flow.rfc_ref)

    # Try request/response pairing for supported protocols
    txid = _extract_txid(pkt, proto)
    if txid is not None:
        req_key = (True, txid)   # forward direction request
        if is_fwd:
            # Forward packet → treat as request
            conv._pending_reqs[req_key] = {'ts': ts, 'pkt_id': pkt.get('id', 0)}
            conv.req_count += 1
        else:
            # Reverse packet → try to match a pending request
            if req_key in conv._pending_reqs:
                req = conv._pending_reqs.pop(req_key)
                rtt_ms = round((ts - req['ts']) * 1000, 3)
                conv.pairs.append({
                    'proto':      proto,
                    'txid':       txid,
                    'req_pkt_id': req['pkt_id'],
                    'rep_pkt_id': pkt.get('id', 0),
                    'rtt_ms':     rtt_ms,
                })
                conv.resp_count += 1
                if not flow.is_complete:
                    flow.is_complete = len(conv.pairs) > 0


def finalise_udp_state(
    conv: UDPConversation,
    flow: FlowRecord,
    capture_end_ts: float = 0.0,
) -> None:
    """
    Mark unanswered requests and apply timeout flag.

    Call once after all packets are processed, before generating summaries.
    """
    timeout_secs = conversation_timeout(flow.app_proto or flow.proto)

    # Mark as timed-out if no packet arrived within the idle window
    if capture_end_ts > 0 and conv.last_ts > 0:
        idle = capture_end_ts - conv.last_ts
        if idle >= timeout_secs:
            flow.udp_timeout = True

    # Collect unanswered pending requests
    for req_key, info in conv._pending_reqs.items():
        conv.unanswered.append({
            'proto':      flow.app_proto or flow.proto,
            'txid':       req_key[1],
            'req_pkt_id': info['pkt_id'],
            'ts':         info['ts'],
        })

    if conv.unanswered:
        flow.has_errors = True


def is_timed_out(
    conv: UDPConversation,
    current_ts: float,
    proto: str = '',
    timeout_secs: float = 0.0,
) -> bool:
    """
    Return True if the conversation has been idle long enough to be
    considered closed.

    If timeout_secs is 0, the per-protocol default is used.
    """
    if conv.last_ts <= 0:
        return False
    limit = timeout_secs if timeout_secs > 0 else conversation_timeout(proto)
    return (current_ts - conv.last_ts) >= limit
