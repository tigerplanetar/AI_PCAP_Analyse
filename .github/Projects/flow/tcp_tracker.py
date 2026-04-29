"""
flow/tcp_tracker.py — TCP Session State Machine and Retransmission Detection
=============================================================================
Tracks individual TCP sessions including:
  - 3-way handshake (SYN → SYN-ACK → ACK)
  - Data transfer phase
  - Graceful teardown (FIN / FIN-ACK)
  - Abrupt reset (RST)
  - Retransmission detection via sequence number tracking
  - Duplicate ACK detection (congestion signal)
  - Zero-window detection (flow control signal)

Public API
----------
    from flow.tcp_tracker import TCPSession, update_tcp_flow

    session = TCPSession()
    result  = update_tcp_flow(session, pkt, flow)

Design notes
------------
Retransmission detection
    A TCP segment is a retransmission if:
      - It carries a non-zero payload AND
      - (seq_num, payload_len) was already observed for the same direction.
    We keep a bounded sliding window of (seq, length) tuples per direction
    to avoid unbounded memory growth on large captures.

    RFC 793 §3.4: sequence numbers wrap at 2^32 — the tracker handles
    this by checking if |seq_a - seq_b| < SEQ_WRAP_THRESHOLD.

Duplicate ACK detection
    Three consecutive ACKs for the same seq number from one direction
    (without intervening new data) indicate probable packet loss and
    trigger fast retransmit (RFC 5681 §3.2).

Zero-window detection
    Window size == 0 in an ACK is a congestion/buffer-full signal
    (RFC 793 §3.7).  Counted per-flow; high counts indicate application
    or network congestion.

State machine transitions
    half-open  → handshake  (SYN-ACK received)
    handshake  → established (data or ACK after handshake)
    established → closing   (FIN seen)
    closing    → closed     (FIN+ACK from both sides)
    any        → reset      (RST seen)
"""

from __future__ import annotations
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from flow.record import FlowRecord


# ── Constants ────────────────────────────────────────────────────────────────

# Maximum number of (seq, length) tuples to remember per direction
_SEQ_WINDOW_SIZE = 500

# Maximum sequence number delta below which we consider two seq numbers
# "adjacent" (to handle the 2^32 wraparound case)
_SEQ_WRAP_THRESHOLD = 0x7FFF_FFFF   # ~2 GB


# ── TCPSession ───────────────────────────────────────────────────────────────

@dataclass
class TCPSession:
    """
    Per-flow mutable TCP session state.

    One TCPSession lives alongside each FlowRecord that tracks TCP traffic.
    It accumulates seq/ACK observations and detects retransmissions,
    duplicate ACKs, and zero windows.
    """

    # Seen (seq, length) pairs per direction for retransmission detection
    _fwd_segs: deque = field(default_factory=lambda: deque(maxlen=_SEQ_WINDOW_SIZE))
    _rev_segs: deque = field(default_factory=lambda: deque(maxlen=_SEQ_WINDOW_SIZE))

    # Last ACK number per direction (for dup-ACK detection)
    _fwd_last_ack: Optional[int] = None
    _rev_last_ack: Optional[int] = None
    _fwd_ack_count: int = 0
    _rev_ack_count: int = 0

    # Initial sequence numbers (set on SYN, used for ISN display)
    isn_fwd: Optional[int] = None   # ISN in forward direction
    isn_rev: Optional[int] = None   # ISN in reverse direction

    def record_segment(
        self,
        seq: int,
        payload_len: int,
        is_forward: bool,
    ) -> bool:
        """
        Record a TCP segment and detect retransmissions.

        Returns True if this segment is a retransmission (seq already seen
        for the same direction with the same or overlapping length).
        """
        if payload_len == 0:
            return False   # Pure ACK / control — not a retransmission candidate

        segs = self._fwd_segs if is_forward else self._rev_segs
        key  = (seq, payload_len)

        # Check for retransmission: same (seq, len) already in window
        is_retx = _seq_seen(segs, seq, payload_len)
        segs.append(key)
        return is_retx

    def record_ack(
        self,
        ack: int,
        win: int,
        is_forward: bool,
    ) -> tuple[bool, bool]:
        """
        Record an ACK number and window size.

        Returns (is_dup_ack, is_zero_window).
        A duplicate ACK is three consecutive identical ACKs without
        intervening new data (RFC 5681).
        """
        is_dup_ack      = False
        is_zero_window  = (win == 0)

        if is_forward:
            if ack == self._fwd_last_ack:
                self._fwd_ack_count += 1
                if self._fwd_ack_count >= 3:
                    is_dup_ack = True
            else:
                self._fwd_last_ack  = ack
                self._fwd_ack_count = 1
        else:
            if ack == self._rev_last_ack:
                self._rev_ack_count += 1
                if self._rev_ack_count >= 3:
                    is_dup_ack = True
            else:
                self._rev_last_ack  = ack
                self._rev_ack_count = 1

        return is_dup_ack, is_zero_window


def _seq_seen(segs: deque, seq: int, length: int) -> bool:
    """Return True if (seq, length) was already recorded in *segs*."""
    for (s, l) in segs:
        # Handle 32-bit wraparound: treat as equal if within threshold
        delta = abs(seq - s)
        if delta > _SEQ_WRAP_THRESHOLD:
            delta = (2 ** 32) - delta
        if delta == 0 and l == length:
            return True
    return False


# ── Main update function ──────────────────────────────────────────────────────

def update_tcp_flow(
    session: TCPSession,
    pkt: dict,
    flow: FlowRecord,
) -> None:
    """
    Apply one TCP packet's information to a TCPSession and update the
    corresponding FlowRecord.

    Parameters
    ----------
    session : TCPSession
        Mutable session state bound to the flow.
    pkt : dict
        Parsed packet dict from AI_PCAP_new_Apr27.py's parse_all().
    flow : FlowRecord
        The flow record to update in-place.
    """
    flags_str = pkt.get('tcp_flags', '')
    seq       = pkt.get('tcp_seq',  0) or 0
    ack       = pkt.get('tcp_ack',  0) or 0
    win       = pkt.get('tcp_window', 0) or 0
    is_fwd    = pkt.get('src_ip', '') == flow.src_ip and \
                pkt.get('src_port', 0) == flow.src_port

    # ── Flag parsing ─────────────────────────────────────────────────────

    has_syn = 'SYN' in flags_str
    has_ack = 'ACK' in flags_str
    has_fin = 'FIN' in flags_str
    has_rst = 'RST' in flags_str
    has_psh = 'PSH' in flags_str

    # ── Handshake tracking ────────────────────────────────────────────────

    if has_syn and not has_ack:
        flow.tcp_syn += 1
        flow.tcp_state = 'handshake' if flow.tcp_state != 'established' else flow.tcp_state
        # Record ISN
        if is_fwd and session.isn_fwd is None:
            session.isn_fwd = seq
        elif not is_fwd and session.isn_rev is None:
            session.isn_rev = seq

    elif has_syn and has_ack:
        flow.tcp_synack += 1
        flow.tcp_state   = 'handshake'

    # ── Teardown tracking ────────────────────────────────────────────────

    if has_fin:
        flow.tcp_fin  += 1
        if flow.tcp_state not in ('reset', 'closed'):
            flow.tcp_state = 'closing'

    if has_rst:
        flow.tcp_rst  += 1
        flow.tcp_state = 'reset'
        flow.has_errors = True

    # Transition handshake → established on first ACK-only or data packet
    if (flow.tcp_state == 'handshake' and has_ack
            and not has_syn and not has_fin):
        flow.tcp_state = 'established'

    # ── Payload length for retransmission detection ───────────────────────
    # Estimate TCP payload size from frame_len − expected header overhead.
    # We use pkt['frame_len'] minus a conservative fixed estimate (54 bytes:
    # 14 Ethernet + 20 IP + 20 TCP) rather than requiring an exact offset.
    frame_len   = pkt.get('frame_len', 0)
    payload_len = max(0, frame_len - 54)

    # ── Retransmission detection ─────────────────────────────────────────

    if has_psh or payload_len > 0:
        is_retx = session.record_segment(seq, max(payload_len, 1), is_fwd)
        if is_retx:
            flow.retransmissions += 1

    # ── Duplicate ACK / zero-window detection ────────────────────────────

    if has_ack:
        is_dup, is_zero_win = session.record_ack(ack, win, is_fwd)
        if is_dup:
            flow.dup_acks += 1
        if is_zero_win:
            flow.zero_windows += 1

    # ── Error signals ────────────────────────────────────────────────────

    if flow.retransmissions > 0 or flow.dup_acks > 2:
        flow.has_errors = True

    # ── Update app proto from packet if more specific ─────────────────────

    proto = pkt.get('proto', '')
    if proto and proto != '?' and proto not in ('TCP', 'IPv4'):
        flow.app_proto = proto
        from flow.record import RFC_MAP
        flow.rfc_ref   = RFC_MAP.get(proto, flow.rfc_ref)


# ── TCP state finalisation ────────────────────────────────────────────────────

def finalise_tcp_state(flow: FlowRecord) -> None:
    """
    Compute the final TCP state for a flow after all packets are processed.

    Called by FlowEngine._finalise_flows() — do not call per-packet.
    """
    base = flow.tcp_state

    if flow.tcp_syn > 0 and flow.tcp_synack > 0 and flow.tcp_fin > 0 and flow.tcp_rst == 0:
        flow.is_complete = True
        flow.tcp_state   = 'closed'
    elif flow.tcp_rst > 0:
        flow.tcp_state   = 'reset'
    elif flow.tcp_fin > 0 and flow.tcp_state not in ('reset', 'closed'):
        flow.tcp_state   = 'closing'
    elif flow.tcp_syn > 0 and flow.tcp_synack == 0:
        flow.tcp_state   = 'half-open'
    elif flow.tcp_syn > 0 and flow.tcp_synack > 0 and flow.tcp_state == 'handshake':
        flow.tcp_state   = 'established'
    elif not base:
        # Mid-stream only (capture started after handshake)
        flow.tcp_state   = 'established'
