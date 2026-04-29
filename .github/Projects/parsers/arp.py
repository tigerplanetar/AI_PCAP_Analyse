"""
parsers/arp.py — ARP Parser  (RFC 826)
=======================================
Standalone parser for Address Resolution Protocol packets.

Public API
----------
    from parsers.arp import parse_arp

    layers = parse_arp(payload, pkt)   # payload starts after Ethernet header
    # pkt['proto'], pkt['summary'] etc. are updated in-place on success.

Design notes
------------
- Call this when EtherType == 0x0806.
- Detects gratuitous ARP (sender IP == target IP) and annotates it.
- Detects RARP opcodes (3/4) and labels them accordingly.
- Human-readable 'Meaning' field explains the packet in plain English
  (protocol-parsing.md requirement).
- Never raises — returns None on malformed/short input.
- Appends one layer dict to pkt['layers'].

ARP packet layout (28 bytes for IPv4/Ethernet):
  Offset  Size  Field
  0       2     Hardware Type
  2       2     Protocol Type
  4       1     HW Address Length
  5       1     Protocol Address Length
  6       2     Operation (1=REQUEST, 2=REPLY)
  8       6     Sender Hardware Address (SHA)
  14      4     Sender Protocol Address (SPA)
  18      6     Target Hardware Address (THA)
  24      4     Target Protocol Address (TPA)

RFC 826 — Address Resolution Protocol
"""

from __future__ import annotations
import struct

from parsers.constants import _mac, _ip4, _field, _layer


# Hardware type codes (IANA assigned numbers)
_HW_TYPES = {
    1:  'Ethernet (10Mb)',
    6:  'IEEE 802 Networks',
    7:  'ARCNET',
    15: 'Frame Relay',
    16: 'ATM',
    17: 'HDLC',
    18: 'Fibre Channel',
    19: 'ATM (RFC 2225)',
    20: 'Serial Line',
}

_OP_NAMES = {
    1: 'REQUEST',
    2: 'REPLY',
    3: 'RARP-REQUEST',
    4: 'RARP-REPLY',
}


def parse_arp(payload: bytes, pkt: dict) -> list[dict] | None:
    """
    Parse an ARP packet.

    The caller must have confirmed EtherType == 0x0806 before calling.

    Parameters
    ----------
    payload : bytes
        Bytes starting immediately after the Ethernet header (EtherType
        field already consumed).  Must be at least 28 bytes.
    pkt : dict
        Accumulating packet dict.  Will be mutated in-place.

    Returns
    -------
    List containing the ARP layer dict on success, or None if the
    payload is shorter than 28 bytes.

    Side-effects
    ------------
    - Updates pkt: proto, src_ip, dst_ip, arp_op, arp_src_mac,
      arp_dst_mac, summary.
    - Appends the ARP layer dict to pkt['layers'].
    """
    if len(payload) < 28:
        return None

    hw  = struct.unpack('!H', payload[0:2])[0]
    pt  = struct.unpack('!H', payload[2:4])[0]
    hln = payload[4]
    pln = payload[5]
    op  = struct.unpack('!H', payload[6:8])[0]
    sha = _mac(payload[8:14]);   spa = _ip4(payload[14:18])
    tha = _mac(payload[18:24]);  tpa = _ip4(payload[24:28])

    op_str  = _OP_NAMES.get(op, f'OP{op}')
    hw_name = _HW_TYPES.get(hw, f'HW-{hw}')
    pt_name = 'IPv4' if pt == 0x0800 else f'0x{pt:04x}'

    if op == 1:
        summary = f'ARP REQUEST: Who has {tpa}? Tell {spa}'
        meaning = f'{spa} asks: Who has {tpa}? Tell me your MAC.'
    elif op == 2:
        summary = f'ARP REPLY: {spa} is at {sha}'
        meaning = f'{spa} replies: I have {tpa}. My MAC is {sha}.'
    else:
        summary = f'ARP {op_str}: {spa} → {tpa}'
        meaning = f'ARP operation {op_str} — sender={spa}, target={tpa}'

    # Gratuitous ARP: sender announces/refreshes its own mapping
    # (sender IP == target IP, RFC 826 §6)
    is_gratuitous = (spa == tpa and op in (1, 2))
    if is_gratuitous:
        summary += ' [GRATUITOUS]'
        meaning += ' NOTE: Gratuitous ARP — sender is announcing or updating its own IP↔MAC mapping.'

    pkt.update({
        'proto':       'ARP',
        'src_ip':      spa,
        'dst_ip':      tpa,
        'arp_op':      op_str,
        'arp_src_mac': sha,
        'arp_dst_mac': tha,
        'summary':     summary,
    })

    layer = _layer('ARP — Address Resolution Protocol  (RFC 826)', '#f59e0b', [
        _field('Hardware Type',           f'0x{hw:04x} ({hw_name})',  'Layer 2 technology'),
        _field('Protocol Type',           f'0x{pt:04x} ({pt_name})', 'L3 protocol being resolved'),
        _field('HW Address Length',       f'{hln} bytes',            'MAC = 6 bytes'),
        _field('Protocol Address Length', f'{pln} bytes',            'IPv4 = 4 bytes'),
        _field('Operation',               f'{op} ({op_str})',        '1=REQUEST  2=REPLY  3=RARP-REQ  4=RARP-REP'),
        _field('Sender MAC',              sha,                       'MAC of device sending this ARP'),
        _field('Sender IP',               spa,                       'IP of device sending this ARP'),
        _field('Target MAC',              tha,                       'All zeros in REQUEST = unknown target'),
        _field('Target IP',               tpa,                       'IP address being looked up'),
        _field('Gratuitous',              'Yes' if is_gratuitous else 'No', 'Sender IP == Target IP'),
        _field('Meaning',                 meaning,                   'Plain English interpretation'),
    ])
    pkt.setdefault('layers', []).append(layer)
    return [layer]
