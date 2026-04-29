"""
parsers/ethernet.py — Ethernet II Frame Parser
===============================================
Standalone parser for the Ethernet II (IEEE 802.3) frame header.

Public API
----------
    from parsers.ethernet import parse_ethernet

    result = parse_ethernet(raw_frame, pkt)
    if result:
        dst_mac, src_mac, ethertype, payload = result

Design notes
------------
- Never raises — returns None on malformed/short input.
- Appends one layer dict to pkt['layers'] using the same schema as
  _parse_one() in AI_PCAP_new_Apr27.py.
- Initialises pkt['hex_data'] if not already set (first 256 bytes).
- Caller is responsible for deciding what to do with the returned
  ethertype and payload (pass to vlan.py, arp.py, ipv4.py, etc.).

Minimum frame: 14 bytes (6 dst + 6 src + 2 EtherType).
"""

from __future__ import annotations
import struct

from parsers.constants import _mac, _field, _layer


def parse_ethernet(data: bytes, pkt: dict) -> tuple[str, str, int, bytes] | None:
    """
    Parse Ethernet II frame header.

    Parameters
    ----------
    data : bytes
        Raw frame bytes starting at byte 0 (destination MAC).
    pkt : dict
        Accumulating packet dict.  Will be mutated in-place.

    Returns
    -------
    (dst_mac, src_mac, ethertype, payload) on success, or None if the
    frame is shorter than 14 bytes.

    Side-effects
    ------------
    - Sets pkt['src_mac'] and pkt['dst_mac'].
    - Sets pkt['hex_data'] (first 256 raw bytes as int list) if absent.
    - Appends the Ethernet layer dict to pkt['layers'].
    """
    if len(data) < 14:
        return None

    dst_mac = _mac(data[0:6])
    src_mac = _mac(data[6:12])
    et      = struct.unpack('!H', data[12:14])[0]
    payload = data[14:]

    pkt['src_mac'] = src_mac
    pkt['dst_mac'] = dst_mac
    pkt.setdefault('hex_data', list(data[:256]))

    layer = _layer('Ethernet II  (IEEE 802.3)', '#00d4ff', [
        _field('Destination MAC', dst_mac,           'Layer 2 destination'),
        _field('Source MAC',      src_mac,           'Layer 2 source'),
        _field('EtherType',       f'0x{et:04x}',    'Identifies next layer protocol'),
        _field('Frame Length',    f'{len(data)} bytes', 'Total wire frame size'),
    ])
    pkt.setdefault('layers', []).append(layer)

    return dst_mac, src_mac, et, payload
