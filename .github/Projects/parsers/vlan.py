"""
parsers/vlan.py — IEEE 802.1Q VLAN Tag Parser
==============================================
Standalone parser for 802.1Q VLAN-tagged frames.

Public API
----------
    from parsers.vlan import parse_vlan

    result = parse_vlan(payload, pkt)
    if result:
        vlan_id, inner_ethertype, inner_payload = result

Design notes
------------
- Call this when EtherType == 0x8100 has already been detected.
- Strips the 4-byte VLAN tag and returns the inner EtherType + payload
  so the caller can continue parsing (pass to arp.py, ipv4.py, etc.).
- Handles the EXOS edge-case quirk from _parse_one(): when the inner
  EtherType looks like an IP version byte rather than a full EtherType
  (i.e. it's in the range 0x0800–0x08FF and the low byte has version=4),
  the payload is adjusted to match how _parse_one() handles this.
- Never raises — returns None on malformed/short input.
- Appends one layer dict to pkt['layers'].

IEEE 802.1Q TCI field layout (16 bits):
  [15:13]  PCP — Priority Code Point (3 bits, QoS 0–7)
  [12]     DEI — Drop Eligible Indicator (1 bit)
  [11:0]   VID — VLAN Identifier (12 bits, 0–4094)
"""

from __future__ import annotations
import struct

from parsers.constants import _field, _layer


# IEEE 802.1p Priority Code Point names (QoS marking)
_PCP_NAMES = {
    0: 'Best Effort',            1: 'Background',
    2: 'Spare',                  3: 'Excellent Effort',
    4: 'Controlled Load',        5: 'Video (<100ms latency)',
    6: 'Voice (<10ms latency)',  7: 'Network Control',
}


def parse_vlan(payload: bytes, pkt: dict) -> tuple[int, int, bytes] | None:
    """
    Parse a 802.1Q VLAN tag from the start of *payload*.

    The caller must have already identified EtherType == 0x8100 in the
    Ethernet header before calling this function.

    Parameters
    ----------
    payload : bytes
        Bytes starting immediately after the 0x8100 EtherType field
        (i.e. the first 2 bytes are the TCI, followed by inner EtherType).
    pkt : dict
        Accumulating packet dict.  Will be mutated in-place.

    Returns
    -------
    (vlan_id, inner_ethertype, inner_payload) on success, or None if
    the payload is shorter than 4 bytes.

    Side-effects
    ------------
    - Sets pkt['vlan_id'].
    - Appends the VLAN tag layer dict to pkt['layers'].
    """
    if len(payload) < 4:
        return None

    tci      = struct.unpack('!H', payload[0:2])[0]
    vlan_id  = tci & 0x0FFF
    pcp      = (tci >> 13) & 0x7
    dei      = (tci >> 12) & 0x1
    inner_et = struct.unpack('!H', payload[2:4])[0]
    inner_payload = payload[4:]

    # EXOS quirk: some captures have the IP version byte bleed into the
    # EtherType field.  Detect and correct so IPv4 parsing still works.
    # Condition mirrors the check in _parse_one():
    #   et != 0x0800 and (et & 0xFF00) == 0x0800 and ip_version_nibble == 4
    if (inner_et != 0x0800
            and (inner_et & 0xFF00) == 0x0800
            and len(inner_payload) > 0
            and (inner_et & 0xFF) >> 4 == 4):
        inner_payload = bytes([inner_et & 0xFF]) + inner_payload
        inner_et      = 0x0800

    pkt['vlan_id'] = vlan_id

    layer = _layer('VLAN Tag  (IEEE 802.1Q)', '#a78bfa', [
        _field('TPID',                '0x8100',                               'Tag Protocol Identifier'),
        _field('User Priority (PCP)', f'{pcp} ({_PCP_NAMES.get(pcp, "?")})', 'QoS priority — 0=lowest 7=highest'),
        _field('Drop Eligible (DEI)', str(dei),                               '1=may be dropped under congestion'),
        _field('VLAN ID',             f'{vlan_id}  (0x{vlan_id:03x})',        f'VLAN segment {vlan_id}'),
        _field('Inner EtherType',     f'0x{inner_et:04x}',                   'Protocol inside VLAN tag'),
    ])
    pkt.setdefault('layers', []).append(layer)

    return vlan_id, inner_et, inner_payload
