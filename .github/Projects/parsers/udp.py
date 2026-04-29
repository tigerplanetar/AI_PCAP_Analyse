"""
parsers/udp.py — UDP Datagram Parser  (RFC 768)
================================================
Standalone parser for User Datagram Protocol datagrams.
Also performs inline SNMP detection (RFC 3411) on non-standard ports
via BER/ASN.1 payload inspection — mirroring the logic in _parse_one().

Public API
----------
    from parsers.udp import parse_udp

    layers = parse_udp(payload, pkt, src_ip='10.0.0.1', dst_ip='10.0.0.2')
    # pkt['proto'] will be updated to 'SNMP' or 'SNMP-Trap' if detected.

Design notes
------------
- Call this when IPv4 protocol number == 17 (or equivalent context).
- App-layer protocol is classified via port mapping (_classify_app).
- SNMP ASN.1 detection runs when port-based classification reports 'UDP'
  (i.e. the well-known ports 161/162 are absent) — same behaviour as
  _parse_one() in AI_PCAP_new_Apr27.py.
- Returns None on malformed/short input, never raises.
- May append 1 or 2 layer dicts to pkt['layers'] (UDP + optional SNMP).

UDP datagram layout (8-byte header):
  Offset  Bits  Field
  0       16    Source Port
  2       16    Destination Port
  4       16    Length (header + data)
  6       16    Checksum (0x0000 = disabled for IPv4, mandatory for IPv6)

RFC 768  — User Datagram Protocol
RFC 3411 — SNMP Management Framework (version negotiation)
RFC 3550 — RTP (detected via high-numbered UDP port range 16384–32767)
"""

from __future__ import annotations
import struct

from parsers.constants import (
    SERVICES, RFC_REF,
    _field, _layer,
    _classify_app, _detect_snmp,
)


def parse_udp(
    payload: bytes,
    pkt: dict,
    src_ip: str = '',
    dst_ip: str = '',
) -> list[dict] | None:
    """
    Parse a UDP datagram.

    The caller must have confirmed IPv4 protocol == 17 (or equivalent).

    Parameters
    ----------
    payload : bytes
        Bytes starting at the first byte of the UDP header (source port).
        Must be at least 8 bytes.
    pkt : dict
        Accumulating packet dict.  Will be mutated in-place.
    src_ip, dst_ip : str
        IP addresses from the enclosing IPv4 header (for the summary).

    Returns
    -------
    List of layer dicts (UDP layer, and optionally SNMP layer) on success,
    or None if the payload is shorter than 8 bytes.

    Side-effects
    ------------
    - Updates pkt: proto, src_port, dst_port, service, summary.
    - If SNMP is detected, also updates pkt['proto'] and pkt['summary']
      to reflect the SNMP version/PDU.
    - Appends UDP layer dict (and optional SNMP layer dict) to
      pkt['layers'].
    """
    if len(payload) < 8:
        return None

    sp     = struct.unpack('!H', payload[0:2])[0]
    dp     = struct.unpack('!H', payload[2:4])[0]
    udplen = struct.unpack('!H', payload[4:6])[0]
    ck     = struct.unpack('!H', payload[6:8])[0]
    udp_data = payload[8:]

    svc       = SERVICES.get(dp) or SERVICES.get(sp, '')
    app_proto = _classify_app('UDP', dp, sp) or 'UDP'

    pkt.update({
        'proto':    app_proto,
        'src_port': sp,
        'dst_port': dp,
        'service':  svc,
        'summary':  (
            f'{app_proto} {src_ip}:{sp} → {dst_ip}:{dp}'
            + (f' {svc}' if svc else '')
        ),
    })

    udp_layer = _layer('UDP — User Datagram Protocol  (RFC 768)', '#10b981', [
        _field('Source Port',      str(sp),
               f'{"Well-known service" if sp < 1024 else "Client (ephemeral)"} port'),
        _field('Destination Port', f'{dp}{f" ({svc})" if svc else ""}',
               f'{"Well-known service" if dp < 1024 else "Client (ephemeral)"} port'),
        _field('Length',           f'{udplen} bytes',  'UDP header (8B) + payload'),
        _field('Checksum',         f'0x{ck:04x}',      '0x0000 = disabled (optional for IPv4)'),
        _field('Service',          svc or 'Unknown',  RFC_REF.get(svc, '')),
        _field('Note',             'Connectionless — no handshake',
               'Low overhead; no retransmit or ordering guarantee'),
    ])
    pkt.setdefault('layers', []).append(udp_layer)
    layers: list[dict] = [udp_layer]

    # SNMP detection via ASN.1/BER payload inspection.
    # Only inspect when port-based classification did not already identify SNMP
    # (i.e. traffic on non-standard ports may still carry SNMP).
    if app_proto == 'UDP' and udp_data:
        snmp_info = _detect_snmp(udp_data)
        if snmp_info:
            ver_s, comm_s, pdu_s, is_trap = snmp_info
            snmp_proto = 'SNMP-Trap' if is_trap else 'SNMP'
            pkt['proto']   = snmp_proto
            pkt['summary'] = (
                f'{snmp_proto} {ver_s} {pdu_s}  '
                f'{src_ip}:{sp} → {dst_ip}:{dp}  '
                f'community="{comm_s}"'
            )
            snmp_layer = _layer(
                f'SNMP — Simple Network Management Protocol  ({ver_s})',
                '#f97316',
                [
                    _field('Version',   ver_s,  'SNMP protocol version'),
                    _field('Community', comm_s, 'Authentication string (plaintext in SNMPv1/v2c)'),
                    _field('PDU Type',  pdu_s,  'SNMP operation'),
                    _field('Direction', f'{src_ip} → {dst_ip}', f'Port {sp} → {dp}'),
                ],
            )
            pkt.setdefault('layers', []).append(snmp_layer)
            layers.append(snmp_layer)

    return layers
