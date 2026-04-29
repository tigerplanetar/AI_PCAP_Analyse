"""
parsers/ipv4.py — IPv4, ICMP and IGMP Parsers
==============================================
Standalone parsers for IPv4 (RFC 791), ICMP (RFC 792) and
IGMP (RFC 3376) as they appear nested inside IPv4 payloads.

Public API
----------
    from parsers.ipv4 import parse_ipv4, parse_icmp, parse_igmp

    result = parse_ipv4(payload, pkt)
    if result:
        src_ip, dst_ip, proto_num, ip_payload = result
        if proto_num == 1:
            parse_icmp(ip_payload, pkt, src_ip, dst_ip, ttl=pkt['ttl'])
        elif proto_num == 2:
            parse_igmp(ip_payload, pkt, src_ip, dst_ip)
        # proto 6 → tcp.py, proto 17 → udp.py

Design notes
------------
- parse_ipv4() validates the IHL field and caps at packet length — it
  never reads past the end of the buffer.
- RFC 791 advisory notes are added for notable TTL values.
- ICMP parse handles both id/seq fields (types 0 and 8) and the
  directionless variant (all other types).
- All three functions return None on malformed/short input and never
  raise exceptions.

IPv4 header (minimum 20 bytes):
  Offset  Bits  Field
  0       4     Version
  0       4     IHL (header length in 32-bit words)
  1       8     DSCP (6) + ECN (2)
  2       16    Total Length
  4       16    Identification
  6       3     Flags  +  13  Fragment Offset
  8       8     TTL
  9       8     Protocol
  10      16    Header Checksum
  12      32    Source Address
  16      32    Destination Address
  20+           Options (if IHL > 5)

RFC 791  — Internet Protocol v4
RFC 792  — Internet Control Message Protocol
RFC 3376 — Internet Group Management Protocol v3
"""

from __future__ import annotations
import struct

from parsers.constants import (
    _ip4, _field, _layer,
    DSCP_NAMES, IP_FLAGS, IP_PROTOS,
    ICMP_TYPES, ICMP_CODES, IGMP_TYPES,
)


def parse_ipv4(
    payload: bytes,
    pkt: dict,
) -> tuple[str, str, int, bytes] | None:
    """
    Parse an IPv4 header.

    The caller must have confirmed EtherType == 0x0800.

    Parameters
    ----------
    payload : bytes
        Bytes starting at the first byte of the IPv4 header (version/IHL).
    pkt : dict
        Accumulating packet dict.  Will be mutated in-place.

    Returns
    -------
    (src_ip, dst_ip, proto_num, ip_payload) on success, or None if:
    - payload is shorter than 20 bytes, or
    - IHL field encodes a header shorter than 20 bytes (invalid).

    Side-effects
    ------------
    - Sets pkt['src_ip'], pkt['dst_ip'], pkt['ttl'].
    - Appends the IPv4 layer dict to pkt['layers'].
    """
    if len(payload) < 20:
        return None

    ihl   = (payload[0] & 0x0F) * 4
    if ihl < 20:
        return None

    dscp  = payload[1] >> 2
    ecn   = payload[1] & 0x3
    tlen  = struct.unpack('!H', payload[2:4])[0]
    ip_id = struct.unpack('!H', payload[4:6])[0]
    fraw  = struct.unpack('!H', payload[6:8])[0]
    flags = (fraw >> 13) & 0x7
    foff  = (fraw & 0x1FFF) * 8
    ttl   = payload[8]
    proto = payload[9]
    cksum = struct.unpack('!H', payload[10:12])[0]
    src   = _ip4(payload[12:16])
    dst   = _ip4(payload[16:20])

    # Extract payload, capped to buffer length to handle short captures
    ip_payload = payload[ihl:ihl + max(0, tlen - ihl)] if ihl < len(payload) else b''
    if not ip_payload:
        ip_payload = payload[ihl:]

    pn = IP_PROTOS.get(proto, str(proto))

    pkt.update({'src_ip': src, 'dst_ip': dst, 'ttl': ttl})

    layer = _layer('IPv4 — Internet Protocol v4  (RFC 791)', '#10b981', [
        _field('Version',         '4',                                       'IPv4'),
        _field('Header Length',   f'{ihl} bytes',                           'IHL×4, min=20'),
        _field('DSCP / QoS',      f'{dscp} ({DSCP_NAMES.get(dscp, "?")})', 'Quality of Service marking'),
        _field('ECN',             str(ecn),                                  'Explicit Congestion Notification'),
        _field('Total Length',    f'{tlen} bytes',                          'IP header + payload'),
        _field('Identification',  f'0x{ip_id:04x} ({ip_id})',              'Fragment reassembly group ID'),
        _field('Flags',           IP_FLAGS.get(flags, str(flags)),          'DF=Do-Not-Fragment  MF=More-Fragments'),
        _field('Fragment Offset', f'{foff} bytes',                          'Position in original datagram'),
        _field('TTL',             str(ttl),                                  'Hops remaining before discard'),
        _field('Protocol',        f'{proto} ({pn})',                        'Encapsulated upper-layer protocol'),
        _field('Checksum',        f'0x{cksum:04x}',                        'Header error detection'),
        _field('Source IP',       src,                                       'Originating host'),
        _field('Destination IP',  dst,                                       'Target host'),
    ])
    pkt.setdefault('layers', []).append(layer)

    return src, dst, proto, ip_payload


def parse_icmp(
    payload: bytes,
    pkt: dict,
    src_ip: str = '',
    dst_ip: str = '',
    ttl: int = 0,
) -> list[dict] | None:
    """
    Parse an ICMP message (IPv4 protocol 1, RFC 792).

    Parameters
    ----------
    payload : bytes
        Bytes starting at the first byte of the ICMP header (type field).
        Must be at least 8 bytes.
    pkt : dict
        Accumulating packet dict.  Will be mutated in-place.
    src_ip, dst_ip : str
        IP addresses from the enclosing IPv4 header (for the summary).
    ttl : int
        TTL from the enclosing IPv4 header (for the summary).

    Returns
    -------
    List containing the ICMP layer dict, or None if too short.

    Side-effects
    ------------
    - Sets pkt['proto'], pkt['icmp_type'], pkt['icmp_code'],
      pkt['icmp_type_str'], pkt['summary'].
    - Appends the ICMP layer dict to pkt['layers'].
    """
    if len(payload) < 8:
        return None

    t  = payload[0]
    c  = payload[1]
    ck = struct.unpack('!H', payload[2:4])[0]

    t_name, t_desc = ICMP_TYPES.get(t, (f'Type {t}', ''))
    c_desc          = ICMP_CODES.get((t, c), f'Code {c}')

    # Identifier and Sequence are only meaningful for Echo Request/Reply
    icmp_id  = struct.unpack('!H', payload[4:6])[0] if t in (0, 8) else None
    icmp_seq = struct.unpack('!H', payload[6:8])[0] if t in (0, 8) else None

    fields = [
        _field('Type',     f'{t} ({t_name})', t_desc),
        _field('Code',     f'{c} ({c_desc})', 'Sub-type further qualifies the Type'),
        _field('Checksum', f'0x{ck:04x}',     'Error detection — covers ICMP header + data'),
    ]
    if icmp_id  is not None:
        fields.append(_field('Identifier',   str(icmp_id),  'Links request to reply'))
    if icmp_seq is not None:
        fields.append(_field('Sequence',     str(icmp_seq), 'Detects out-of-order or lost packets'))
    if src_ip or dst_ip:
        fields.append(_field('Direction', f'{src_ip} → {dst_ip}', ''))

    ttl_note = f'  ttl={ttl}' if ttl else ''
    pkt.update({
        'proto':          'ICMP',
        'icmp_type':      t,
        'icmp_code':      c,
        'icmp_type_str':  t_name,
        'summary':        f'ICMP {t_name}  {src_ip} → {dst_ip}  (code={c}{ttl_note})',
    })

    layer = _layer(
        'ICMP — Internet Control Message Protocol  (RFC 792)',
        '#ef4444',
        fields,
    )
    pkt.setdefault('layers', []).append(layer)
    return [layer]


def parse_igmp(
    payload: bytes,
    pkt: dict,
    src_ip: str = '',
    dst_ip: str = '',
) -> list[dict] | None:
    """
    Parse an IGMP message (IPv4 protocol 2, RFC 3376).

    Parameters
    ----------
    payload : bytes
        Bytes starting at the first byte of the IGMP header (type field).
        Must be at least 8 bytes.
    pkt : dict
        Accumulating packet dict.  Will be mutated in-place.
    src_ip, dst_ip : str
        IP addresses from the enclosing IPv4 header (for the summary).

    Returns
    -------
    List containing the IGMP layer dict, or None if too short.

    Side-effects
    ------------
    - Sets pkt['proto'] and pkt['summary'].
    - Appends the IGMP layer dict to pkt['layers'].
    """
    if len(payload) < 8:
        return None

    igmp_t   = payload[0]
    igmp_rt  = payload[1]
    igmp_ck  = struct.unpack('!H', payload[2:4])[0]
    igmp_grp = _ip4(payload[4:8])

    t_name, t_desc = IGMP_TYPES.get(igmp_t, (f'Type 0x{igmp_t:02x}', 'Unknown IGMP message'))

    pkt.update({
        'proto':   'IGMP',
        'summary': f'IGMP {t_name}  {src_ip} → {dst_ip}  Group={igmp_grp}',
    })

    layer = _layer(
        'IGMP — Internet Group Management Protocol  (RFC 3376)',
        '#ec4899',
        [
            _field('Type',          f'0x{igmp_t:02x} ({t_name})', t_desc),
            _field('Max Resp Time', f'{igmp_rt / 10:.1f}s',        'Max delay before member sends report'),
            _field('Checksum',      f'0x{igmp_ck:04x}',            'Error detection'),
            _field('Group Address', igmp_grp,                       'Multicast group address (0.0.0.0 = general query)'),
        ],
    )
    pkt.setdefault('layers', []).append(layer)
    return [layer]
