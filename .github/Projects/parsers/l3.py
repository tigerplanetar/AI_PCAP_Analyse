"""
parsers/l3.py — Layer 3 Protocol Parsers
=========================================
Modular parsers for:  IPv4 · IPv6 · ICMP · ICMPv6 · IGMP

RFC references:
  IPv4    — RFC 791
  IPv6    — RFC 8200
  ICMP    — RFC 792
  ICMPv6  — RFC 4443
  IGMP    — RFC 3376 (v3), RFC 2236 (v2), RFC 1112 (v1)
"""

from __future__ import annotations
import struct
from parsers.registry import BaseParser, ParseContext


# ── Shared ICMP / IPv4 constants ──────────────────────────────────────────────

ICMP_TYPES = {
    0:  ('Echo Reply',              'Host responded to ping — reachable (RFC 792)'),
    3:  ('Destination Unreachable', 'Packet could not reach destination (RFC 792)'),
    4:  ('Source Quench',           'Congestion control — deprecated (RFC 6633)'),
    5:  ('Redirect',                'Use a better route (RFC 792)'),
    8:  ('Echo Request',            'Ping — testing if host is reachable (RFC 792)'),
    9:  ('Router Advertisement',    'Router announcing its presence (RFC 1256)'),
    10: ('Router Solicitation',     'Host requesting router info (RFC 1256)'),
    11: ('Time Exceeded',           'TTL=0 — used by traceroute (RFC 792)'),
    12: ('Parameter Problem',       'Malformed IP header (RFC 792)'),
    13: ('Timestamp',               'Clock synchronisation request (RFC 792)'),
    14: ('Timestamp Reply',         'Clock synchronisation reply (RFC 792)'),
}

ICMP_CODES = {
    (3, 0): 'Network Unreachable',          (3, 1): 'Host Unreachable',
    (3, 2): 'Protocol Unreachable',         (3, 3): 'Port Unreachable',
    (3, 4): 'Fragmentation Needed (DF set)', (3, 6): 'Destination Network Unknown',
    (3, 7): 'Destination Host Unknown',     (3, 9): 'Network Administratively Prohibited',
    (3, 10): 'Host Administratively Prohibited',
    (3, 13): 'Communication Administratively Prohibited',
    (11, 0): 'TTL Expired in Transit',      (11, 1): 'Fragment Reassembly Timeout',
    (5, 0): 'Redirect for Network',         (5, 1): 'Redirect for Host',
    (5, 2): 'Redirect for TOS & Network',   (5, 3): 'Redirect for TOS & Host',
}

DSCP_NAMES = {
    0: 'CS0 / Best Effort',  8: 'CS1 (Low Priority)',
    10: 'AF11',              12: 'AF12',             14: 'AF13',
    16: 'CS2',               18: 'AF21',             20: 'AF22',
    22: 'AF23',              24: 'CS3',              26: 'AF31',
    28: 'AF32',              30: 'AF33',             32: 'CS4',
    34: 'AF41',              36: 'AF42',             38: 'AF43',
    40: 'CS5',               46: 'EF (VoIP)',
    48: 'CS6 (Network Control)', 56: 'CS7',
}

IP_FLAGS = {0: 'None', 1: 'MF (More Fragments)', 2: 'DF (Do Not Fragment)', 3: 'MF+DF'}

_IP_PROTOS = {
    1: 'ICMP', 2: 'IGMP', 4: 'IP-in-IP', 6: 'TCP', 17: 'UDP',
    41: 'IPv6', 47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6',
    89: 'OSPF', 103: 'PIM', 112: 'VRRP', 132: 'SCTP',
}


# ── IPv4 Parser ───────────────────────────────────────────────────────────────

class IPv4Parser(BaseParser):
    """RFC 791 — Internet Protocol version 4."""
    priority = 40

    def can_parse(self, ctx: ParseContext) -> bool:
        return ctx.eth_type == 0x0800 and len(ctx.raw) >= 20

    def parse(self, ctx: ParseContext):
        d   = ctx.raw
        ihl = (d[0] & 0xF) * 4
        dscp  = d[1] >> 2
        ecn   = d[1] & 3
        tlen  = struct.unpack('!H', d[2:4])[0]
        ip_id = struct.unpack('!H', d[4:6])[0]
        fraw  = struct.unpack('!H', d[6:8])[0]
        flags = (fraw >> 13) & 7
        foff  = (fraw & 0x1FFF) * 8
        ttl   = d[8]
        proto = d[9]
        cksum = struct.unpack('!H', d[10:12])[0]
        src   = self._ip4(d[12:16])
        dst   = self._ip4(d[16:20])

        pn = _IP_PROTOS.get(proto, str(proto))

        # RFC 791 validation hints
        notes = []
        if ttl == 1:
            notes.append('TTL=1 — will not be forwarded beyond next hop')
        if ttl < 10:
            notes.append(f'TTL={ttl} — very low, may be traceroute or misconfiguration')
        if flags == 2 and foff > 0:
            notes.append('DF set but fragment offset > 0 — invalid per RFC 791')
        if ihl < 20:
            notes.append(f'IHL={ihl} bytes is below minimum 20 — malformed header')

        ctx.pkt.update({'src_ip': src, 'dst_ip': dst, 'ttl': ttl})
        ctx.src_ip = src
        ctx.dst_ip = dst
        ctx.transport_proto = pn if pn in ('TCP', 'UDP', 'ICMP', 'IGMP') else ''

        # Update context raw to the IP payload
        ctx.raw = d[ihl:] if ihl <= len(d) else b''
        ctx.eth_type = proto   # reuse eth_type slot for next-layer dispatch

        layer = self._layer('IPv4 — Internet Protocol v4  (RFC 791)', '#10b981', [
            self._field('Version',         '4',                                    'IPv4'),
            self._field('Header Length',   f'{ihl} bytes',                        'IHL×4, min=20'),
            self._field('DSCP / QoS',      f'{dscp} ({DSCP_NAMES.get(dscp, "Custom")})', 'Quality of Service marking'),
            self._field('ECN',             f'{ecn}',                              'Explicit Congestion Notification'),
            self._field('Total Length',    f'{tlen} bytes',                        'IP header + payload'),
            self._field('Identification',  f'0x{ip_id:04x} ({ip_id})',            'Fragment reassembly ID'),
            self._field('Flags',           IP_FLAGS.get(flags, str(flags)),       'DF/MF fragment control flags'),
            self._field('Fragment Offset', f'{foff} bytes',                       'Position in original datagram'),
            self._field('TTL',             f'{ttl}',                              'Max hops remaining before discard'),
            self._field('Protocol',        f'{proto} ({pn})',                     f'RFC: {_ip_proto_rfc(proto)}'),
            self._field('Checksum',        f'0x{cksum:04x}',                     'Header error detection'),
            self._field('Source IP',       src,                                   'Originating device'),
            self._field('Destination IP',  dst,                                   'Target device'),
        ] + ([self._field('RFC 791 Note', n, '') for n in notes] if notes else []))

        return '__IPv4__', f'IPv4 {src} → {dst} ({pn})', [layer], ctx


def _ip_proto_rfc(proto: int) -> str:
    return {1: 'RFC 792', 6: 'RFC 793', 17: 'RFC 768', 2: 'RFC 3376',
            58: 'RFC 4443', 89: 'RFC 5340', 112: 'RFC 5798'}.get(proto, '')


# ── ICMP Parser ───────────────────────────────────────────────────────────────

class ICMPParser(BaseParser):
    """RFC 792 — Internet Control Message Protocol."""
    priority = 50

    def can_parse(self, ctx: ParseContext) -> bool:
        # Triggered after IPv4Parser sets eth_type = 1
        return ctx.eth_type == 1 and len(ctx.raw) >= 8

    def parse(self, ctx: ParseContext):
        d = ctx.raw
        t = d[0]; c = d[1]
        cksum = struct.unpack('!H', d[2:4])[0]

        t_name, t_desc = ICMP_TYPES.get(t, (f'Type {t}', f'ICMP type {t}'))
        c_desc = ICMP_CODES.get((t, c), f'Code {c}')
        src, dst = ctx.pkt.get('src_ip', '?'), ctx.pkt.get('dst_ip', '?')

        fields = [
            self._field('Type',     f'{t} ({t_name})', t_desc),
            self._field('Code',     f'{c} ({c_desc})', 'Sub-classification'),
            self._field('Checksum', f'0x{cksum:04x}',  'Error detection'),
        ]

        if t in (0, 8) and len(d) >= 8:
            icmp_id  = struct.unpack('!H', d[4:6])[0]
            icmp_seq = struct.unpack('!H', d[6:8])[0]
            fields += [
                self._field('Identifier', str(icmp_id),  'Matches request to reply'),
                self._field('Sequence',   str(icmp_seq), 'Detects dropped pings'),
            ]
            ctx.pkt.update({'icmp_id': icmp_id, 'icmp_seq': icmp_seq})

        if t == 3 and len(d) >= 8:
            # Include original IP header hint
            fields.append(self._field('Explanation',
                f'Packet to {dst} was rejected: {c_desc}', 'Unreachable detail'))

        if t == 11:
            fields.append(self._field('Traceroute',
                'TTL expired — packet passed through this router', 'Standard traceroute behaviour'))

        summary = f'ICMP {t_name}  {src} → {dst}  (code={c}, ttl={ctx.pkt.get("ttl", "?")})'
        ctx.pkt.update({
            'proto': 'ICMP', 'icmp_type': t, 'icmp_code': c,
            'icmp_type_str': t_name, 'summary': summary,
        })

        layer = self._layer('ICMP — Internet Control Message Protocol  (RFC 792)', '#ef4444', fields)
        return 'ICMP', summary, [layer], ctx


# ── IGMP Parser ───────────────────────────────────────────────────────────────

class IGMPParser(BaseParser):
    """RFC 3376 / 2236 / 1112 — Internet Group Management Protocol."""
    priority = 50

    _TYPES = {
        0x11: ('Membership Query',      'Router queries group members'),
        0x16: ('v2 Membership Report',  'Host joins group (IGMPv2)'),
        0x17: ('Leave Group',           'Host leaves multicast group'),
        0x22: ('v3 Membership Report',  'Host joins/leaves (IGMPv3)'),
    }

    def can_parse(self, ctx: ParseContext) -> bool:
        return ctx.eth_type == 2 and len(ctx.raw) >= 8

    def parse(self, ctx: ParseContext):
        d = ctx.raw
        igmp_t   = d[0]
        igmp_rt  = d[1]
        igmp_ck  = struct.unpack('!H', d[2:4])[0]
        grp      = self._ip4(d[4:8])
        t_name, t_desc = self._TYPES.get(igmp_t, (f'Type 0x{igmp_t:02x}', 'Unknown IGMP message'))

        # IGMPv3 source list
        src_count = 0
        if igmp_t == 0x22 and len(d) >= 8:
            src_count = struct.unpack('!H', d[6:8])[0] if len(d) >= 8 else 0

        src, dst = ctx.pkt.get('src_ip', '?'), ctx.pkt.get('dst_ip', '?')
        summary = f'IGMP {t_name}  {src} → {dst}  Group={grp}'
        ctx.pkt.update({'proto': 'IGMP', 'summary': summary})

        fields = [
            self._field('Type',           f'0x{igmp_t:02x} ({t_name})', t_desc),
            self._field('Max Resp Time',  f'{igmp_rt / 10:.1f}s',        'Max wait before responding'),
            self._field('Checksum',       f'0x{igmp_ck:04x}',            'Error detection'),
            self._field('Group Address',  grp,                            'Multicast group'),
        ]
        if src_count:
            fields.append(self._field('Source Count', str(src_count), 'IGMPv3 source-specific multicast'))

        layer = self._layer('IGMP — Internet Group Management Protocol  (RFC 3376)', '#ec4899', fields)
        return 'IGMP', summary, [layer], ctx


# ── IPv6 Parser ───────────────────────────────────────────────────────────────

def _ipv6_addr(data: bytes, offset: int) -> str:
    groups = [struct.unpack('!H', data[offset + i*2: offset + i*2 + 2])[0] for i in range(8)]
    return ':'.join(f'{g:04x}' for g in groups)


class IPv6Parser(BaseParser):
    """RFC 8200 — Internet Protocol version 6."""
    priority = 40

    def can_parse(self, ctx: ParseContext) -> bool:
        return ctx.eth_type == 0x86DD and len(ctx.raw) >= 40

    def parse(self, ctx: ParseContext):
        d   = ctx.raw
        tc   = ((d[0] & 0xF) << 4) | (d[1] >> 4)
        flow = ((d[1] & 0xF) << 16) | struct.unpack('!H', d[2:4])[0]
        plen = struct.unpack('!H', d[4:6])[0]
        nxt  = d[6]
        hop  = d[7]
        s6   = _ipv6_addr(d, 8)
        d6   = _ipv6_addr(d, 24)

        nxt_name = _IP_PROTOS.get(nxt, str(nxt))

        ctx.pkt.update({'proto': 'IPv6', 'src_ip': s6, 'dst_ip': d6})
        ctx.src_ip = s6; ctx.dst_ip = d6
        ctx.raw = d[40:]
        ctx.eth_type = nxt   # inner protocol

        # Link-local and multicast detection
        is_link_local = s6.startswith('fe80:')
        is_multicast  = d6.startswith('ff')
        scope_note    = 'Link-local scope' if is_link_local else ('Multicast' if is_multicast else 'Global unicast')

        layer = self._layer('IPv6 — Internet Protocol v6  (RFC 8200)', '#06b6d4', [
            self._field('Traffic Class',  str(tc),                       'DSCP+ECN for IPv6'),
            self._field('Flow Label',     f'0x{flow:05x}',               'Same-flow packet identifier'),
            self._field('Payload Length', f'{plen} bytes',               'Data after 40B IPv6 header'),
            self._field('Next Header',    f'{nxt} ({nxt_name})',         'Inner protocol'),
            self._field('Hop Limit',      str(hop),                      'IPv4 TTL equivalent — max hops'),
            self._field('Source IPv6',    s6,                            f'128-bit source ({scope_note})'),
            self._field('Dest IPv6',      d6,                            '128-bit destination'),
        ])

        summary = f'IPv6 {s6[:19]}… → {d6[:19]}… ({nxt_name})'
        return '__IPv6__', summary, [layer], ctx
