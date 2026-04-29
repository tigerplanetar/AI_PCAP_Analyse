"""
parsers/l2.py — Layer 2 Protocol Parsers
=========================================
Modular parsers for:  ARP · VLAN (802.1Q) · LLDP · EAPoL (802.1X)
                      STP/RSTP · PPPoE Discovery · PPPoE Session

Each parser is backward-compatible with the layer dict schema used in
AI_PCAP_new_Apr27.py's _parse_one() function.

RFC / Standard references:
  ARP      — RFC 826
  VLAN     — IEEE 802.1Q
  LLDP     — IEEE 802.1AB
  EAPoL    — IEEE 802.1X
  STP/RSTP — IEEE 802.1D / 802.1w
  PPPoE    — RFC 2516
"""

from __future__ import annotations
import struct
from parsers.registry import BaseParser, ParseContext


# ── ARP Parser ────────────────────────────────────────────────────────────────

class ARPParser(BaseParser):
    """RFC 826 — Address Resolution Protocol."""
    priority = 20

    # Hardware type → name
    _HW = {1: 'Ethernet (10Mb)', 6: 'IEEE 802 Networks', 7: 'ARCNET',
           15: 'Frame Relay', 16: 'ATM', 17: 'HDLC', 18: 'Fibre Channel',
           19: 'ATM (RFC 2225)', 20: 'Serial Line'}

    def can_parse(self, ctx: ParseContext) -> bool:
        return ctx.eth_type == 0x0806 and len(ctx.raw) >= 28

    def parse(self, ctx: ParseContext):
        d = ctx.raw
        hw  = struct.unpack('!H', d[0:2])[0]
        pt  = struct.unpack('!H', d[2:4])[0]
        hln = d[4]; pln = d[5]
        op  = struct.unpack('!H', d[6:8])[0]
        sha = self._mac(d[8:14]);  spa = self._ip4(d[14:18])
        tha = self._mac(d[18:24]); tpa = self._ip4(d[24:28])

        op_str = {1: 'REQUEST', 2: 'REPLY', 3: 'RARP-REQUEST', 4: 'RARP-REPLY'}.get(op, f'OP{op}')
        hw_name = self._HW.get(hw, f'HW-{hw}')

        if op == 1:
            summary = f'ARP REQUEST: Who has {tpa}? Tell {spa}'
            meaning = f'{spa} asks: Who has {tpa}? Tell me your MAC.'
        elif op == 2:
            summary = f'ARP REPLY: {spa} is at {sha}'
            meaning = f'{spa} replies: I have {tpa}. My MAC is {sha}.'
        else:
            summary = f'ARP {op_str}: {spa} → {tpa}'
            meaning = f'ARP operation {op_str}'

        # Detect gratuitous ARP (sender IP == target IP)
        is_gratuitous = (spa == tpa and op in (1, 2))
        if is_gratuitous:
            summary += ' [GRATUITOUS]'
            meaning += ' NOTE: Gratuitous ARP — sender is announcing/updating its own MAC.'

        ctx.pkt.update({
            'proto': 'ARP', 'src_ip': spa, 'dst_ip': tpa,
            'arp_op': op_str, 'arp_src_mac': sha, 'arp_dst_mac': tha,
            'summary': summary,
        })

        layer = self._layer(
            'ARP — Address Resolution Protocol  (RFC 826)', '#f59e0b', [
                self._field('Hardware Type',           f'0x{hw:04x} ({hw_name})',   'Layer 2 technology'),
                self._field('Protocol Type',           f'0x{pt:04x} ({"IPv4" if pt == 0x0800 else hex(pt)})', 'L3 protocol being resolved'),
                self._field('HW Address Length',       f'{hln} bytes',              'MAC = 6 bytes'),
                self._field('Protocol Address Length', f'{pln} bytes',              'IPv4 = 4 bytes'),
                self._field('Operation',               f'{op} ({op_str})',           '1=REQUEST 2=REPLY'),
                self._field('Sender MAC',              sha,                          'MAC of device sending ARP'),
                self._field('Sender IP',               spa,                          'IP of device sending ARP'),
                self._field('Target MAC',              tha,                          'All zeros in REQUEST = unknown'),
                self._field('Target IP',               tpa,                          'IP address being looked up'),
                self._field('Gratuitous',              'Yes' if is_gratuitous else 'No',  'Sender IP == Target IP'),
                self._field('Meaning',                 meaning,                      'Plain English interpretation'),
            ]
        )
        return 'ARP', summary, [layer], ctx


# ── VLAN (802.1Q) Parser ──────────────────────────────────────────────────────

_PCP_NAMES = {
    0: 'Best Effort', 1: 'Background', 2: 'Spare', 3: 'Excellent Effort',
    4: 'Controlled Load', 5: 'Video (<100ms latency)', 6: 'Voice (<10ms latency)',
    7: 'Network Control',
}

class VLANParser(BaseParser):
    """IEEE 802.1Q — VLAN Tagged Frame."""
    priority = 10   # strip before any L3 parser

    def can_parse(self, ctx: ParseContext) -> bool:
        return ctx.eth_type == 0x8100 and len(ctx.raw) >= 4

    def parse(self, ctx: ParseContext):
        d = ctx.raw
        tci    = struct.unpack('!H', d[0:2])[0]
        vlan_id = tci & 0xFFF
        pcp     = (tci >> 13) & 7
        dei     = (tci >> 12) & 1
        inner_et = struct.unpack('!H', d[2:4])[0]

        ctx.pkt['vlan_id'] = vlan_id
        ctx.eth_type = inner_et
        ctx.raw = d[4:]   # advance past VLAN tag

        layer = self._layer(
            'VLAN Tag  (IEEE 802.1Q)', '#a78bfa', [
                self._field('TPID',               '0x8100',                          'Tag Protocol Identifier'),
                self._field('User Priority (PCP)', f'{pcp} ({_PCP_NAMES.get(pcp, "?")})', 'QoS priority 0=lowest 7=highest'),
                self._field('Drop Eligible (DEI)', str(dei),                          '1=may be dropped under congestion'),
                self._field('VLAN ID',             f'{vlan_id}  (0x{vlan_id:03x})',  f'VLAN segment {vlan_id}'),
                self._field('Inner EtherType',     f'0x{inner_et:04x}',              'Protocol inside VLAN tag'),
            ]
        )
        # Return a sentinel so the registry continues parsing the inner payload
        return '__VLAN__', f'VLAN {vlan_id}', [layer], ctx


# ── LLDP Parser ───────────────────────────────────────────────────────────────

class LLDPParser(BaseParser):
    """IEEE 802.1AB — Link Layer Discovery Protocol."""
    priority = 25

    _TLV_TYPES = {
        0: 'End of LLDPDU', 1: 'Chassis ID', 2: 'Port ID', 3: 'TTL',
        4: 'Port Description', 5: 'System Name', 6: 'System Description',
        7: 'System Capabilities', 8: 'Management Address',
        127: 'Organizationally Specific',
    }

    def can_parse(self, ctx: ParseContext) -> bool:
        return ctx.eth_type == 0x88CC

    def parse(self, ctx: ParseContext):
        d = ctx.raw
        fields = [
            self._field('Destination', ctx.dst_mac,        '01:80:c2:00:00:0e = LLDP multicast'),
            self._field('Source',      ctx.src_mac,         'MAC of advertising device'),
            self._field('Purpose',     'Device and topology discovery', 'Advertises system name, port, capabilities'),
            self._field('Scope',       'Local segment only', 'Not forwarded by switches'),
        ]

        # Parse TLVs for richer detail
        system_name = ''
        port_desc   = ''
        pos = 0
        try:
            while pos + 2 <= len(d):
                hdr  = struct.unpack('!H', d[pos:pos+2])[0]
                ttype = (hdr >> 9) & 0x7F
                tlen  = hdr & 0x1FF
                pos  += 2
                if ttype == 0:
                    break
                val = d[pos:pos + tlen]
                if ttype == 5 and tlen > 0:
                    system_name = val.decode('utf-8', errors='replace').strip()
                if ttype == 4 and tlen > 0:
                    port_desc = val.decode('utf-8', errors='replace').strip()
                if ttype == 3 and tlen == 2:
                    ttl_val = struct.unpack('!H', val)[0]
                    fields.append(self._field('TTL', f'{ttl_val}s', 'How long neighbor info is valid'))
                pos += tlen
        except Exception:
            pass

        if system_name:
            fields.append(self._field('System Name', system_name, 'Advertising device hostname'))
            ctx.pkt['lldp_system_name'] = system_name
        if port_desc:
            fields.append(self._field('Port Description', port_desc, 'Originating port'))

        summary = f'LLDP — Link Layer Discovery{" from " + system_name if system_name else ""}'
        ctx.pkt.update({'proto': 'LLDP', 'summary': summary})

        layer = self._layer('LLDP — Link Layer Discovery Protocol  (IEEE 802.1AB)', '#8b5cf6', fields)
        return 'LLDP', summary, [layer], ctx


# ── EAPoL (802.1X) Parser ────────────────────────────────────────────────────

class EAPoLParser(BaseParser):
    """IEEE 802.1X — Extensible Authentication Protocol over LAN."""
    priority = 25

    _PKT_TYPES = {0: 'EAP-Packet', 1: 'EAPOL-Start', 2: 'EAPOL-Logoff', 3: 'EAPOL-Key', 4: 'EAPOL-Encapsulated-ASF-Alert'}
    _EAP_CODES = {1: 'Request', 2: 'Response', 3: 'Success', 4: 'Failure'}
    _EAP_TYPES = {1: 'Identity', 2: 'Notification', 3: 'NAK', 4: 'MD5-Challenge',
                  13: 'EAP-TLS', 21: 'TTLS', 25: 'PEAP', 43: 'EAP-FAST'}

    def can_parse(self, ctx: ParseContext) -> bool:
        return ctx.eth_type == 0x888E and len(ctx.raw) >= 4

    def parse(self, ctx: ParseContext):
        d   = ctx.raw
        ver   = d[0]
        ptype = d[1]
        plen  = struct.unpack('!H', d[2:4])[0] if len(d) >= 4 else 0
        pt_str = self._PKT_TYPES.get(ptype, f'Type-{ptype}')

        fields = [
            self._field('Version',     str(ver),  'EAPoL version'),
            self._field('Packet Type', pt_str,    'EAP message type'),
            self._field('Length',      f'{plen} bytes', 'Payload length'),
            self._field('Purpose',     'Port-based NAC — device must authenticate before port opens', ''),
        ]

        # Decode inner EAP packet
        eap_method = ''
        if ptype == 0 and plen >= 4 and len(d) >= 8:
            eap_code  = d[4]
            eap_id    = d[5]
            eap_type  = d[8] if plen > 4 and len(d) >= 9 else 0
            code_str  = self._EAP_CODES.get(eap_code, f'Code-{eap_code}')
            type_str  = self._EAP_TYPES.get(eap_type, f'Type-{eap_type}') if eap_type else ''
            eap_method = type_str
            fields += [
                self._field('EAP Code',       f'{eap_code} ({code_str})', 'EAP message direction'),
                self._field('EAP Identifier', str(eap_id),                'Request/response correlation'),
            ]
            if type_str:
                fields.append(self._field('EAP Method', type_str, 'Authentication method'))

        summary = f'EAPoL 802.1X {pt_str} v{ver}' + (f' [{eap_method}]' if eap_method else '')
        ctx.pkt.update({'proto': 'EAPoL', 'summary': summary})

        layer = self._layer('EAPoL — 802.1X Port Authentication  (IEEE 802.1X)', '#f97316', fields)
        return 'EAPoL', summary, [layer], ctx


# ── STP / RSTP Parser ────────────────────────────────────────────────────────

class STPParser(BaseParser):
    """IEEE 802.1D / 802.1w — Spanning Tree / Rapid Spanning Tree."""
    priority = 30

    def can_parse(self, ctx: ParseContext) -> bool:
        # STP frames have EtherType < 0x0600 (length field) and dst 01:80:c2:00:00:00
        return (ctx.eth_type < 0x0600 and
                ctx.dst_mac == '01:80:c2:00:00:00' and
                len(ctx.raw) >= 7)

    def parse(self, ctx: ParseContext):
        d = ctx.raw
        proto_id = struct.unpack('!H', d[0:2])[0]
        version  = d[2]
        bpdu_type = d[3]
        flags    = d[4] if len(d) > 4 else 0

        _BPDU = {0x00: 'Configuration BPDU', 0x80: 'Topology Change Notification', 0x02: 'RST BPDU'}
        bpdu_str = _BPDU.get(bpdu_type, f'BPDU-{bpdu_type:#04x}')
        version_str = {0: 'STP (802.1D)', 2: 'RSTP (802.1w)', 3: 'MSTP (802.1s)'}.get(version, f'v{version}')
        tc_flag = bool(flags & 0x01)
        tca_flag = bool(flags & 0x80)

        fields = [
            self._field('Protocol ID',  f'0x{proto_id:04x}', 'STP protocol identifier'),
            self._field('Version',      version_str,          'Spanning Tree variant'),
            self._field('BPDU Type',    bpdu_str,             'Type of BPDU message'),
        ]
        if len(d) >= 6:
            fields.append(self._field('TC Flag',  'Set' if tc_flag else 'Clear', 'Topology Change'))
        if bpdu_type == 0x00 and len(d) >= 36:
            root_id  = d[5:13].hex()
            root_cost = struct.unpack('!I', d[13:17])[0]
            bridge_id = d[17:25].hex()
            port_id   = struct.unpack('!H', d[25:27])[0]
            fields += [
                self._field('Root Bridge ID', root_id,           'Current root bridge'),
                self._field('Root Path Cost', str(root_cost),    'Cost to root (lower = preferred)'),
                self._field('Bridge ID',      bridge_id,         'Sending bridge'),
                self._field('Port ID',        f'0x{port_id:04x}', 'Sending port'),
            ]

        summary = f'{version_str} {bpdu_str}' + (' [TC]' if tc_flag else '')
        ctx.pkt.update({'proto': 'STP', 'summary': summary})

        color = '#84cc16'
        layer = self._layer(f'STP/RSTP — Spanning Tree  (IEEE 802.1D/802.1w)', color, fields)
        return 'STP', summary, [layer], ctx


# ── PPPoE Discovery Parser ───────────────────────────────────────────────────

class PPPoEDiscoveryParser(BaseParser):
    """RFC 2516 — PPPoE Discovery Phase."""
    priority = 15

    _CODES = {0x09: 'PADI (Discovery Initiation)', 0x07: 'PADO (Discovery Offer)',
              0x19: 'PADR (Session Request)',       0x65: 'PADS (Session Confirmed)',
              0xa7: 'PADT (Session Terminated)'}

    def can_parse(self, ctx: ParseContext) -> bool:
        return ctx.eth_type == 0x8863 and len(ctx.raw) >= 6

    def parse(self, ctx: ParseContext):
        d = ctx.raw
        ver  = (d[0] >> 4) & 0xF
        typ  = d[0] & 0xF
        code = d[1]
        sid  = struct.unpack('!H', d[2:4])[0]
        plen = struct.unpack('!H', d[4:6])[0]
        code_str = self._CODES.get(code, f'Code 0x{code:02x}')

        summary = f'PPPoE Discovery: {code_str}'
        ctx.pkt.update({'proto': 'PPPoE', 'summary': summary})

        layer = self._layer('PPPoE Discovery  (RFC 2516)', '#f97316', [
            self._field('Version',    str(ver),               'PPPoE version'),
            self._field('Type',       str(typ),               'PPPoE type'),
            self._field('Code',       f'0x{code:02x} ({code_str})', 'Discovery phase'),
            self._field('Session ID', f'0x{sid:04x}',         '0x0000 during discovery'),
            self._field('Length',     f'{plen} bytes',         'Payload length'),
        ])
        return 'PPPoE', summary, [layer], ctx


# ── PPPoE Session Parser ──────────────────────────────────────────────────────

class PPPoESessionParser(BaseParser):
    """RFC 2516 — PPPoE Session Phase (decapsulates to IPv4/IPv6)."""
    priority = 15

    _PPP = {0x0021: 'IPv4', 0x0057: 'IPv6', 0xc021: 'LCP',
            0xc023: 'PAP',  0xc223: 'CHAP', 0x8021: 'IPCP', 0x8057: 'IPv6CP'}

    def can_parse(self, ctx: ParseContext) -> bool:
        return ctx.eth_type == 0x8864 and len(ctx.raw) >= 8

    def parse(self, ctx: ParseContext):
        d = ctx.raw
        ver      = (d[0] >> 4) & 0xF
        code     = d[1]
        sid      = struct.unpack('!H', d[2:4])[0]
        ppp_len  = struct.unpack('!H', d[4:6])[0]
        ppp_proto = struct.unpack('!H', d[6:8])[0]
        ppp_name  = self._PPP.get(ppp_proto, f'PPP-0x{ppp_proto:04x}')

        pppoe_layer = self._layer('PPPoE Session  (RFC 2516)', '#f97316', [
            self._field('Version',        str(ver),                    'PPPoE version'),
            self._field('Type',           str(d[0] & 0xF),             'PPPoE type'),
            self._field('Code',           f'0x{code:02x} ({"Session Data" if code == 0 else "Other"})', 'PPPoE code'),
            self._field('Session ID',     f'0x{sid:04x}',              'PPPoE session identifier'),
            self._field('Payload Length', f'{ppp_len} bytes',           'PPP payload size'),
        ])
        ppp_layer = self._layer('PPP — Point-to-Point Protocol  (RFC 1661)', '#a78bfa', [
            self._field('Protocol', f'0x{ppp_proto:04x} ({ppp_name})', 'Encapsulated protocol'),
        ])

        # Advance past PPPoE header and PPP protocol field
        ctx.raw = d[8:]
        if ppp_proto == 0x0021:
            ctx.eth_type = 0x0800
        elif ppp_proto == 0x0057:
            ctx.eth_type = 0x86DD
        else:
            ctx.eth_type = 0

        summary = f'PPPoE Session [{ppp_name}] SID=0x{sid:04x}'
        ctx.pkt.update({'proto': 'PPPoE', 'summary': summary})

        return '__PPPOE__', summary, [pppoe_layer, ppp_layer], ctx
