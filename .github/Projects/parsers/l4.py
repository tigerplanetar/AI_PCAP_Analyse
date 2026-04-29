"""
parsers/l4.py — Layer 4 Protocol Parsers
=========================================
Modular parsers for:  TCP · UDP

RFC references:
  TCP  — RFC 793 (updated by RFC 7323, RFC 6298)
  UDP  — RFC 768

These parsers also handle basic application-layer identification via
APP_PROTO_MAP (port-based) matching the logic in AI_PCAP_new_Apr27.py.
"""

from __future__ import annotations
import struct
from parsers.registry import BaseParser, ParseContext

# ── Well-known services (mirrors SERVICES dict in main script) ────────────────
SERVICES = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP-Server', 68: 'DHCP-Client', 69: 'TFTP',
    80: 'HTTP', 88: 'Kerberos', 110: 'POP3', 123: 'NTP',
    137: 'NetBIOS-NS', 138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN',
    143: 'IMAP', 161: 'SNMP', 162: 'SNMP-Trap', 179: 'BGP',
    389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    500: 'IKE/IPSec', 514: 'Syslog', 520: 'RIP', 546: 'DHCPv6-Client',
    547: 'DHCPv6-Server', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
    1194: 'OpenVPN', 1433: 'MSSQL', 1521: 'Oracle', 1701: 'L2TP',
    1723: 'PPTP', 1812: 'RADIUS-Auth', 1813: 'RADIUS-Acct',
    3306: 'MySQL', 3389: 'RDP', 3799: 'RADIUS-CoA',
    4500: 'IPSec-NAT', 4789: 'VXLAN', 5060: 'SIP', 5061: 'SIPS',
    5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt', 9200: 'Elasticsearch', 27017: 'MongoDB',
}

RFC_REF = {
    'DNS': 'RFC 1035', 'DHCP-Server': 'RFC 2131', 'DHCP-Client': 'RFC 2131',
    'TFTP': 'RFC 1350', 'HTTP': 'RFC 9110', 'HTTPS': 'RFC 9110+TLS',
    'SSH': 'RFC 4253', 'Telnet': 'RFC 854', 'SMTP': 'RFC 5321',
    'SNMP': 'RFC 3411', 'LDAP': 'RFC 4511', 'NTP': 'RFC 5905',
    'BGP': 'RFC 4271', 'RIP': 'RFC 2453', 'RADIUS-Auth': 'RFC 2865',
    'SIP': 'RFC 3261', 'RDP': 'MS-RDPBCGR', 'FTP': 'RFC 959',
    'Syslog': 'RFC 5424', 'VXLAN': 'RFC 7348', 'IKE/IPSec': 'RFC 7296',
}

# TCP flags
TCP_FLAGS_MAP = [
    (0x20, 'URG', 'Urgent pointer valid'),
    (0x10, 'ACK', 'Acknowledgment valid'),
    (0x08, 'PSH', 'Push data immediately to application'),
    (0x04, 'RST', 'Abrupt connection reset'),
    (0x02, 'SYN', 'Synchronise sequence numbers — connection start'),
    (0x01, 'FIN', 'Graceful close — no more data from sender'),
]

# HTTP payload signatures for validation
_HTTP_SIGS = (b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ',
              b'OPTIONS ', b'PATCH ', b'CONNECT ', b'TRACE ', b'HTTP/')


def _tcp_flags_str(b: int) -> str:
    return '|'.join(n for bit, n, _ in TCP_FLAGS_MAP if b & bit) or 'NONE'


def _tcp_state_desc(b: int) -> str:
    if b & 0x02 and not b & 0x10:
        return 'SYN — step 1 of 3-way handshake (client → server)'
    if b & 0x02 and b & 0x10:
        return 'SYN+ACK — step 2 of 3-way handshake (server → client)'
    if b & 0x10 and not b & 0x02 and not b & 0x08:
        return 'ACK — handshake complete or data acknowledgment'
    if b & 0x08 and b & 0x10:
        return 'PSH+ACK — data transfer (push to application)'
    if b & 0x01 and b & 0x10:
        return 'FIN+ACK — graceful connection teardown'
    if b & 0x04:
        return 'RST — abrupt connection reset (error or rejection)'
    if b & 0x10:
        return 'ACK — data acknowledgment'
    return 'Data transfer'


def _classify_app(transport: str, dst_port: int, src_port: int) -> str:
    """Port-based application protocol identification."""
    _MAP = {
        (53, 'UDP'): 'DNS', (53, 'TCP'): 'DNS',
        (67, 'UDP'): 'DHCP-Server', (68, 'UDP'): 'DHCP-Client',
        (69, 'UDP'): 'TFTP', (137, 'UDP'): 'NBNS', (138, 'UDP'): 'NetBIOS-DGM',
        (139, 'TCP'): 'NetBIOS-SSN', (20, 'TCP'): 'FTP-Data', (21, 'TCP'): 'FTP',
        (22, 'TCP'): 'SSH', (23, 'TCP'): 'Telnet', (25, 'TCP'): 'SMTP',
        (80, 'TCP'): 'HTTP', (110, 'TCP'): 'POP3', (123, 'UDP'): 'NTP',
        (143, 'TCP'): 'IMAP', (161, 'UDP'): 'SNMP', (162, 'UDP'): 'SNMP-Trap',
        (389, 'TCP'): 'LDAP', (443, 'TCP'): 'HTTPS', (445, 'TCP'): 'SMB',
        (465, 'TCP'): 'SMTPS', (514, 'UDP'): 'Syslog', (520, 'UDP'): 'RIP',
        (636, 'TCP'): 'LDAPS', (993, 'TCP'): 'IMAPS', (995, 'TCP'): 'POP3S',
        (1194, 'UDP'): 'OpenVPN', (1433, 'TCP'): 'MSSQL', (1521, 'TCP'): 'Oracle',
        (3306, 'TCP'): 'MySQL', (3389, 'TCP'): 'RDP', (5060, 'UDP'): 'SIP',
        (5060, 'TCP'): 'SIP', (5061, 'TCP'): 'SIPS', (5432, 'TCP'): 'PostgreSQL',
        (5900, 'TCP'): 'VNC', (6379, 'TCP'): 'Redis', (8080, 'TCP'): 'HTTP-Alt',
        (8443, 'TCP'): 'HTTPS-Alt', (27017, 'TCP'): 'MongoDB',
        (4789, 'UDP'): 'VXLAN', (9200, 'TCP'): 'Elasticsearch',
        (1812, 'UDP'): 'RADIUS-Auth', (1813, 'UDP'): 'RADIUS-Acct',
        (3799, 'UDP'): 'RADIUS-CoA',
    }
    app = _MAP.get((dst_port, transport)) or _MAP.get((src_port, transport))
    if not app and transport == 'UDP':
        port = dst_port or src_port
        if 16384 <= port <= 32767:
            app = 'RTP'
    return app or transport


def _validate_tcp_payload(app_proto: str, payload: bytes) -> bool:
    """Validate app-layer payload confirms the detected protocol."""
    if not payload:
        return False
    if app_proto in ('HTTP', 'HTTP-Alt'):
        return any(payload[:10].startswith(s) for s in _HTTP_SIGS)
    if app_proto in ('HTTPS', 'HTTPS-Alt'):
        return len(payload) >= 3 and 0x14 <= payload[0] <= 0x17
    return True   # port-based is reliable for other protocols


# ── TCP Parser ────────────────────────────────────────────────────────────────

class TCPParser(BaseParser):
    """RFC 793 — Transmission Control Protocol."""
    priority = 60

    def can_parse(self, ctx: ParseContext) -> bool:
        return ctx.eth_type == 6 and len(ctx.raw) >= 20

    def parse(self, ctx: ParseContext):
        d    = ctx.raw
        sp   = struct.unpack('!H', d[0:2])[0]
        dp   = struct.unpack('!H', d[2:4])[0]
        seq  = struct.unpack('!I', d[4:8])[0]
        ack  = struct.unpack('!I', d[8:12])[0]
        doff = (d[12] >> 4) * 4
        flagb = d[13]
        win  = struct.unpack('!H', d[14:16])[0]
        ck2  = struct.unpack('!H', d[16:18])[0]
        urg  = struct.unpack('!H', d[18:20])[0]

        svc      = SERVICES.get(dp) or SERVICES.get(sp, '')
        payload  = d[doff:] if doff <= len(d) else b''
        app_proto = _classify_app('TCP', dp, sp)
        if app_proto != 'TCP' and not _validate_tcp_payload(app_proto, payload):
            app_proto = 'TCP'

        fs   = _tcp_flags_str(flagb)
        fn   = ' | '.join(desc for bit, _, desc in TCP_FLAGS_MAP if flagb & bit) or 'none'
        state = _tcp_state_desc(flagb)

        src, dst = ctx.pkt.get('src_ip', '?'), ctx.pkt.get('dst_ip', '?')
        summary = f'{app_proto} {src}:{sp} → {dst}:{dp}  [{fs}]' + (f'  {svc}' if svc else '')

        ctx.pkt.update({
            'proto': app_proto, 'src_port': sp, 'dst_port': dp,
            'tcp_flags': fs, 'tcp_seq': seq, 'tcp_ack': ack,
            'tcp_window': win, 'service': svc, 'tcp_state': state,
            'summary': summary,
        })
        ctx.src_port = sp; ctx.dst_port = dp
        ctx.transport_proto = 'TCP'

        # TCP options parsing (basic — detect SACK, MSS, timestamps)
        opt_notes = []
        if doff > 20 and len(d) >= doff:
            opts = d[20:doff]
            i = 0
            while i < len(opts):
                k = opts[i]
                if k == 0: break
                if k == 1: i += 1; continue
                if i + 1 >= len(opts): break
                l = opts[i + 1]
                if k == 2 and l == 4 and i + 3 < len(opts):
                    mss = struct.unpack('!H', opts[i+2:i+4])[0]
                    opt_notes.append(f'MSS={mss}')
                elif k == 4:
                    opt_notes.append('SACK-Permitted')
                elif k == 8:
                    opt_notes.append('Timestamps')
                i += max(l, 2)

        fields = [
            self._field('Source Port',       f'{sp}',                               f'{"Well-known service" if sp < 1024 else "Ephemeral client port"}'),
            self._field('Destination Port',  f'{dp}' + (f' ({svc})' if svc else ''), f'{"Service" if dp < 1024 else "Ephemeral"} port | {RFC_REF.get(svc, "")}'),
            self._field('Sequence Number',   str(seq),                              'Position in TCP byte stream'),
            self._field('Acknowledgment',    str(ack),                              'Next byte expected from peer'),
            self._field('Data Offset',       f'{doff} bytes',                       'TCP header size (options included)'),
            self._field('Flags',             fs,                                    fn),
            self._field('Connection State',  state,                                 'TCP state machine interpretation'),
            self._field('Window Size',       f'{win} bytes',                       'Receiver buffer available (flow control)'),
            self._field('Checksum',          f'0x{ck2:04x}',                      'TCP segment error detection'),
            self._field('Urgent Pointer',    str(urg),                              'Valid only when URG flag is set'),
            self._field('Service',           svc or 'Unknown',                     RFC_REF.get(svc, '')),
        ]
        if opt_notes:
            fields.append(self._field('TCP Options', ', '.join(opt_notes), 'Negotiated capabilities'))
        if win == 0:
            fields.append(self._field('⚠ Zero Window', 'Receiver buffer full — sender must pause', 'Flow control / backpressure'))

        layer = self._layer('TCP — Transmission Control Protocol  (RFC 793)', '#3b82f6', fields)
        return app_proto, summary, [layer], ctx


# ── UDP Parser ────────────────────────────────────────────────────────────────

class UDPParser(BaseParser):
    """RFC 768 — User Datagram Protocol."""
    priority = 60

    def can_parse(self, ctx: ParseContext) -> bool:
        return ctx.eth_type == 17 and len(ctx.raw) >= 8

    def parse(self, ctx: ParseContext):
        d  = ctx.raw
        sp = struct.unpack('!H', d[0:2])[0]
        dp = struct.unpack('!H', d[2:4])[0]
        udplen = struct.unpack('!H', d[4:6])[0]
        ck2    = struct.unpack('!H', d[6:8])[0]

        svc = SERVICES.get(dp) or SERVICES.get(sp, '')
        app_proto = _classify_app('UDP', dp, sp)

        src, dst = ctx.pkt.get('src_ip', '?'), ctx.pkt.get('dst_ip', '?')
        summary = f'{app_proto} {src}:{sp} → {dst}:{dp}' + (f'  {svc}' if svc else '')

        ctx.pkt.update({
            'proto': app_proto, 'src_port': sp, 'dst_port': dp,
            'service': svc, 'summary': summary,
        })
        ctx.src_port = sp; ctx.dst_port = dp
        ctx.transport_proto = 'UDP'
        ctx.raw = d[8:]   # UDP payload for app parsers

        fields = [
            self._field('Source Port',      f'{sp}',                               f'{"Well-known service" if sp < 1024 else "Client port"}'),
            self._field('Destination Port', f'{dp}' + (f' ({svc})' if svc else ''), f'{"Service" if dp < 1024 else "Client"} port | {RFC_REF.get(svc, "")}'),
            self._field('Length',           f'{udplen} bytes',                      'Header (8B) + payload'),
            self._field('Checksum',         f'0x{ck2:04x}' + (' (disabled)' if ck2 == 0 else ''), 'Optional — 0x0000 means disabled'),
            self._field('Service',          svc or 'Unknown',                       RFC_REF.get(svc, '')),
            self._field('Note',             'Connectionless — no handshake, no retransmit', 'Low overhead, UDP characteristics'),
        ]

        layer = self._layer('UDP — User Datagram Protocol  (RFC 768)', '#10b981', fields)
        return app_proto, summary, [layer], ctx
