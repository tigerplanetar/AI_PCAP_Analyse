"""
parsers/constants.py — Shared Lookup Tables and Utility Helpers
================================================================
Single source of truth for all protocol constants used across individual
parser modules (ethernet.py, vlan.py, arp.py, ipv4.py, tcp.py, udp.py).

Mirrors the constants defined in AI_PCAP_new_Apr27.py so the modular
parsers produce identical field values and colour-coded layers.

No imports from other parsers modules — safe to import from anywhere.
"""

from __future__ import annotations

# ── Layer dict helpers ────────────────────────────────────────────────────────

def _mac(b: bytes) -> str:
    """Format 6-byte sequence as colon-separated hex MAC address."""
    return ':'.join(f'{x:02x}' for x in b)


def _ip4(b: bytes) -> str:
    """Format 4-byte sequence as dotted-decimal IPv4 address."""
    return '.'.join(str(x) for x in b)


def _field(name: str, value, note: str = '') -> dict:
    """Return a field dict compatible with the dashboard layer schema."""
    return {'n': name, 'v': str(value), 'note': note}


def _layer(title: str, color: str, fields: list) -> dict:
    """Return a layer dict compatible with pkt['layers'] schema."""
    return {'title': title, 'color': color, 'fields': fields}


# ── TCP flag helpers ──────────────────────────────────────────────────────────

TCP_FLAGS_MAP = [
    (0x20, 'URG', 'Urgent pointer valid'),
    (0x10, 'ACK', 'Acknowledgment valid'),
    (0x08, 'PSH', 'Push data immediately to application'),
    (0x04, 'RST', 'Abrupt connection reset'),
    (0x02, 'SYN', 'Synchronise sequence numbers — connection start'),
    (0x01, 'FIN', 'Graceful close — no more data from sender'),
]


def _tcp_flags_str(flagb: int) -> str:
    """Return pipe-separated TCP flag abbreviations string, e.g. 'SYN|ACK'."""
    return '|'.join(n for bit, n, _ in TCP_FLAGS_MAP if flagb & bit) or 'NONE'


def _tcp_state_desc(flagb: int) -> str:
    """Return human-readable TCP connection state description."""
    if flagb & 0x02 and not flagb & 0x10:
        return 'SYN — step 1 of 3-way handshake (client → server)'
    if flagb & 0x02 and flagb & 0x10:
        return 'SYN+ACK — step 2 of 3-way handshake (server → client)'
    if flagb & 0x10 and not flagb & 0x02 and not flagb & 0x08:
        return 'ACK — handshake complete or data acknowledgment'
    if flagb & 0x08 and flagb & 0x10:
        return 'PSH+ACK — data transfer (push to application)'
    if flagb & 0x01 and flagb & 0x10:
        return 'FIN+ACK — graceful connection teardown'
    if flagb & 0x04:
        return 'RST — abrupt connection reset (error or rejection)'
    if flagb & 0x10:
        return 'ACK — data acknowledgment'
    return 'Data transfer'


# ── IPv4 / ICMP / IGMP constants ──────────────────────────────────────────────

DSCP_NAMES = {
    0:  'CS0 / Best Effort',      8:  'CS1 (Low Priority)',
    10: 'AF11',                   12: 'AF12',              14: 'AF13',
    16: 'CS2',                    18: 'AF21',              20: 'AF22',
    22: 'AF23',                   24: 'CS3',               26: 'AF31',
    28: 'AF32',                   30: 'AF33',              32: 'CS4',
    34: 'AF41',                   36: 'AF42',              38: 'AF43',
    40: 'CS5',                    46: 'EF (VoIP)',
    48: 'CS6 (Network Control)',  56: 'CS7',
}

IP_FLAGS = {0: 'None', 1: 'MF (More Fragments)', 2: 'DF (Do Not Fragment)', 3: 'MF+DF'}

IP_PROTOS = {
    1: 'ICMP',    2: 'IGMP',   4: 'IP-in-IP', 6: 'TCP',    17: 'UDP',
    41: 'IPv6',  47: 'GRE',   50: 'ESP',      51: 'AH',    58: 'ICMPv6',
    89: 'OSPF', 103: 'PIM',  112: 'VRRP',   132: 'SCTP',
}

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
    (3, 0):  'Network Unreachable',
    (3, 1):  'Host Unreachable',
    (3, 2):  'Protocol Unreachable',
    (3, 3):  'Port Unreachable',
    (3, 4):  'Fragmentation Needed (DF set)',
    (3, 6):  'Destination Network Unknown',
    (3, 7):  'Destination Host Unknown',
    (3, 9):  'Network Administratively Prohibited',
    (3, 10): 'Host Administratively Prohibited',
    (3, 13): 'Communication Administratively Prohibited',
    (5, 0):  'Redirect for Network',
    (5, 1):  'Redirect for Host',
    (5, 2):  'Redirect for TOS & Network',
    (5, 3):  'Redirect for TOS & Host',
    (11, 0): 'TTL Expired in Transit',
    (11, 1): 'Fragment Reassembly Timeout',
}

IGMP_TYPES = {
    0x11: ('Membership Query',     'Router queries group members'),
    0x16: ('v2 Membership Report', 'Host joins group (IGMPv2)'),
    0x17: ('Leave Group',          'Host leaves multicast group'),
    0x22: ('v3 Membership Report', 'Host joins/leaves (IGMPv3)'),
}


# ── TCP / UDP service and RFC tables ──────────────────────────────────────────

SERVICES = {
    20: 'FTP-Data',      21: 'FTP',           22: 'SSH',          23: 'Telnet',
    25: 'SMTP',          53: 'DNS',            67: 'DHCP-Server',  68: 'DHCP-Client',
    69: 'TFTP',          80: 'HTTP',           88: 'Kerberos',    110: 'POP3',
   123: 'NTP',          137: 'NetBIOS-NS',   138: 'NetBIOS-DGM', 139: 'NetBIOS-SSN',
   143: 'IMAP',         161: 'SNMP',          162: 'SNMP-Trap',   179: 'BGP',
   389: 'LDAP',         443: 'HTTPS',         445: 'SMB',         465: 'SMTPS',
   500: 'IKE/IPSec',    514: 'Syslog',        520: 'RIP',         546: 'DHCPv6-Client',
   547: 'DHCPv6-Server',636: 'LDAPS',         993: 'IMAPS',       995: 'POP3S',
  1194: 'OpenVPN',     1433: 'MSSQL',        1521: 'Oracle',     1701: 'L2TP',
  1723: 'PPTP',        1812: 'RADIUS-Auth',  1813: 'RADIUS-Acct',
  3306: 'MySQL',       3389: 'RDP',          3799: 'RADIUS-CoA',
  4500: 'IPSec-NAT',   4789: 'VXLAN',        5060: 'SIP',        5061: 'SIPS',
  5432: 'PostgreSQL',  5900: 'VNC',          6379: 'Redis',      8080: 'HTTP-Alt',
  8443: 'HTTPS-Alt',   9200: 'Elasticsearch',27017: 'MongoDB',
}

RFC_REF = {
    'ARP': 'RFC 826',        'RARP': 'RFC 903',
    'LLDP': 'IEEE 802.1AB',  'EAPoL': 'IEEE 802.1X',
    'STP': 'IEEE 802.1D',    'RSTP': 'IEEE 802.1w',
    'IPv4': 'RFC 791',       'IPv6': 'RFC 8200',
    'ICMP': 'RFC 792',       'ICMPv6': 'RFC 4443',
    'IGMP': 'RFC 3376',      'TCP': 'RFC 793',
    'UDP': 'RFC 768',        'DNS': 'RFC 1035',
    'DHCP': 'RFC 2131',      'DHCP-Server': 'RFC 2131',
    'DHCP-Client': 'RFC 2131','NTP': 'RFC 5905',
    'HTTP': 'RFC 9110',      'HTTPS': 'RFC 9110+TLS',
    'TLS': 'RFC 8446',       'SSH': 'RFC 4253',
    'FTP': 'RFC 959',        'SMTP': 'RFC 5321',
    'POP3': 'RFC 1939',      'IMAP': 'RFC 9051',
    'SNMP': 'RFC 3411',      'LDAP': 'RFC 4511',
    'SIP': 'RFC 3261',       'RTP': 'RFC 3550',
    'Syslog': 'RFC 5424',    'TFTP': 'RFC 1350',
    'SMB': 'MS-SMB2',        'RADIUS-Auth': 'RFC 2865',
    'BGP': 'RFC 4271',       'RIP': 'RFC 2453',
    'OSPF': 'RFC 5340',      'VXLAN': 'RFC 7348',
    'IKE/IPSec': 'RFC 7296', 'Kerberos': 'RFC 4120',
    'VRRP': 'RFC 5798',      'OpenVPN': 'RFC 2408',
}

# Port-based application protocol map: (port, transport) → app name
APP_PROTO_MAP: dict[tuple, str] = {
    (20,  'TCP'): 'FTP-Data',     (21,  'TCP'): 'FTP',
    (22,  'TCP'): 'SSH',          (23,  'TCP'): 'Telnet',
    (25,  'TCP'): 'SMTP',         (53,  'UDP'): 'DNS',
    (53,  'TCP'): 'DNS',          (67,  'UDP'): 'DHCP-Server',
    (68,  'UDP'): 'DHCP-Client',  (69,  'UDP'): 'TFTP',
    (80,  'TCP'): 'HTTP',         (110, 'TCP'): 'POP3',
    (123, 'UDP'): 'NTP',          (137, 'UDP'): 'NBNS',
    (138, 'UDP'): 'NetBIOS-DGM',  (139, 'TCP'): 'NetBIOS-SSN',
    (143, 'TCP'): 'IMAP',         (161, 'UDP'): 'SNMP',
    (162, 'UDP'): 'SNMP-Trap',    (179, 'TCP'): 'BGP',
    (389, 'TCP'): 'LDAP',         (443, 'TCP'): 'HTTPS',
    (445, 'TCP'): 'SMB',          (465, 'TCP'): 'SMTPS',
    (514, 'UDP'): 'Syslog',       (520, 'UDP'): 'RIP',
    (636, 'TCP'): 'LDAPS',        (993, 'TCP'): 'IMAPS',
    (995, 'TCP'): 'POP3S',        (1194,'UDP'): 'OpenVPN',
    (1433,'TCP'): 'MSSQL',        (1521,'TCP'): 'Oracle',
    (3306,'TCP'): 'MySQL',        (3389,'TCP'): 'RDP',
    (5060,'UDP'): 'SIP',          (5060,'TCP'): 'SIP',
    (5061,'TCP'): 'SIPS',         (5432,'TCP'): 'PostgreSQL',
    (5900,'TCP'): 'VNC',          (6379,'TCP'): 'Redis',
    (8080,'TCP'): 'HTTP-Alt',     (8443,'TCP'): 'HTTPS-Alt',
    (27017,'TCP'): 'MongoDB',
}

# HTTP request/response signatures for payload validation
_HTTP_SIGS = (
    b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ',
    b'OPTIONS ', b'PATCH ', b'CONNECT ', b'TRACE ', b'HTTP/',
)


def _classify_app(transport: str, dst_port: int, src_port: int) -> str | None:
    """
    Port-based application protocol classification.

    Returns app protocol name or None if unknown.
    Check destination port first (server side), then source port (responses).
    RTP is detected by the characteristic high-numbered UDP port range (RFC 3550).
    """
    if transport not in ('TCP', 'UDP'):
        return None
    app = APP_PROTO_MAP.get((dst_port, transport)) or APP_PROTO_MAP.get((src_port, transport))
    if app:
        return app
    if transport == 'UDP':
        port = dst_port or src_port
        if port and 16384 <= port <= 32767:
            return 'RTP'
    return None


def _has_app_payload(proto_name: str, tcp_payload: bytes) -> bool:
    """
    Validate that TCP payload actually contains the claimed app-layer protocol.

    Used to avoid misclassifying pure ACKs as HTTP/HTTPS when no payload is
    present.  Returns True if payload confirms the protocol (or if the protocol
    doesn't need payload inspection).
    """
    if not tcp_payload:
        return False
    if proto_name in ('HTTP', 'HTTP-Alt'):
        return any(tcp_payload[:10].startswith(sig) for sig in _HTTP_SIGS)
    if proto_name in ('HTTPS', 'HTTPS-Alt'):
        # TLS record layer: first byte is content type 0x14–0x17
        return len(tcp_payload) >= 3 and 0x14 <= tcp_payload[0] <= 0x17
    return True   # for SSH, FTP, SMTP etc. port classification is reliable


def _detect_snmp(payload: bytes) -> tuple | None:
    """
    Detect SNMP in raw UDP payload via BER/ASN.1 structure inspection.

    Returns (version_str, community, pdu_name, is_trap) or None if not SNMP.
    Mirrors the _detect_snmp() function in AI_PCAP_new_Apr27.py.
    """
    if len(payload) < 10 or payload[0] != 0x30:   # must start with SEQUENCE tag
        return None
    try:
        pos = 1
        # Skip SEQUENCE length (BER short or long form)
        if payload[pos] & 0x80:
            pos += 1 + (payload[pos] & 0x7F)
        else:
            pos += 1
        # Version: INTEGER tag=0x02, length=0x01, value byte
        if payload[pos] != 0x02 or payload[pos + 1] != 0x01:
            return None
        ver = payload[pos + 2]; pos += 3
        # Community string: OCTET STRING tag=0x04
        if payload[pos] != 0x04:
            return None
        clen = payload[pos + 1]; pos += 2
        if pos + clen > len(payload):
            return None
        community = payload[pos:pos + clen].decode('ascii', errors='replace')
        pos += clen
        # PDU context-specific constructed tag (0xa0–0xa7)
        if pos >= len(payload) or not (0xA0 <= payload[pos] <= 0xA7):
            return None
        pdu_tag = payload[pos] - 0xA0
        _PDU_NAMES = {
            0: 'GetRequest',    1: 'GetNextRequest', 2: 'GetResponse',
            3: 'SetRequest',    4: 'Trap-v1',        5: 'GetBulkRequest',
            6: 'InformRequest', 7: 'SNMPv2-Trap',
        }
        pdu_name = _PDU_NAMES.get(pdu_tag, f'PDU-{pdu_tag}')
        ver_name = {0: 'v1', 1: 'v2c', 3: 'v3'}.get(ver, f'v{ver}')
        is_trap  = pdu_tag in (4, 7)
        return (ver_name, community, pdu_name, is_trap)
    except (IndexError, ValueError):
        return None
