#!/usr/bin/env python3
"""
AI PCAP Protocol Analyser — Dashboard v3
Drop-in replacement make_html() for both main_1.py and capmain12_fixed.py.

USAGE (standalone):
  python3 dashboard_v3.py --pcap capture.pcap
  python3 dashboard_v3.py --switch 10.127.11.165

This file is self-contained.  Copy it alongside your existing script and
replace the make_html() call with the one exported here, OR run it directly
(it includes its own minimal HTTP server for testing).

WHAT'S NEW vs capmain12_fixed.py:
  - Complete rewrite of make_html() — no broken JS, no missing CDN deps
  - Inline Chart engine (no chart.js CDN needed — pure Canvas2D)
  - Inline terminal renderer (no xterm.js CDN needed)
  - Fixed: donut chart renders correctly on first load
  - Fixed: packet table rows appear immediately on every view switch
  - Fixed: detail pane resize handle works reliably
  - Fixed: timeline filter buttons highlight correctly
  - Fixed: protocol tabs in Protocols view activate on first click
  - Fixed: ARP pair table shows correct requester/replier columns
  - Fixed: hex dump offsets shown for all packets
  - Clean, modern dark UI with IBM Plex Mono typography
  - Fully standalone — zero external JS dependencies at runtime
"""

import os
import sys
import re
import json
import struct
import time
import math
import hashlib
import base64
import socket
import signal
import tempfile
import platform
import threading
import subprocess
import webbrowser
import argparse
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# ── Platform-specific imports (Unix/macOS only — not available on Windows) ──
IS_WINDOWS = platform.system() == 'Windows'
if not IS_WINDOWS:
    import pty
    import select
    import fcntl
else:
    pty    = None  # type: ignore
    select = None  # type: ignore
    fcntl  = None  # type: ignore

# ── Third-party (pip install paramiko scp) ───────────────────────────────────
# paramiko  — SSH live capture from switches  (required for --protocol ssh)
# scp       — PCAP file transfer over SCP     (required for live capture)
# Both are imported lazily inside the functions that need them so the tool
# still works for offline PCAP analysis without them installed.

# ── Optional AI / semantic search (pip install sentence-transformers numpy) ──
# Imported lazily inside the knowledge-retriever function only when needed.

# ── Re-use constants from the parent project (they'll be available in scope) ──
# If running standalone we define them here.

SERVICES = {
    20:'FTP-Data', 21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP',
    53:'DNS', 67:'DHCP-Server', 68:'DHCP-Client', 69:'TFTP',
    80:'HTTP', 88:'Kerberos', 110:'POP3', 123:'NTP',
    137:'NetBIOS-NS', 138:'NetBIOS-DGM', 139:'NetBIOS-SSN',
    143:'IMAP', 161:'SNMP', 162:'SNMP-Trap', 179:'BGP',
    389:'LDAP', 443:'HTTPS', 445:'SMB', 465:'SMTPS',
    500:'IKE/IPSec', 514:'Syslog', 520:'RIP', 546:'DHCPv6-Client',
    547:'DHCPv6-Server', 636:'LDAPS', 993:'IMAPS', 995:'POP3S',
    1194:'OpenVPN', 1433:'MSSQL', 1521:'Oracle', 1701:'L2TP',
    1723:'PPTP', 1812:'RADIUS-Auth', 1813:'RADIUS-Acct',
    3306:'MySQL', 3389:'RDP', 3799:'RADIUS-CoA',
    4500:'IPSec-NAT', 4789:'VXLAN', 5060:'SIP', 5061:'SIPS',
    5432:'PostgreSQL', 5900:'VNC', 6379:'Redis', 8080:'HTTP-Alt',
    8443:'HTTPS-Alt', 9200:'Elasticsearch', 27017:'MongoDB',
}

RFC_REF = {
    'ARP':'RFC 826', 'RARP':'RFC 903',
    'LLDP':'IEEE 802.1AB', 'EAPoL':'IEEE 802.1X',
    'STP':'IEEE 802.1D', 'RSTP':'IEEE 802.1w',
    'LACP':'IEEE 802.3ad', 'CDP':'Cisco Prop.',
    'IPv4':'RFC 791', 'IPv6':'RFC 8200',
    'ICMP':'RFC 792', 'ICMPv6':'RFC 4443',
    'IGMP':'RFC 3376', 'MLD':'RFC 3810',
    'OSPF':'RFC 5340', 'BGP':'RFC 4271',
    'RIP':'RFC 2453', 'IS-IS':'RFC 1195',
    'EIGRP':'Cisco Prop.',
    'TCP':'RFC 793', 'UDP':'RFC 768',
    'SCTP':'RFC 4960', 'DCCP':'RFC 4340',
    'DNS':'RFC 1035', 'DHCP':'RFC 2131',
    'DHCPv6':'RFC 8415', 'NTP':'RFC 5905',
    'HTTP':'RFC 9110', 'HTTPS':'RFC 9110+TLS',
    'TLS':'RFC 8446', 'SSH':'RFC 4253',
    'FTP':'RFC 959', 'SMTP':'RFC 5321',
    'POP3':'RFC 1939', 'IMAP':'RFC 9051',
    'SNMP':'RFC 3411', 'LDAP':'RFC 4511',
    'SIP':'RFC 3261', 'RTP':'RFC 3550',
    'Syslog':'RFC 5424', 'TFTP':'RFC 1350',
    'NFS':'RFC 7530', 'SMB':'MS-SMB2',
    'RADIUS':'RFC 2865', 'RADIUS-Acct':'RFC 2866',
    'RADIUS-CoA':'RFC 5176', 'Kerberos':'RFC 4120',
    'IPSec':'RFC 4301', 'IKE':'RFC 7296',
    'PIM':'RFC 7761', 'VRRP':'RFC 5798',
    'HSRP':'Cisco Prop.',
}

ICMP_TYPES = {
    0:  ('Echo Reply',              'Host responded to ping — reachable (RFC 792)'),
    3:  ('Destination Unreachable', 'Packet could not reach destination (RFC 792)'),
    5:  ('Redirect',                'Use a better route (RFC 792)'),
    8:  ('Echo Request',            'Ping — testing if host is reachable (RFC 792)'),
    9:  ('Router Advertisement',    'Router announcing its presence (RFC 1256)'),
    10: ('Router Solicitation',     'Host requesting router info (RFC 1256)'),
    11: ('Time Exceeded',           'TTL=0 — used by traceroute (RFC 792)'),
    12: ('Parameter Problem',       'Malformed IP header (RFC 792)'),
}

ICMP_CODES = {
    (3,0):'Network Unreachable',   (3,1):'Host Unreachable',
    (3,2):'Protocol Unreachable',  (3,3):'Port Unreachable',
    (3,4):'Fragmentation Needed',  (11,0):'TTL Expired in Transit',
    (11,1):'Fragment Reassembly Timeout',
}

DSCP_NAMES = {
    0:'CS0/Best Effort', 8:'CS1 (Low Priority)',
    16:'CS2', 24:'CS3', 32:'CS4', 40:'CS5',
    46:'EF (VoIP)', 48:'CS6 (Network Control)', 56:'CS7',
}

IP_FLAGS = {0:'None', 1:'MF (More Fragments)', 2:'DF (Do Not Fragment)', 3:'MF+DF'}

TCP_FLAGS_MAP = [
    (0x20,'URG','Urgent pointer valid'),
    (0x10,'ACK','Acknowledgment valid'),
    (0x08,'PSH','Push data immediately'),
    (0x04,'RST','Reset connection'),
    (0x02,'SYN','Synchronise / connection start'),
    (0x01,'FIN','Graceful close'),
]

KNOWN_ET = {0x0800, 0x0806, 0x8100, 0x86DD, 0x88CC, 0x888E, 0x88E7, 0x88F7, 0x8863, 0x8864,
            0x2000, 0x2004, 0x2003, 0x2005}  # CDP, DTP, PAgP, VTP

PROTO_COLORS = {
    'ARP':'#f59e0b',  'ICMP':'#ef4444', 'TCP':'#3b82f6',   'UDP':'#10b981',
    'LLDP':'#8b5cf6', 'IPv6':'#06b6d4', 'EAPoL':'#f97316', 'IGMP':'#ec4899',
    'RARP':'#fb923c', 'STP':'#84cc16',  'OSPF':'#38bdf8',  'BGP':'#818cf8',
    'EIGRP':'#818cf8','GRE':'#94a3b8',
    'VRRP':'#f472b6', 'PIM':'#34d399',  'SCTP':'#a78bfa',  'DCCP':'#67e8f9',
    'DNS':'#fbbf24',  'DHCP':'#4ade80', 'NTP':'#a3e635',   'SSH':'#60a5fa',
    # Application-layer protocols
    'DHCP-Server':'#22c55e', 'DHCP-Client':'#22c55e', 'TFTP':'#a3e635',
    'NBNS':'#60a5fa',  'NetBIOS-DGM':'#60a5fa', 'NetBIOS-SSN':'#60a5fa',
    'FTP':'#f97316',   'FTP-Data':'#f97316', 'Telnet':'#f59e0b',
    'SMTP':'#fb923c',  'SMTPS':'#fb923c', 'POP3':'#fb923c', 'POP3S':'#fb923c',
    'IMAP':'#fb923c',  'IMAPS':'#fb923c', 'HTTP':'#3b82f6', 'HTTPS':'#3b82f6',
    'HTTP-Alt':'#60a5fa', 'HTTPS-Alt':'#60a5fa',
    'LDAP':'#8b5cf6',  'LDAPS':'#8b5cf6', 'SMB':'#a78bfa',
    'SNMP':'#34d399',  'SNMP-Trap':'#34d399', 'Syslog':'#06b6d4',
    'RIP':'#818cf8',   'OpenVPN':'#f472b6', 'VNC':'#f97316',
    'SIP':'#ec4899',   'SIPS':'#ec4899', 'RTP':'#ec4899',
    'MSSQL':'#a855f7', 'Oracle':'#a855f7', 'MySQL':'#a855f7', 'PostgreSQL':'#a855f7', 'MongoDB':'#a855f7', 'Redis':'#a855f7',
    'RDP':'#14b8a6',   'Kerberos':'#8b5cf6',
    'RADIUS':'#f97316','RADIUS-Acct':'#f97316', 'TACACS+':'#fb923c',
    'BFD':'#22d3ee',   'LDP':'#a3e635',  'NETCONF':'#34d399',
    # IEEE 802.3 / LLC / EDP / IS-IS
    'EDP':'#f59e0b',   'LLC':'#7c3aed', 'IEEE802.3':'#64748b', 'IS-IS':'#f97316',
    # Cisco discovery / L2 protocols
    'CDP':'#0ea5e9',   'DTP':'#38bdf8', 'VTP':'#7dd3fc', 'PAgP':'#bae6fd',
}

_FALLBACK = ['#00e5ff','#7c5cfc','#ff6b6b','#ffd93d','#6bcb77','#4d96ff',
             '#ff9a3c','#c77dff','#48cae4','#f72585','#b5e48c','#90e0ef']

def _proto_color(p):
    if p in PROTO_COLORS: return PROTO_COLORS[p]
    return _FALLBACK[sum(ord(c) for c in p) % len(_FALLBACK)]

OLLAMA_MODEL   = 'llama3.2'
AI_BACKEND     = 'ollama'
CLAUDE_API_KEY = ''
CLAUDE_MODEL   = 'claude-sonnet-4-6'
OPENAI_API_KEY = ''

# ── MCP (Model Context Protocol) — EXOS Switch Server ────────────────────────
MCP_ENABLED    = True
MCP_SERVER_URL = 'http://localhost:8000/sse'  # exos-mcp-server SSE endpoint
MCP_SERVER_NAME = 'exos-mcp-server'

# Keywords that indicate a query should be routed to MCP (EXOS switch queries)
MCP_KEYWORDS = [
    # VLANs
    'vlan', 'vlans',
    # Ports
    'port', 'ports', 'interface', 'interfaces', 'traffic stats', 'down ports',
    # Routing
    'ospf', 'bgp', 'route', 'routes', 'routing', 'ip route', 'vr-default',
    'static route',
    # ACL / Policy
    'acl', 'policy', 'access policy', 'access list', 'policy role',
    # LAG / MLAG
    'lag', 'mlag', 'port channel', 'link aggregation',
    # System
    'firmware', 'save config', 'system health', 'hardware inventory',
    'reboot', 'switch engine', 'exos', 'extremexos',
    # Multi-switch / discovery
    'switches', 'compare', 'available tools', 'list tools',
    # Cisco/Juniper to EXOS translation
    'trunk port', 'port channel', 'ae interface', 'translate',
    # General switch management
    'show', 'disable port', 'enable port', 'configure', 'create vlan',
    'delete vlan', 'peer status',
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _mac(b):   return ':'.join(f'{x:02x}' for x in b)
def _ip4(b):   return '.'.join(str(x) for x in b)
def _step(t):  print(f"\n{'='*60}\n  {t}\n{'='*60}")
def _die(lines):
    print("\n  ERROR:")
    for l in lines: print(f"    {l}")
    sys.exit(1)
def _free_port(start=8765):
    p = start
    while True:
        try:
            s = socket.socket(); s.bind(('', p)); s.close(); return p
        except OSError: p += 1

def _tcp_flags(b):
    return '|'.join(n for bit,n,_ in TCP_FLAGS_MAP if b & bit) or 'NONE'

def _tcp_state(b):
    if   b&0x02 and not b&0x10: return 'SYN: Client initiating (step 1 of 3-way handshake)'
    elif b&0x02 and     b&0x10: return 'SYN+ACK: Server accepting (step 2 of 3-way handshake)'
    elif b&0x10 and not b&0x02 and not b&0x08: return 'ACK: Handshake complete or data ack'
    elif b&0x08 and     b&0x10: return 'PSH+ACK: Data transfer'
    elif b&0x01 and     b&0x10: return 'FIN+ACK: Graceful teardown'
    elif b&0x04:                return 'RST: Abrupt connection reset'
    return 'Data transfer'

# ── PCAP reader ───────────────────────────────────────────────────────────────

def _exos_offset(data):
    VALID_ET   = {0x0800,0x0806,0x86DD,0x88CC,0x888E,0x88E7,0x88F7,0x8847,0x8848}
    VLAN_INNER = VALID_ET | {0x8100}

    def _inner_valid(buf, off):
        """Return True only if there is a plausibly real Ethernet frame at buf[off:]."""
        if len(buf) < off + 14:
            return False
        # Source MAC must not be all-zeros or broadcast (those are invalid as a sender)
        src = buf[off+6:off+12]
        if src == b'\x00\x00\x00\x00\x00\x00' or src == b'\xff\xff\xff\xff\xff\xff':
            return False
        et = struct.unpack('!H', buf[off+12:off+14])[0]
        if et == 0x8100:                             # VLAN-tagged
            if len(buf) < off+18: return False
            return struct.unpack('!H', buf[off+16:off+18])[0] in VALID_ET
        if et == 0x0800:                             # IPv4
            if len(buf) < off+15: return False
            ip0 = buf[off+14]
            return (ip0>>4) == 4 and (ip0&0xF) >= 5
        if et == 0x0806:                             # ARP
            # hardware-type must be 1 (Ethernet) – prevents false positives on random 0x0806 bytes
            if len(buf) < off+16: return False
            return struct.unpack('!H', buf[off+14:off+16])[0] == 1
        if et < 0x0600:                              # IEEE 802.3 length field (LLC payload)
            return et > 0 and len(buf) >= off+17    # at least length>0 and room for LLC header
        return et in VALID_ET

    # ── EXOS debug-capture fast path (EtherType 0xe555) ─────────────────────────
    # The outer Ethernet frame carries EtherType 0xe555 followed by a proprietary
    # extra header of variable length (typically 28–42 bytes observed in the wild).
    # Scan byte-by-byte from offset 28 to find the first valid inner Ethernet frame.
    if len(data) >= 14 and struct.unpack('!H', data[12:14])[0] == 0xe555:
        for inner in range(28, min(100, len(data)-14), 2):
            if _inner_valid(data, inner):
                return inner
        return 14   # strip at minimum the outer 14-byte EXOS Ethernet header

    # ── Standard heuristic scan (non-EXOS PCAPs) ─────────────────────────────────
    for off in [0,4,8,12,16,20,24,28,32,36,40,44,48,52]:
        if len(data) < off+14: break
        et = struct.unpack('!H', data[off+12:off+14])[0]
        if et == 0x8100:
            if len(data) < off+18: continue
            if struct.unpack('!H', data[off+16:off+18])[0] in VLAN_INNER: return off
            continue
        if et == 0x0800:
            if len(data) < off+15: continue
            ip0 = data[off+14]
            if (ip0>>4)&0xF == 4 and (ip0&0xF) >= 5: return off
            continue
        if et == 0x0806:
            # Require ARP hardware-type == 1 (Ethernet) to avoid false positives
            if len(data) < off+16: continue
            if struct.unpack('!H', data[off+14:off+16])[0] == 1: return off
            continue
        if et in VALID_ET: return off
    return 0

def read_pcap(path):
    with open(path, 'rb') as f:
        magic = f.read(4)
        if magic not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
            raise ValueError(f'Not a valid PCAP (magic={magic.hex()})')
        endian = '<' if magic == b'\xd4\xc3\xb2\xa1' else '>'
        f.read(20)
        pkts = []; seen = set()
        while True:
            h = f.read(16)
            if len(h) < 16: break
            ts_s, ts_u, incl, orig = struct.unpack(endian+'IIII', h)
            data = f.read(incl)
            off = _exos_offset(data); seen.add(off)
            if off: data = data[off:]; orig = max(0, orig-off)
            pkts.append({'ts': ts_s+ts_u/1e6, 'data': data, 'orig': orig})
        non_zero = seen - {0}
        if non_zero: print(f'  EXOS headers stripped (offsets: {sorted(non_zero)} bytes)')
    return pkts

# ── Application Layer Protocol Detection ──────────────────────────────────────
# Maps application protocols to their transport details (port-based classification)
APP_PROTO_MAP = {
    # (port, protocol) tuples → app protocol name
    (53, 'UDP'): 'DNS',          # DNS queries
    (53, 'TCP'): 'DNS',          # DNS zone transfers
    (67, 'UDP'): 'DHCP-Server',  # DHCP server
    (68, 'UDP'): 'DHCP-Client',  # DHCP client  
    (69, 'UDP'): 'TFTP',         # Trivial FTP
    (137, 'UDP'): 'NBNS',        # NetBIOS Name Service
    (138, 'UDP'): 'NetBIOS-DGM', # NetBIOS Datagram
    (139, 'TCP'): 'NetBIOS-SSN', # NetBIOS Session
    (20, 'TCP'): 'FTP-Data',     # FTP data
    (21, 'TCP'): 'FTP',          # FTP control
    (22, 'TCP'): 'SSH',          # SSH
    (23, 'TCP'): 'Telnet',       # Telnet
    (25, 'TCP'): 'SMTP',         # SMTP
    (80, 'TCP'): 'HTTP',         # HTTP
    (110, 'TCP'): 'POP3',        # POP3
    (123, 'UDP'): 'NTP',         # NTP
    (143, 'TCP'): 'IMAP',        # IMAP
    (161, 'UDP'): 'SNMP',        # SNMP
    (162, 'UDP'): 'SNMP-Trap',   # SNMP Trap
    (389, 'TCP'): 'LDAP',        # LDAP
    (443, 'TCP'): 'HTTPS',       # HTTPS
    (445, 'TCP'): 'SMB',         # SMB
    (465, 'TCP'): 'SMTPS',       # SMTP over TLS
    (514, 'UDP'): 'Syslog',      # Syslog
    (520, 'UDP'): 'RIP',         # RIP
    (636, 'TCP'): 'LDAPS',       # LDAP over TLS
    (993, 'TCP'): 'IMAPS',       # IMAP over TLS
    (995, 'TCP'): 'POP3S',       # POP3 over TLS
    (1194, 'UDP'): 'OpenVPN',    # OpenVPN
    (1433, 'TCP'): 'MSSQL',      # MS SQL Server
    (1521, 'TCP'): 'Oracle',     # Oracle DB
    (3306, 'TCP'): 'MySQL',      # MySQL
    (3389, 'TCP'): 'RDP',        # Remote Desktop
    (5060, 'UDP'): 'SIP',        # SIP (over UDP)
    (5060, 'TCP'): 'SIP',        # SIP (over TCP)
    (5061, 'TCP'): 'SIPS',       # SIP over TLS
    (5432, 'TCP'): 'PostgreSQL', # PostgreSQL
    (5900, 'TCP'): 'VNC',        # VNC
    (6379, 'TCP'): 'Redis',      # Redis
    (8080, 'TCP'): 'HTTP-Alt',   # HTTP alternate
    (8443, 'TCP'): 'HTTPS-Alt',  # HTTPS alternate
    (27017, 'TCP'): 'MongoDB',   # MongoDB
    # Routing / network protocols
    (179, 'TCP'): 'BGP',         # BGP — Border Gateway Protocol
    (88,  'TCP'): 'Kerberos',    # Kerberos
    (88,  'UDP'): 'Kerberos',    # Kerberos
    (1812, 'UDP'): 'RADIUS',     # RADIUS Authentication
    (1813, 'UDP'): 'RADIUS-Acct',# RADIUS Accounting
    (1645, 'UDP'): 'RADIUS',     # RADIUS (legacy)
    (1646, 'UDP'): 'RADIUS-Acct',# RADIUS Accounting (legacy)
    (3784, 'UDP'): 'BFD',        # Bidirectional Forwarding Detection
    (3785, 'UDP'): 'BFD',        # BFD echo
    (646,  'TCP'): 'LDP',        # MPLS LDP
    (646,  'UDP'): 'LDP',        # MPLS LDP
    (49,   'TCP'): 'TACACS+',    # TACACS+
    (830,  'TCP'): 'NETCONF',    # NETCONF over SSH
}

# Payload-peek signatures for app-layer protocols
_HTTP_SIGS = (b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'OPTIONS ',
              b'PATCH ', b'CONNECT ', b'TRACE ', b'HTTP/')

def _has_app_payload(proto_name, tcp_payload):
    """Check if TCP payload actually contains the claimed app-layer protocol.
    Returns True if payload confirms the protocol, False otherwise."""
    if not tcp_payload or len(tcp_payload) == 0:
        return False  # Pure ACK / no data → stay as TCP
    if proto_name in ('HTTP', 'HTTP-Alt'):
        return any(tcp_payload[:10].startswith(sig) for sig in _HTTP_SIGS)
    if proto_name in ('HTTPS', 'HTTPS-Alt'):
        # TLS record: first byte 0x14-0x17 (ChangeCipherSpec/Alert/Handshake/App)
        return len(tcp_payload) >= 3 and 0x14 <= tcp_payload[0] <= 0x17
    # For other app protos (SSH, FTP, SMTP…) port-based classification is reliable
    return True

def _classify_app_protocol(transport_proto, dst_port, src_port):
    """Classify packet to application layer protocol based on ports and transport layer"""
    if not transport_proto or transport_proto not in ('TCP', 'UDP'):
        return None
    
    # Check destination port first (more common case)
    if dst_port and (dst_port, transport_proto) in APP_PROTO_MAP:
        return APP_PROTO_MAP[(dst_port, transport_proto)]
    
    # Check source port (for responses)
    if src_port and (src_port, transport_proto) in APP_PROTO_MAP:
        return APP_PROTO_MAP[(src_port, transport_proto)]
    
    # Special case for RTP (high-numbered UDP ports, usually 16384-32767)
    if transport_proto == 'UDP' and (dst_port or src_port):
        port = dst_port or src_port
        if 16384 <= port <= 32767:
            return 'RTP'
    
    return None

# ── BGP payload detector ──────────────────────────────────────────────────────

def _detect_bgp(payload):
    """Return True if TCP payload starts with a valid BGP message header:
       16-byte all-0xff marker + 2-byte length (19-4096) + 1-byte type (1-5)."""
    if len(payload) < 19:
        return False
    if payload[0:16] != b'\xff' * 16:
        return False
    msg_len  = struct.unpack('!H', payload[16:18])[0]
    msg_type = payload[18]
    return 19 <= msg_len <= 4096 and 1 <= msg_type <= 5


# ── SNMP ASN.1 payload detector ────────────────────────────────────────────────

def _detect_snmp(payload):
    """Detect SNMP in raw UDP payload via BER/ASN.1 signature.
    Returns (version_str, community, pdu_name, is_trap) or None."""
    if len(payload) < 10 or payload[0] != 0x30:  # Must start with SEQUENCE
        return None
    try:
        pos = 1
        # Skip SEQUENCE length (BER short/long form)
        if payload[pos] & 0x80:
            pos += 1 + (payload[pos] & 0x7f)
        else:
            pos += 1
        # Version: INTEGER tag=0x02, len=0x01, value
        if payload[pos] != 0x02 or payload[pos + 1] != 0x01:
            return None
        ver = payload[pos + 2]; pos += 3
        # Community: OCTET STRING tag=0x04
        if payload[pos] != 0x04:
            return None
        clen = payload[pos + 1]; pos += 2
        if pos + clen > len(payload):
            return None
        community = payload[pos:pos + clen].decode('ascii', errors='replace')
        pos += clen
        # PDU tag (context-specific constructed: 0xa0-0xa7)
        if pos >= len(payload) or not (0xa0 <= payload[pos] <= 0xa7):
            return None
        pdu_tag = payload[pos] - 0xa0
        _PDU = {0: 'GetRequest', 1: 'GetNextRequest', 2: 'GetResponse', 3: 'SetRequest',
                4: 'Trap-v1', 5: 'GetBulkRequest', 6: 'InformRequest', 7: 'SNMPv2-Trap'}
        pdu_name = _PDU.get(pdu_tag, f'PDU-{pdu_tag}')
        ver_name = {0: 'v1', 1: 'v2c', 3: 'v3'}.get(ver, f'v{ver}')
        is_trap = pdu_tag in (4, 7)
        return (ver_name, community, pdu_name, is_trap)
    except (IndexError, ValueError):
        return None

# ── Packet parser ─────────────────────────────────────────────────────────────

def _parse_one(idx, p):
    d = p['data']
    if len(d) < 14: return None
    pkt = {
        'id': idx+1, 'ts': round(p['ts'],6),
        'frame_len': p['orig'], 'proto':'?', 'summary':'',
        'layers':[], 'hex_data': list(d[:256]),
    }
    dst_mac = _mac(d[0:6]); src_mac = _mac(d[6:12])
    pkt['src_mac'] = src_mac; pkt['dst_mac'] = dst_mac
    et = struct.unpack('!H', d[12:14])[0]
    pay = d[14:]
    # ── IEEE 802.3 vs Ethernet II detection ─────────────────────────────────────
    # If the 2-byte field at offset 12 is < 0x0600 (1536), it is a LENGTH (IEEE 802.3),
    # not an EtherType.  Parse LLC and dispatch from there.
    if et < 0x0600:
        frame_len_field = et   # it's really a length value
        pkt['layers'].append({'title':'IEEE 802.3 Ethernet', 'color':'#00d4ff', 'fields':[
            {'n':'Destination MAC', 'v':dst_mac,                   'note':'Layer 2 destination'},
            {'n':'Source MAC',      'v':src_mac,                   'note':'Layer 2 source'},
            {'n':'Length',          'v':f'{frame_len_field} bytes','note':'IEEE 802.3 payload length (not EtherType)'},
            {'n':'Frame Length',    'v':f'{p["orig"]} bytes',      'note':'Total wire frame size'},
        ]})
        # ── LLC (Logical Link Control, IEEE 802.2) ───────────────────────────
        if len(pay) >= 3:
            dsap = pay[0]; ssap = pay[1]; ctrl = pay[2]
            # IEEE 802.2 control field widths:
            #   I-frame  (bit 0 = 0):           2 bytes
            #   S-frame  (bits 1-0 = 01):        2 bytes
            #   U-frame  (bits 1-0 = 11):        1 byte
            ctrl_is_iframe = (ctrl & 0x01) == 0
            ctrl_is_sframe = (ctrl & 0x03) == 0x01
            ctrl_is_uframe = (ctrl & 0x03) == 0x03
            ctrl_width = 1 if ctrl_is_uframe else 2   # S-frames also use 2 bytes
            if ctrl_is_iframe and len(pay) >= 4:
                ctrl_word = struct.unpack('!H', pay[2:4])[0]
                ns = (ctrl_word >> 1) & 0x7F
                nr = (ctrl_word >> 9) & 0x7F
                ctrl_str = f'I-frame  N(S)={ns}  N(R)={nr}  (0x{ctrl_word:04x})'
            elif ctrl_is_sframe and len(pay) >= 4:
                ctrl_word = struct.unpack('!H', pay[2:4])[0]
                nr = (ctrl_word >> 9) & 0x7F
                _SF = {0:'RR (Receive Ready)', 1:'REJ (Reject)', 2:'RNR (Receive Not Ready)', 3:'SREJ (Selective Reject)'}
                sf_type = _SF.get((ctrl >> 2) & 0x03, f'S-func-{(ctrl>>2)&0x03}')
                ctrl_str = f'S-frame  {sf_type}  N(R)={nr}  (0x{ctrl_word:04x})'
            else:
                _UF = {0x00:'UI', 0x43:'DISC', 0x0F:'DM', 0x63:'UA', 0x87:'FRMR', 0x6F:'XID', 0xE3:'TEST'}
                uf_name = _UF.get(ctrl & 0xEF, f'0x{ctrl:02x}')
                ctrl_str = f'U-frame  {uf_name}'
            llc_pay = pay[2+ctrl_width:]
            # SAP name table (masking off Individual/Group & C/R bits)
            _SAP = {0x00:'Null SAP', 0x02:'LLC Sub-Layer Management', 0x04:'SNA Path Control',
                    0x06:'TCP/IP', 0x08:'SNA', 0x0C:'SNA', 0x42:'STP/BPDU',
                    0x4E:'MMS', 0x7E:'X.25 PLP', 0x8E:'NetBEUI', 0x98:'ARP',
                    0xAA:'SNAP', 0xBC:'Banyan Vines', 0xE0:'IPX/SPX',
                    0xF0:'NetBIOS', 0xF4:'LAN Management', 0xFE:'ISO CLNP / IS-IS',
                    0xFF:'Global/NULL DSAP'}
            dsap_name = _SAP.get(dsap & 0xFE, f'SAP 0x{dsap:02x}')
            ssap_name = _SAP.get(ssap & 0xFE, f'SAP 0x{ssap:02x}')
            # Raw data field shown for all LLC payloads (like Wireshark "Data" section)
            _data_hex = llc_pay.hex() if llc_pay else ''
            _data_ascii = ''.join(chr(b) if 32 <= b < 127 else '.' for b in llc_pay)
            pkt['layers'].append({'title':'LLC — Logical Link Control  (IEEE 802.2)', 'color':'#7c3aed', 'fields':[
                {'n':'DSAP',    'v':f'0x{dsap:02x}  ({dsap_name})',  'note':'Destination SAP — Group bit: '+('1=Group' if dsap&1 else '0=Individual')},
                {'n':'SSAP',    'v':f'0x{ssap:02x}  ({ssap_name})',  'note':'Source SAP — Command/Response: '+('Response' if ssap&1 else 'Command')},
                {'n':'Control', 'v':ctrl_str,                         'note':'Frame type and sequence numbers'},
            ]})
            # ── SNAP (Sub-Network Access Protocol) ──────────────────────────
            if (dsap & 0xFE) == 0xAA and (ssap & 0xFE) == 0xAA and len(llc_pay) >= 5:
                oui = llc_pay[0:3]; snap_et = struct.unpack('!H', llc_pay[3:5])[0]
                oui_str = ':'.join(f'{b:02x}' for b in oui)
                _OUI_NAMES = {b'\x00\x00\x0c':'Cisco', b'\x00\xe0\x2b':'Extreme Networks',
                              b'\x00\x00\x00':'RFC 1042 (standard)'}
                oui_name = _OUI_NAMES.get(bytes(oui), oui_str)
                pkt['layers'].append({'title':f'SNAP — Sub-Network Access Protocol  (OUI {oui_name})', 'color':'#0ea5e9', 'fields':[
                    {'n':'OUI',      'v':oui_str,                 'note':oui_name+' organisation'},
                    {'n':'Protocol', 'v':f'0x{snap_et:04x}',     'note':'Protocol encapsulated'},
                ]})
                llc_pay = llc_pay[5:]
                # Dispatch known SNAP-encapsulated protocols
                if oui == b'\x00\x00\x0c' and snap_et == 0x2000:  # Cisco CDP via SNAP
                    _snap_pay = llc_pay
                    cdp_ver2 = _snap_pay[0] if _snap_pay else 0
                    cdp_ttl2 = _snap_pay[1] if len(_snap_pay) > 1 else 0
                    cdp_ck2  = struct.unpack('!H',_snap_pay[2:4])[0] if len(_snap_pay) >= 4 else 0
                    pkt.update({'proto':'CDP',
                                'summary':f'CDP (SNAP) — Cisco Discovery Protocol  src={src_mac}'})
                    pkt['layers'].append({'title':'CDP — Cisco Discovery Protocol  (IEEE 802.3 + SNAP)',
                                          'color':'#0ea5e9','fields':[
                        {'n':'Protocol', 'v':'Cisco Discovery Protocol', 'note':'802.3+SNAP encapsulated CDP'},
                        {'n':'CDP Version','v':f'v{cdp_ver2}',           'note':'CDP protocol version'},
                        {'n':'TTL',       'v':f'{cdp_ttl2} seconds',    'note':'Neighbour info validity'},
                        {'n':'Checksum',  'v':f'0x{cdp_ck2:04x}',      'note':'Error detection'},
                        {'n':'Source MAC','v':src_mac,                   'note':'Originating device'},
                        {'n':'Dest MAC',  'v':dst_mac,                   'note':'Cisco multicast'},
                        {'n':'Note',      'v':'Standard CDP: 802.3 + LLC SNAP + CDP TLVs','note':''},
                    ]})
                    return pkt
                # Treat SNAP-encapsulated protocol as the real EtherType
                et = snap_et
                pay = llc_pay
                # Fall through to standard EtherType dispatch below
            # ── EDP — Extreme Discovery Protocol ────────────────────────────
            # Detection priority order:
            #  1. DSAP=0x44, SSAP=0x78 — EDP well-known LLC SAPs (Extreme Networks)
            #  2. Payload contains "Extreme Discovery Protocol" string
            #  3. LLC payload OUI = 00:e0:2b (Extreme Networks OUI)
            #  Note: also check full pay[] to catch strings spanning LLC header bytes
            elif (frame_len_field == 0x00bb) or \
                 ((dsap & 0xFE) == 0x44 and (ssap & 0xFE) == 0x78) or \
                 b'Extreme Discovery Protocol' in pay[:150] or \
                 b'Extreme Discovery Protocol' in llc_pay[:120] or \
                 (len(llc_pay) >= 5 and llc_pay[0:3] == b'\x00\xe0\x2b'):
                edp_ver = llc_pay[0] if llc_pay else 0
                edp_seq = struct.unpack('!H', llc_pay[2:4])[0] if len(llc_pay) >= 4 else 0
                edp_mid = ':'.join(f'{b:02x}' for b in llc_pay[6:12]) if len(llc_pay) >= 12 else ''
                _edp_payload_str = llc_pay.decode('latin-1', errors='replace')
                _edp_device = ''
                for marker in (b'Extreme Discovery Protocol', b'EDP'):
                    for search_buf in (pay, llc_pay):
                        idx = search_buf.find(marker)
                        if idx >= 0:
                            _edp_device = search_buf[idx:idx+40].decode('latin-1', errors='replace').replace('\x00','').strip()
                            break
                    if _edp_device:
                        break
                pkt.update({'proto':'EDP',
                            'src_mac': src_mac, 'dst_mac': dst_mac,
                            'summary': f'EDP — Extreme Discovery Protocol  src={src_mac}'
                                       + (f'  [{_edp_device[:30]}]' if _edp_device else '')})
                pkt['layers'].append({'title':'EDP — Extreme Discovery Protocol  (Extreme Networks proprietary)',
                                      'color':'#f59e0b', 'fields':[
                    {'n':'Protocol',    'v':'Extreme Discovery Protocol', 'note':'Extreme Networks L2 neighbour discovery'},
                    {'n':'Version',     'v':str(edp_ver),                 'note':'EDP version'},
                    {'n':'Sequence',    'v':str(edp_seq),                 'note':'Packet sequence number'},
                    {'n':'Machine ID',  'v':edp_mid,                     'note':'Sending switch identifier'},
                    {'n':'Source MAC',  'v':src_mac,                     'note':'Originating switch port MAC'},
                    {'n':'Dest MAC',    'v':dst_mac,                     'note':'EDP multicast or unicast'},
                    {'n':'Frame Length','v':f'{p["orig"]} bytes',        'note':'Wire size'},
                    {'n':'Note',        'v':'L2 only — not forwarded by other vendors', 'note':''},
                ]})
                return pkt
            # ── STP/BPDU via LLC SAP 0x42 ────────────────────────────────
            elif (dsap & 0xFE) == 0x42:
                pkt.update({'proto':'STP', 'summary':f'STP BPDU  {src_mac} → {dst_mac}'})
                pkt['layers'].append({'title':'STP — Spanning Tree Protocol BPDU  (IEEE 802.1D)',
                                      'color':'#84cc16', 'fields':[
                    {'n':'DSAP/SSAP', 'v':'0x42',    'note':'SAP for STP/BPDU'},
                    {'n':'Source',    'v':src_mac,   'note':'Sending switch'},
                    {'n':'Dest',      'v':dst_mac,   'note':'01:80:c2:00:00:00 = STP multicast'},
                ]})
                return pkt
            # ── IS-IS — Intermediate System to Intermediate System ───────
            # Detection: ISO CLNP SAP 0xFE, IS-IS multicast MACs, or IS-IS payload
            elif ((dsap & 0xFE) == 0xFE) or \
                 dst_mac.lower() in ('01:80:c2:00:00:14', '01:80:c2:00:00:15',
                                     '09:00:2b:00:00:05', '09:00:2b:00:00:06') or \
                 b'IS_HELLO' in llc_pay or b'IS-IS' in llc_pay[:30] or \
                 (llc_pay and llc_pay[0] in (0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x18,0x19,0x1a,0x1b)):
                _ISIS_PDU = {0x0f:'L1 LAN Hello (IIH)', 0x10:'L2 LAN Hello (IIH)',
                             0x11:'P2P Hello (IIH)',
                             0x12:'L1 Link State PDU (LSP)', 0x13:'L2 LSP',
                             0x14:'L1 CSNP', 0x15:'L2 CSNP',
                             0x18:'L1 PSNP', 0x19:'L2 PSNP', 0x1a:'L1 PSNP', 0x1b:'L2 PSNP'}
                _pdu_type_byte = llc_pay[0] if llc_pay else 0
                _pdu_name = _ISIS_PDU.get(_pdu_type_byte, f'PDU type 0x{_pdu_type_byte:02x}')
                _isis_str = ''
                for _marker in (b'IS_HELLO', b'IS-IS', b'HELLO'):
                    _idx = llc_pay.find(_marker)
                    if _idx >= 0:
                        _isis_str = llc_pay[_idx:_idx+30].decode('latin-1','replace').replace('\x00','').strip()
                        break
                _isis_mac_role = {
                    '01:80:c2:00:00:14': 'IS-IS all Level-1 routers multicast',
                    '01:80:c2:00:00:15': 'IS-IS all Level-2 routers multicast',
                    '09:00:2b:00:00:05': 'IS-IS all Level-1 (legacy)',
                    '09:00:2b:00:00:06': 'IS-IS all Level-2 (legacy)',
                }.get(dst_mac.lower(), dst_mac)
                pkt.update({'proto':'IS-IS',
                            'summary': f'IS-IS {_pdu_name}  src={src_mac} \u2192 {dst_mac}'
                                       + (f'  [{_isis_str[:25]}]' if _isis_str else '')})
                _isis_fields = [
                    {'n':'Protocol',    'v':'IS-IS (Intermediate System to Intermediate System)',
                                         'note':'ISO 10589 / RFC 1195 — link-state routing protocol'},
                    {'n':'DSAP',        'v':f'0x{dsap:02x}',     'note':'0xFE = ISO CLNP / IS-IS SAP'},
                    {'n':'SSAP',        'v':f'0x{ssap:02x}',     'note':'0xFE = ISO CLNP / IS-IS SAP'},
                    {'n':'PDU Type',    'v':_pdu_name,            'note':'IS-IS packet type'},
                    {'n':'Source MAC',  'v':src_mac,              'note':'Originating router interface MAC'},
                    {'n':'Dest MAC',    'v':dst_mac,              'note':_isis_mac_role},
                    {'n':'Frame Length','v':f'{p["orig"]} bytes', 'note':'Wire size'},
                    {'n':'Scope',       'v':'L2 only \u2014 not forwarded beyond the local segment', 'note':''},
                ]
                if _data_hex:
                    _isis_fields.append({'n':f'Data ({len(llc_pay)} bytes)',
                                         'v':_data_hex, 'note':f'ASCII: {_data_ascii}'})
                pkt['layers'].append({'title':f'IS-IS \u2014 {_pdu_name}  (ISO 10589 / RFC 1195)',
                                      'color':'#f97316', 'fields':_isis_fields})
                return pkt
            else:
                # Unknown LLC payload — show data bytes like Wireshark
                _llc_desc = f'LLC DSAP=0x{dsap:02x} SSAP=0x{ssap:02x}'
                pkt.update({'proto':'LLC', 'summary':f'{_llc_desc}  {src_mac} \u2192 {dst_mac}'})
                if llc_pay:
                    pkt['layers'].append({'title':f'Data  ({len(llc_pay)} bytes)', 'color':'#475569', 'fields':[
                        {'n':f'Data ({len(llc_pay)} bytes)', 'v':_data_hex,       'note':f'ASCII: {_data_ascii}'},
                        {'n':'Length',                        'v':str(len(llc_pay)),'note':'LLC payload size'},
                    ]})
            return pkt
        else:
            pkt.update({'proto':'IEEE802.3', 'summary':f'IEEE 802.3 frame  {src_mac} → {dst_mac}'})
            return pkt

    pkt['layers'].append({'title':'Ethernet II  (IEEE 802.3)', 'color':'#00d4ff', 'fields':[
        {'n':'Destination MAC','v':dst_mac,         'note':'Layer 2 destination'},
        {'n':'Source MAC',     'v':src_mac,         'note':'Layer 2 source'},
        {'n':'EtherType',      'v':f'0x{et:04x}',  'note':'Identifies next layer protocol'},
        {'n':'Frame Length',   'v':f'{p["orig"]} bytes','note':'Total wire frame size'},
    ]})
    if et == 0x8100 and len(pay) >= 4:
        tci = struct.unpack('!H', pay[0:2])[0]
        vlan_id = tci & 0xFFF; pcp = (tci >> 13) & 7
        et = struct.unpack('!H', pay[2:4])[0]; pay = pay[4:]
        if et != 0x0800 and (et & 0xFF00)==0x0800 and len(pay)>0 and (et&0xFF)>>4==4:
            pay = bytes([et&0xFF])+pay; et = 0x0800
        pkt['vlan_id'] = vlan_id
        pkt['layers'].append({'title':'VLAN Tag  (IEEE 802.1Q)', 'color':'#a78bfa', 'fields':[
            {'n':'TPID',              'v':'0x8100',                        'note':'Tag Protocol Identifier'},
            {'n':'User Priority(PCP)','v':str(pcp),                        'note':'QoS 0=lowest 7=highest'},
            {'n':'VLAN ID',           'v':f'{vlan_id}  (0x{vlan_id:03x})','note':f'VLAN {vlan_id}'},
            {'n':'Inner EtherType',   'v':f'0x{et:04x}',                  'note':'Protocol inside VLAN tag'},
        ]})
    # PPPoE Session — decapsulate to get inner IPv4/IPv6
    if et == 0x8864 and len(pay) >= 8:
        _pppoe_vt = pay[0]; _pppoe_code = pay[1]
        _pppoe_sid = struct.unpack('!H', pay[2:4])[0]
        _pppoe_len = struct.unpack('!H', pay[4:6])[0]
        _ppp_proto = struct.unpack('!H', pay[6:8])[0]
        pkt['layers'].append({'title':'PPPoE Session  (RFC 2516)', 'color':'#f97316', 'fields':[
            {'n':'Version',        'v':str((_pppoe_vt>>4)&0xf),  'note':'PPPoE version'},
            {'n':'Type',           'v':str(_pppoe_vt&0xf),       'note':'PPPoE type'},
            {'n':'Code',           'v':f'0x{_pppoe_code:02x} ({"Session Data" if _pppoe_code==0 else "Other"})', 'note':'PPPoE code'},
            {'n':'Session ID',     'v':f'0x{_pppoe_sid:04x}',    'note':'PPPoE session identifier'},
            {'n':'Payload Length',  'v':f'{_pppoe_len} bytes',    'note':'PPP payload size'},
        ]})
        _PPP_NAMES = {0x0021:'IPv4',0x0057:'IPv6',0xc021:'LCP',0xc023:'PAP',0xc223:'CHAP',0x8021:'IPCP',0x8057:'IPv6CP'}
        pkt['layers'].append({'title':'PPP \u2014 Point-to-Point Protocol  (RFC 1661)', 'color':'#a78bfa', 'fields':[
            {'n':'Protocol', 'v':f'0x{_ppp_proto:04x} ({_PPP_NAMES.get(_ppp_proto,"Unknown")})',
             'note':'Encapsulated protocol'},
        ]})
        pay = pay[8:]  # skip PPPoE header (6B) + PPP protocol (2B)
        if _ppp_proto == 0x0021:   et = 0x0800   # continue as IPv4
        elif _ppp_proto == 0x0057: et = 0x86DD   # continue as IPv6
        else:                      et = 0        # will fall through to unknown
    # ARP
    if et == 0x0806 and len(pay) >= 28:
        hw = struct.unpack('!H', pay[0:2])[0]; pt = struct.unpack('!H', pay[2:4])[0]
        hln = pay[4]; pln = pay[5]; op = struct.unpack('!H', pay[6:8])[0]
        sha = _mac(pay[8:14]); spa = _ip4(pay[14:18])
        tha = _mac(pay[18:24]); tpa = _ip4(pay[24:28])
        op_str = 'REQUEST' if op==1 else 'REPLY' if op==2 else f'OP{op}'
        meaning = (f'{spa} asks: Who has {tpa}? Tell me your MAC.' if op==1
                   else f'{spa} replies: I have {tpa}. My MAC is {sha}.')
        pkt.update({'proto':'ARP','src_ip':spa,'dst_ip':tpa,'arp_op':op_str,
                    'arp_src_mac':sha,'arp_dst_mac':tha,
                    'summary':f'ARP {op_str}: Who has {tpa}? Tell {spa}' if op==1
                               else f'ARP REPLY: {spa} is at {sha}'})
        pkt['layers'].append({'title':'ARP — Address Resolution Protocol  (RFC 826)', 'color':'#f59e0b', 'fields':[
            {'n':'Hardware Type',          'v':f'0x{hw:04x} ({"Ethernet" if hw==1 else hw})','note':'Layer 2 technology'},
            {'n':'Protocol Type',          'v':f'0x{pt:04x} ({"IPv4" if pt==0x0800 else pt})','note':'Layer 3 protocol being resolved'},
            {'n':'HW Address Length',      'v':f'{hln} bytes','note':'MAC = 6 bytes'},
            {'n':'Protocol Address Length','v':f'{pln} bytes','note':'IPv4 = 4 bytes'},
            {'n':'Operation',              'v':f'{op} ({op_str})','note':'1=REQUEST 2=REPLY'},
            {'n':'Sender MAC',             'v':sha,'note':'MAC of device sending ARP'},
            {'n':'Sender IP',              'v':spa,'note':'IP of device sending ARP'},
            {'n':'Target MAC',             'v':tha,'note':'All zeros in REQUEST = unknown'},
            {'n':'Target IP',              'v':tpa,'note':'IP address being looked up'},
            {'n':'Meaning',                'v':meaning,'note':'Plain English'},
        ]})
    elif et == 0x0800 and len(pay) >= 20:
        ihl   = (pay[0]&0xf)*4; dscp = pay[1]>>2; ecn = pay[1]&3
        tlen  = struct.unpack('!H', pay[2:4])[0]
        ip_id = struct.unpack('!H', pay[4:6])[0]
        fraw  = struct.unpack('!H', pay[6:8])[0]
        flags = (fraw>>13)&7; foff = (fraw&0x1fff)*8
        ttl = pay[8]; proto = pay[9]; cksum = struct.unpack('!H', pay[10:12])[0]
        src_ip = _ip4(pay[12:16]); dst_ip = _ip4(pay[16:20])
        ipp = pay[ihl:]
        pn = {'1':'ICMP','2':'IGMP','6':'TCP','17':'UDP'}.get(str(proto), str(proto))
        pkt.update({'src_ip':src_ip,'dst_ip':dst_ip,'ttl':ttl})
        pkt['layers'].append({'title':'IPv4 — Internet Protocol v4  (RFC 791)', 'color':'#10b981', 'fields':[
            {'n':'Version',        'v':'4',                                       'note':'IPv4'},
            {'n':'Header Length',  'v':f'{ihl} bytes',                           'note':'IHL×4, min 20'},
            {'n':'DSCP / QoS',     'v':f'{dscp} ({DSCP_NAMES.get(dscp,"?")})',   'note':'Quality of Service'},
            {'n':'ECN',            'v':str(ecn),                                  'note':'Explicit Congestion Notification'},
            {'n':'Total Length',   'v':f'{tlen} bytes',                           'note':'IP header + data'},
            {'n':'Identification', 'v':f'0x{ip_id:04x} ({ip_id})',               'note':'Fragment reassembly ID'},
            {'n':'Flags',          'v':IP_FLAGS.get(flags,str(flags)),            'note':'DF/MF fragment flags'},
            {'n':'Fragment Offset','v':f'{foff} bytes',                           'note':'Position in original datagram'},
            {'n':'TTL',            'v':str(ttl),                                  'note':'Hops remaining before discard'},
            {'n':'Protocol',       'v':f'{proto} ({pn})',                         'note':'Upper layer protocol'},
            {'n':'Checksum',       'v':f'0x{cksum:04x}',                         'note':'Error detection'},
            {'n':'Source IP',      'v':src_ip,                                    'note':'Originating device'},
            {'n':'Destination IP', 'v':dst_ip,                                    'note':'Target device'},
        ]})
        if proto == 1 and len(ipp) >= 8:
            t = ipp[0]; c = ipp[1]; ck2 = struct.unpack('!H', ipp[2:4])[0]
            t_name, t_desc = ICMP_TYPES.get(t, (f'Type {t}',''))
            c_desc = ICMP_CODES.get((t,c), f'Code {c}')
            icmp_id  = struct.unpack('!H', ipp[4:6])[0] if t in (0,8) else None
            icmp_seq = struct.unpack('!H', ipp[6:8])[0] if t in (0,8) else None
            fields = [
                {'n':'Type',     'v':f'{t} ({t_name})', 'note':t_desc},
                {'n':'Code',     'v':f'{c} ({c_desc})', 'note':'Sub-type'},
                {'n':'Checksum', 'v':f'0x{ck2:04x}',    'note':'Error detection'},
            ]
            if icmp_id  is not None: fields.append({'n':'Identifier','v':str(icmp_id), 'note':'Match request/reply'})
            if icmp_seq is not None: fields.append({'n':'Sequence',  'v':str(icmp_seq),'note':'Detects loss'})
            fields.append({'n':'Direction','v':f'{src_ip} → {dst_ip}','note':''})
            pkt.update({'proto':'ICMP','icmp_type':t,'icmp_code':c,'icmp_type_str':t_name,
                        'summary':f'ICMP {t_name}  {src_ip} → {dst_ip}  (code={c} ttl={ttl})'})
            pkt['layers'].append({'title':'ICMP — Internet Control Message Protocol  (RFC 792)','color':'#ef4444','fields':fields})
        elif proto == 6 and len(ipp) >= 20:
            sp,dp = struct.unpack('!HH', ipp[0:4])
            seq   = struct.unpack('!I',  ipp[4:8])[0]
            ack   = struct.unpack('!I',  ipp[8:12])[0]
            doff  = (ipp[12]>>4)*4; flagb = ipp[13]
            win   = struct.unpack('!H', ipp[14:16])[0]
            ck2   = struct.unpack('!H', ipp[16:18])[0]
            urg   = struct.unpack('!H', ipp[18:20])[0]
            svc   = SERVICES.get(dp) or SERVICES.get(sp,'')
            _tcp_pay = ipp[doff:] if doff < len(ipp) else b''
            app_proto = _classify_app_protocol('TCP', dp, sp) or 'TCP'
            if app_proto != 'TCP' and not _has_app_payload(app_proto, _tcp_pay):
                app_proto = 'TCP'  # no app-layer content → keep as TCP
            # Auto-detect BGP by payload signature even on non-standard ports
            if app_proto == 'TCP' and _detect_bgp(_tcp_pay):
                app_proto = 'BGP'
            fs    = _tcp_flags(flagb)
            fn    = ' | '.join(desc for bit,name,desc in TCP_FLAGS_MAP if flagb&bit) or 'none'
            pkt.update({'proto':app_proto,'src_port':sp,'dst_port':dp,'tcp_flags':fs,
                        'tcp_seq':seq,'tcp_ack':ack,'tcp_window':win,'service':svc,
                        'tcp_state':_tcp_state(flagb),
                        'summary':f'{app_proto} {src_ip}:{sp} → {dst_ip}:{dp}  [{fs}]{" "+svc if svc else ""}'})
            pkt['layers'].append({'title':'TCP — Transmission Control Protocol  (RFC 793)','color':'#3b82f6','fields':[
                {'n':'Source Port',      'v':str(sp),                              'note':f'{"Service" if sp<1024 else "Ephemeral"} port'},
                {'n':'Destination Port', 'v':f'{dp}{" ("+svc+")" if svc else ""}','note':f'{"Service" if dp<1024 else "Ephemeral"} port'},
                {'n':'Sequence Number',  'v':str(seq),                             'note':'Position in byte stream'},
                {'n':'Acknowledgment',   'v':str(ack),                             'note':'Next byte expected'},
                {'n':'Data Offset',      'v':f'{doff} bytes',                      'note':'TCP header size'},
                {'n':'Flags',            'v':fs,                                   'note':fn},
                {'n':'Connection State', 'v':_tcp_state(flagb),                   'note':'TCP state machine'},
                {'n':'Window Size',      'v':f'{win} bytes',                       'note':'Flow control'},
                {'n':'Checksum',         'v':f'0x{ck2:04x}',                      'note':'Error detection'},
                {'n':'Urgent Pointer',   'v':str(urg),                             'note':'Valid only if URG set'},
                {'n':'Service',          'v':svc or 'Unknown',                     'note':RFC_REF.get(svc,'')},
            ]})
            # ── BGP application-layer parsing ────────────────────────────────
            if app_proto == 'BGP' and len(_tcp_pay) >= 19:
                _BGP_TYPES = {1:'OPEN', 2:'UPDATE', 3:'NOTIFICATION', 4:'KEEPALIVE', 5:'ROUTE-REFRESH'}
                _BGP_ERR   = {1:'Message Header Error', 2:'OPEN Message Error', 3:'UPDATE Message Error',
                              4:'Hold Timer Expired', 5:'Finite State Machine Error', 6:'Cease'}
                _bgp_off = 0
                while _bgp_off + 19 <= len(_tcp_pay):
                    _bgp_hdr = _tcp_pay[_bgp_off:_bgp_off+19]
                    # Marker: 16 bytes of 0xff
                    _bgp_marker = _bgp_hdr[0:16]
                    _bgp_len    = struct.unpack('!H', _bgp_hdr[16:18])[0]
                    _bgp_type   = _bgp_hdr[18]
                    if _bgp_len < 19 or _bgp_off + _bgp_len > len(_tcp_pay) + 1:
                        break  # malformed / partial
                    _bgp_body   = _tcp_pay[_bgp_off+19:_bgp_off+_bgp_len]
                    _type_name  = _BGP_TYPES.get(_bgp_type, f'Type-{_bgp_type}')
                    _bgp_fields = [
                        {'n':'Marker',  'v':_bgp_marker.hex(),     'note':'All-ones = authentic BGP message'},
                        {'n':'Length',  'v':f'{_bgp_len} bytes',   'note':'Total BGP message including header'},
                        {'n':'Type',    'v':f'{_bgp_type} ({_type_name})','note':'BGP message type'},
                    ]
                    if _bgp_type == 1 and len(_bgp_body) >= 10:
                        # OPEN: version(1) my_as(2) hold_time(2) bgp_id(4) opt_len(1)
                        _bgp_ver  = _bgp_body[0]
                        _bgp_as   = struct.unpack('!H', _bgp_body[1:3])[0]
                        _bgp_hold = struct.unpack('!H', _bgp_body[3:5])[0]
                        _bgp_id   = _ip4(_bgp_body[5:9])
                        _bgp_opl  = _bgp_body[9] if len(_bgp_body) > 9 else 0
                        _bgp_fields += [
                            {'n':'Version',              'v':str(_bgp_ver),         'note':'BGP version (4=BGP-4)'},
                            {'n':'My AS',                'v':str(_bgp_as),          'note':'Sender autonomous system number'},
                            {'n':'Hold Time',            'v':f'{_bgp_hold}s',       'note':'Max seconds between messages before session drops'},
                            {'n':'BGP Identifier',       'v':_bgp_id,               'note':'Router ID (usually highest loopback IP)'},
                            {'n':'Optional Params Len',  'v':f'{_bgp_opl} bytes',   'note':'Length of optional capabilities TLVs'},
                        ]
                        # Parse capabilities (opt_params: type=2 cap, type=1 auth)
                        if _bgp_opl > 0 and len(_bgp_body) >= 10 + _bgp_opl:
                            _caps = []; _op = _bgp_body[10:10+_bgp_opl]; _ci = 0
                            _CAP_NAMES = {1:'Multi-Protocol (MP-BGP)', 2:'Route Refresh',
                                          64:'Graceful Restart', 65:'4-byte AS (RFC 6793)',
                                          69:'ADD-PATH', 70:'Enhanced Route Refresh',
                                          128:'Route Refresh (Cisco)', 131:'FQDN'}
                            while _ci + 2 <= len(_op):
                                _ot = _op[_ci]; _ol = _op[_ci+1]
                                if _ot == 2 and _ci + 2 + _ol <= len(_op):  # Capability
                                    _cap_off = _ci + 2; _cap_end = _cap_off + _ol
                                    while _cap_off + 2 <= _cap_end:
                                        _ct = _op[_cap_off]; _cl = _op[_cap_off+1]
                                        _caps.append(_CAP_NAMES.get(_ct, f'Cap-{_ct}'))
                                        _cap_off += 2 + _cl
                                _ci += 2 + _ol
                            if _caps:
                                _bgp_fields.append({'n':'Capabilities', 'v':', '.join(_caps), 'note':'BGP extensions negotiated'})
                        pkt.update({'proto':'BGP', 'summary':f'BGP OPEN  AS={_bgp_as}  ID={_bgp_id}  hold={_bgp_hold}s  {src_ip}:{sp} → {dst_ip}:{dp}'})
                    elif _bgp_type == 2 and len(_bgp_body) >= 4:
                        # UPDATE: unfeasible_len(2) withdrawn + path_attrs + NLRI
                        _unf_len = struct.unpack('!H', _bgp_body[0:2])[0]
                        _attr_len = struct.unpack('!H', _bgp_body[2+_unf_len:4+_unf_len])[0] if len(_bgp_body) >= 4+_unf_len else 0
                        _nlri_start = 4 + _unf_len + _attr_len
                        _nlri_count = 0
                        _ni = _nlri_start
                        while _ni < len(_bgp_body):
                            _prefix_len = _bgp_body[_ni]; _ni += 1
                            _nbytes = (_prefix_len + 7) // 8
                            if _ni + _nbytes > len(_bgp_body): break
                            _ni += _nbytes; _nlri_count += 1
                        _bgp_fields += [
                            {'n':'Withdrawn Routes Len', 'v':f'{_unf_len} bytes',    'note':'Length of withdrawn routes section'},
                            {'n':'Path Attributes Len',  'v':f'{_attr_len} bytes',   'note':'Length of path attributes section'},
                            {'n':'NLRI Prefixes',        'v':str(_nlri_count),       'note':'Number of reachable prefixes advertised'},
                        ]
                        pkt.update({'proto':'BGP', 'summary':f'BGP UPDATE  NLRI={_nlri_count} prefix(es)  {src_ip}:{sp} → {dst_ip}:{dp}'})
                    elif _bgp_type == 3 and len(_bgp_body) >= 2:
                        # NOTIFICATION: error_code(1) error_subcode(1) data
                        _err_code = _bgp_body[0]; _err_sub = _bgp_body[1]
                        _err_name = _BGP_ERR.get(_err_code, f'Error-{_err_code}')
                        _bgp_fields += [
                            {'n':'Error Code',    'v':f'{_err_code} ({_err_name})', 'note':'BGP error category'},
                            {'n':'Error Subcode', 'v':str(_err_sub),                'note':'Specific error within category'},
                        ]
                        pkt.update({'proto':'BGP', 'summary':f'BGP NOTIFICATION  {_err_name}  {src_ip}:{sp} → {dst_ip}:{dp}'})
                    elif _bgp_type == 4:
                        pkt.update({'proto':'BGP', 'summary':f'BGP KEEPALIVE  {src_ip}:{sp} → {dst_ip}:{dp}'})
                    elif _bgp_type == 5:
                        pkt.update({'proto':'BGP', 'summary':f'BGP ROUTE-REFRESH  {src_ip}:{sp} → {dst_ip}:{dp}'})
                    pkt['layers'].append({'title':f'BGP \u2014 Border Gateway Protocol {_type_name}  (RFC 4271)',
                                          'color':'#818cf8', 'fields':_bgp_fields})
                    _bgp_off += _bgp_len
        elif proto == 17 and len(ipp) >= 8:
            sp,dp  = struct.unpack('!HH', ipp[0:4])
            udplen = struct.unpack('!H',  ipp[4:6])[0]
            ck2    = struct.unpack('!H',  ipp[6:8])[0]
            svc    = SERVICES.get(dp) or SERVICES.get(sp,'')
            app_proto = _classify_app_protocol('UDP', dp, sp) or 'UDP'
            pkt.update({'proto':app_proto,'src_port':sp,'dst_port':dp,'service':svc,
                        'summary':f'{app_proto} {src_ip}:{sp} → {dst_ip}:{dp}{" "+svc if svc else ""}'})
            pkt['layers'].append({'title':'UDP — User Datagram Protocol  (RFC 768)','color':'#10b981','fields':[
                {'n':'Source Port',      'v':str(sp),                              'note':f'{"Service" if sp<1024 else "Client"} port'},
                {'n':'Destination Port', 'v':f'{dp}{" ("+svc+")" if svc else ""}','note':f'{"Service" if dp<1024 else "Client"} port'},
                {'n':'Length',           'v':f'{udplen} bytes',                   'note':'Header(8B)+payload'},
                {'n':'Checksum',         'v':f'0x{ck2:04x}',                     'note':'0x0000=disabled'},
                {'n':'Service',          'v':svc or 'Unknown',                    'note':RFC_REF.get(svc,'')},
                {'n':'Note',             'v':'Connectionless — no handshake',     'note':'No retransmit, low overhead'},
            ]})
            # Detect SNMP on non-standard ports via ASN.1 payload inspection
            if app_proto == 'UDP' and len(ipp) > 8:
                _snmp_info = _detect_snmp(ipp[8:])
                if _snmp_info:
                    ver_s, comm_s, pdu_s, is_trap_s = _snmp_info
                    snmp_proto = 'SNMP-Trap' if is_trap_s else 'SNMP'
                    pkt['proto'] = snmp_proto
                    pkt['summary'] = f'{snmp_proto} {ver_s} {pdu_s}  {src_ip}:{sp} → {dst_ip}:{dp}  community="{comm_s}"'
                    pkt['layers'].append({'title':f'SNMP — Simple Network Management Protocol  ({ver_s})','color':'#f97316','fields':[
                        {'n':'Version',   'v':ver_s,  'note':'SNMP version'},
                        {'n':'Community', 'v':comm_s, 'note':'Authentication string (plaintext in v1/v2c)'},
                        {'n':'PDU Type',  'v':pdu_s,  'note':'SNMP operation type'},
                        {'n':'Direction', 'v':f'{src_ip} → {dst_ip}','note':f'Port {sp} → {dp}'},
                    ]})
        elif proto == 2 and len(ipp) >= 8:
            igmp_t = ipp[0]; igmp_rt = ipp[1]; igmp_ck = struct.unpack('!H', ipp[2:4])[0]
            igmp_grp = _ip4(ipp[4:8])
            IGMP_T = {0x11:('Membership Query','Router queries group members'),
                      0x16:('v2 Membership Report','Host joins group (IGMPv2)'),
                      0x17:('Leave Group','Host leaves multicast group'),
                      0x22:('v3 Membership Report','Host joins/leaves (IGMPv3)')}
            t_name,t_desc = IGMP_T.get(igmp_t,(f'Type 0x{igmp_t:02x}','Unknown'))
            pkt.update({'proto':'IGMP','summary':f'IGMP {t_name}  {src_ip} → {dst_ip}  Group={igmp_grp}'})
            pkt['layers'].append({'title':'IGMP — Internet Group Management Protocol  (RFC 3376)','color':'#ec4899','fields':[
                {'n':'Type',          'v':f'0x{igmp_t:02x} ({t_name})','note':t_desc},
                {'n':'Max Resp Time', 'v':f'{igmp_rt/10:.1f}s',        'note':'Max wait before responding'},
                {'n':'Checksum',      'v':f'0x{igmp_ck:04x}',          'note':'Error detection'},
                {'n':'Group Address', 'v':igmp_grp,                     'note':'Multicast group'},
            ]})
        elif proto == 41 and len(ipp) >= 40:
            # IPv6-in-IPv4 (6to4 tunneling, RFC 3056)
            _tc6   = ((ipp[0]&0xf)<<4)|(ipp[1]>>4)
            _flow6 = ((ipp[1]&0xf)<<16)|struct.unpack('!H',ipp[2:4])[0]
            _plen6 = struct.unpack('!H',ipp[4:6])[0]; _nxt6=ipp[6]; _hop6=ipp[7]
            _s6 = ':'.join(f'{struct.unpack("!H",ipp[8+i*2:10+i*2])[0]:04x}' for i in range(8))
            _d6 = ':'.join(f'{struct.unpack("!H",ipp[24+i*2:26+i*2])[0]:04x}' for i in range(8))
            pkt['src_ip'] = _s6; pkt['dst_ip'] = _d6
            pkt['layers'].append({'title':'IPv6-in-IPv4 \u2014 6to4 Tunnel  (RFC 3056)','color':'#06b6d4','fields':[
                {'n':'Tunnel Type',   'v':'6to4 (IPv6 over IPv4, proto 41)', 'note':'RFC 3056 encapsulation'},
                {'n':'Outer Src IPv4','v':src_ip,              'note':'6to4 relay source'},
                {'n':'Outer Dst IPv4','v':dst_ip,              'note':'6to4 relay/anycast (192.88.99.1)'},
                {'n':'Traffic Class', 'v':str(_tc6),           'note':'IPv6 DSCP+ECN'},
                {'n':'Flow Label',    'v':f'0x{_flow6:05x}',  'note':'Identifies same-flow packets'},
                {'n':'Payload Len',   'v':f'{_plen6} bytes',   'note':'Data after IPv6 header'},
                {'n':'Next Header',   'v':f'{_nxt6} ({"TCP" if _nxt6==6 else "UDP" if _nxt6==17 else "ICMPv6" if _nxt6==58 else str(_nxt6)})',
                 'note':'Inner transport protocol'},
                {'n':'Hop Limit',     'v':str(_hop6),          'note':'IPv6 TTL equivalent'},
                {'n':'Source IPv6',   'v':_s6,                 'note':'Inner 6to4 address'},
                {'n':'Dest IPv6',     'v':_d6,                 'note':'Inner IPv6 destination'},
            ]})
            _inner = ipp[40:]
            if _nxt6 == 6 and len(_inner) >= 20:
                sp,dp = struct.unpack('!HH', _inner[0:4])
                seq   = struct.unpack('!I',  _inner[4:8])[0]
                ack   = struct.unpack('!I',  _inner[8:12])[0]
                doff  = (_inner[12]>>4)*4; flagb = _inner[13]
                win   = struct.unpack('!H', _inner[14:16])[0]
                ck2   = struct.unpack('!H', _inner[16:18])[0]
                urg   = struct.unpack('!H', _inner[18:20])[0]
                svc   = SERVICES.get(dp) or SERVICES.get(sp,'')
                _tcp_pay = _inner[doff:] if doff < len(_inner) else b''
                app_proto = _classify_app_protocol('TCP', dp, sp) or 'TCP'
                if app_proto != 'TCP' and not _has_app_payload(app_proto, _tcp_pay):
                    app_proto = 'TCP'  # no app-layer content → keep as TCP
                fs    = _tcp_flags(flagb)
                fn    = ' | '.join(desc for bit,name,desc in TCP_FLAGS_MAP if flagb&bit) or 'none'
                pkt.update({'proto':app_proto,'src_port':sp,'dst_port':dp,'tcp_flags':fs,
                            'tcp_seq':seq,'tcp_ack':ack,'tcp_window':win,'service':svc,
                            'tcp_state':_tcp_state(flagb),
                            'summary':f'{app_proto} [6to4] {_s6}:{sp} \u2192 {_d6}:{dp}  [{fs}]{" "+svc if svc else ""}'})
                pkt['layers'].append({'title':'TCP \u2014 Transmission Control Protocol  (RFC 793)','color':'#3b82f6','fields':[
                    {'n':'Source Port',      'v':str(sp),                              'note':f'{"Service" if sp<1024 else "Ephemeral"} port'},
                    {'n':'Destination Port', 'v':f'{dp}{" ("+svc+")" if svc else ""}','note':f'{"Service" if dp<1024 else "Ephemeral"} port'},
                    {'n':'Sequence Number',  'v':str(seq),                             'note':'Position in byte stream'},
                    {'n':'Acknowledgment',   'v':str(ack),                             'note':'Next byte expected'},
                    {'n':'Data Offset',      'v':f'{doff} bytes',                      'note':'TCP header size'},
                    {'n':'Flags',            'v':fs,                                   'note':fn},
                    {'n':'Connection State', 'v':_tcp_state(flagb),                   'note':'TCP state machine'},
                    {'n':'Window Size',      'v':f'{win} bytes',                       'note':'Flow control'},
                    {'n':'Checksum',         'v':f'0x{ck2:04x}',                      'note':'Error detection'},
                    {'n':'Urgent Pointer',   'v':str(urg),                             'note':'Valid only if URG set'},
                    {'n':'Service',          'v':svc or 'Unknown',                     'note':RFC_REF.get(svc,'')},
                ]})
            elif _nxt6 == 17 and len(_inner) >= 8:
                sp,dp  = struct.unpack('!HH', _inner[0:4])
                udplen = struct.unpack('!H',  _inner[4:6])[0]
                ck2    = struct.unpack('!H',  _inner[6:8])[0]
                svc    = SERVICES.get(dp) or SERVICES.get(sp,'')
                app_proto = _classify_app_protocol('UDP', dp, sp) or 'UDP'
                pkt.update({'proto':app_proto,'src_port':sp,'dst_port':dp,'service':svc,
                            'summary':f'{app_proto} [6to4] {_s6}:{sp} \u2192 {_d6}:{dp}{" "+svc if svc else ""}'})
                pkt['layers'].append({'title':'UDP \u2014 User Datagram Protocol  (RFC 768)','color':'#10b981','fields':[
                    {'n':'Source Port',      'v':str(sp),                              'note':f'{"Service" if sp<1024 else "Client"} port'},
                    {'n':'Destination Port', 'v':f'{dp}{" ("+svc+")" if svc else ""}','note':f'{"Service" if dp<1024 else "Client"} port'},
                    {'n':'Length',           'v':f'{udplen} bytes',                   'note':'Header(8B)+payload'},
                    {'n':'Checksum',         'v':f'0x{ck2:04x}',                     'note':'Error detection'},
                    {'n':'Service',          'v':svc or 'Unknown',                    'note':RFC_REF.get(svc,'')},
                ]})
            else:
                pkt.update({'proto':'IPv6','summary':f'IPv6 [6to4] {_s6} \u2192 {_d6} next={_nxt6}'})
        elif proto == 88:  # EIGRP — Enhanced Interior Gateway Routing Protocol
            _EIGRP_OP = {1:'Update', 3:'Query', 4:'Reply', 5:'Hello', 6:'Probe', 10:'SIA-Query', 11:'SIA-Reply'}
            eigrp_ver = ipp[0] if ipp else 0
            eigrp_op  = ipp[1] if len(ipp) > 1 else 0
            eigrp_ck  = struct.unpack('!H', ipp[2:4])[0] if len(ipp) >= 4 else 0
            eigrp_flags = struct.unpack('!I', ipp[4:8])[0] if len(ipp) >= 8 else 0
            eigrp_seq   = struct.unpack('!I', ipp[8:12])[0] if len(ipp) >= 12 else 0
            eigrp_ack   = struct.unpack('!I', ipp[12:16])[0] if len(ipp) >= 16 else 0
            eigrp_as    = struct.unpack('!I', ipp[16:20])[0] if len(ipp) >= 20 else 0
            # Some implementations put VR ID in bits 16-17 and AS in bits 18-19
            eigrp_vrid  = struct.unpack('!H', ipp[16:18])[0] if len(ipp) >= 18 else 0
            eigrp_as2   = struct.unpack('!H', ipp[18:20])[0] if len(ipp) >= 20 else eigrp_as
            op_name = _EIGRP_OP.get(eigrp_op, f'Opcode-{eigrp_op}')
            # Try to get payload string (for synthetic/test packets)
            _eigrp_str = ipp[20:].decode('latin-1','replace').replace('\x00','').strip() if len(ipp) > 20 else ''
            pkt.update({'proto':'EIGRP', 'src_ip':src_ip, 'dst_ip':dst_ip,
                        'summary': f'EIGRP {op_name}  {src_ip} \u2192 {dst_ip}  AS={eigrp_as2}  TTL={ttl}'
                                   + (f'  [{_eigrp_str[:20]}]' if _eigrp_str else '')})
            pkt['layers'].append({'title':'EIGRP \u2014 Enhanced Interior Gateway Routing Protocol  (Cisco/RFC 7868)',
                                  'color':'#818cf8', 'fields':[
                {'n':'Version',      'v':str(eigrp_ver),             'note':'EIGRP version (typically 2)'},
                {'n':'Opcode',       'v':f'{eigrp_op} ({op_name})',  'note':'EIGRP message type'},
                {'n':'Checksum',     'v':f'0x{eigrp_ck:04x}',       'note':'Error detection'},
                {'n':'Flags',        'v':f'0x{eigrp_flags:08x}',    'note':'Init/CR/RS/EOT flags'},
                {'n':'Sequence',     'v':str(eigrp_seq),             'note':'Reliable transport sequence number'},
                {'n':'ACK Number',   'v':str(eigrp_ack),             'note':'Reliable transport acknowledgment'},
                {'n':'Virtual RID',  'v':str(eigrp_vrid),            'note':'Virtual Router ID (0=unicast)'},
                {'n':'AS Number',    'v':str(eigrp_as2),             'note':'Autonomous System number'},
                {'n':'Source IP',    'v':src_ip,                     'note':'Routing speaker'},
                {'n':'Dest IP',      'v':dst_ip,                     'note':'224.0.0.10 = EIGRP all-routers multicast'},
                {'n':'TTL',          'v':str(ttl),                   'note':'Should be 1 for EIGRP hellos (link-local)'},
                {'n':'Protocol',     'v':'IP protocol 88',           'note':'Cisco proprietary, standardised in RFC 7868'},
            ]})
        elif proto == 89:  # OSPF — Open Shortest Path First
            _OSPF_TYPE = {1:'Hello', 2:'DBD', 3:'LSR', 4:'LSU', 5:'LSAck'}
            ospf_ver  = ipp[0] if ipp else 0
            ospf_type = ipp[1] if len(ipp) > 1 else 0
            ospf_len  = struct.unpack('!H', ipp[2:4])[0] if len(ipp) >= 4 else 0
            ospf_rid  = _ip4(ipp[4:8]) if len(ipp) >= 8 else ''
            ospf_area = _ip4(ipp[8:12]) if len(ipp) >= 12 else ''
            ospf_ck   = struct.unpack('!H', ipp[12:14])[0] if len(ipp) >= 14 else 0
            type_name = _OSPF_TYPE.get(ospf_type, f'Type-{ospf_type}')
            pkt.update({'proto':'OSPF', 'src_ip':src_ip, 'dst_ip':dst_ip,
                        'summary': f'OSPF {type_name}  RouterID={ospf_rid}  Area={ospf_area}  {src_ip} \u2192 {dst_ip}'})
            pkt['layers'].append({'title':'OSPF \u2014 Open Shortest Path First  (RFC 5340)',
                                  'color':'#38bdf8', 'fields':[
                {'n':'Version',    'v':str(ospf_ver),              'note':'OSPF version (2=OSPFv2, 3=OSPFv3)'},
                {'n':'Type',       'v':f'{ospf_type} ({type_name})','note':'OSPF packet type'},
                {'n':'Length',     'v':f'{ospf_len} bytes',        'note':'OSPF packet length'},
                {'n':'Router ID',  'v':ospf_rid,                   'note':'Unique router identifier'},
                {'n':'Area ID',    'v':ospf_area,                  'note':'OSPF area (0.0.0.0 = backbone)'},
                {'n':'Checksum',   'v':f'0x{ospf_ck:04x}',        'note':'Error detection'},
                {'n':'Source IP',  'v':src_ip,                     'note':'Sending router'},
                {'n':'Dest IP',    'v':dst_ip,                     'note':'224.0.0.5/6 = OSPF multicast'},
                {'n':'Protocol',   'v':'IP protocol 89',           'note':'RFC 5340'},
            ]})
        elif proto == 112:  # VRRP — Virtual Router Redundancy Protocol
            _VRRP_TYPE = {1:'Advertisement'}
            vrrp_ver_type = ipp[0] if ipp else 0
            vrrp_ver  = (vrrp_ver_type >> 4) & 0xF
            vrrp_type = vrrp_ver_type & 0xF
            vrrp_vrid = ipp[1] if len(ipp) > 1 else 0
            vrrp_pri  = ipp[2] if len(ipp) > 2 else 0
            vrrp_cnt  = ipp[3] if len(ipp) > 3 else 0
            vrrp_int  = struct.unpack('!H', ipp[4:6])[0] if len(ipp) >= 6 else 0
            vrrp_ck   = struct.unpack('!H', ipp[6:8])[0] if len(ipp) >= 8 else 0
            type_name = _VRRP_TYPE.get(vrrp_type, f'Type-{vrrp_type}')
            pkt.update({'proto':'VRRP', 'src_ip':src_ip, 'dst_ip':dst_ip,
                        'summary': f'VRRP v{vrrp_ver} {type_name}  VRID={vrrp_vrid}  pri={vrrp_pri}  {src_ip} \u2192 {dst_ip}'})
            pkt['layers'].append({'title':f'VRRP \u2014 Virtual Router Redundancy Protocol v{vrrp_ver}  (RFC 5798)',
                                  'color':'#f472b6', 'fields':[
                {'n':'Version',       'v':str(vrrp_ver),              'note':'VRRP version'},
                {'n':'Type',          'v':f'{vrrp_type} ({type_name})','note':'Message type'},
                {'n':'Virtual RID',   'v':str(vrrp_vrid),             'note':'Virtual router identifier (1-255)'},
                {'n':'Priority',      'v':str(vrrp_pri),              'note':'255=owner, 100=default, 0=resign'},
                {'n':'IP Count',      'v':str(vrrp_cnt),              'note':'Number of VIPs advertised'},
                {'n':'Adv Interval',  'v':f'{vrrp_int/100:.2f}s' if vrrp_ver==3 else f'{vrrp_int}s','note':'Advertisement interval'},
                {'n':'Checksum',      'v':f'0x{vrrp_ck:04x}',        'note':'Error detection'},
                {'n':'Source IP',     'v':src_ip,                     'note':'Active/backup router'},
                {'n':'Dest IP',       'v':dst_ip,                     'note':'224.0.0.18 = VRRP multicast'},
            ]})
        elif proto == 103:  # PIM — Protocol Independent Multicast
            _PIM_TYPE = {0:'Hello', 1:'Register', 2:'Register-Stop', 3:'Join/Prune',
                         4:'Bootstrap', 5:'Assert', 6:'Graft', 7:'Graft-Ack', 8:'C-RP-Adv'}
            pim_vt    = ipp[0] if ipp else 0
            pim_ver   = (pim_vt >> 4) & 0xF
            pim_type  = pim_vt & 0xF
            pim_ck    = struct.unpack('!H', ipp[2:4])[0] if len(ipp) >= 4 else 0
            type_name = _PIM_TYPE.get(pim_type, f'Type-{pim_type}')
            pkt.update({'proto':'PIM', 'src_ip':src_ip, 'dst_ip':dst_ip,
                        'summary': f'PIM v{pim_ver} {type_name}  {src_ip} \u2192 {dst_ip}'})
            pkt['layers'].append({'title':f'PIM \u2014 Protocol Independent Multicast  (RFC 7761)',
                                  'color':'#34d399', 'fields':[
                {'n':'Version',    'v':str(pim_ver),              'note':'PIM version (2=PIMv2)'},
                {'n':'Type',       'v':f'{pim_type} ({type_name})','note':'PIM message type'},
                {'n':'Checksum',   'v':f'0x{pim_ck:04x}',        'note':'Error detection'},
                {'n':'Source IP',  'v':src_ip,                    'note':'Sending router'},
                {'n':'Dest IP',    'v':dst_ip,                    'note':'224.0.0.13 = PIM all-routers multicast'},
                {'n':'Protocol',   'v':'IP protocol 103',         'note':'RFC 7761'},
            ]})
        elif proto == 47:  # GRE — Generic Routing Encapsulation
            gre_flags = struct.unpack('!H', ipp[0:2])[0] if len(ipp) >= 2 else 0
            gre_proto = struct.unpack('!H', ipp[2:4])[0] if len(ipp) >= 4 else 0
            _GRE_INNER = {0x0800:'IPv4', 0x86DD:'IPv6', 0x0806:'ARP', 0x8100:'VLAN'}
            inner_name = _GRE_INNER.get(gre_proto, f'0x{gre_proto:04x}')
            pkt.update({'proto':'GRE', 'src_ip':src_ip, 'dst_ip':dst_ip,
                        'summary': f'GRE tunnel  {src_ip} \u2192 {dst_ip}  inner={inner_name}'})
            pkt['layers'].append({'title':'GRE \u2014 Generic Routing Encapsulation  (RFC 2784)',
                                  'color':'#94a3b8', 'fields':[
                {'n':'Flags',       'v':f'0x{gre_flags:04x}',   'note':'Checksum/key/seq present flags'},
                {'n':'Inner Proto', 'v':inner_name,              'note':'Encapsulated protocol EtherType'},
                {'n':'Source IP',   'v':src_ip,                  'note':'Tunnel endpoint (local)'},
                {'n':'Dest IP',     'v':dst_ip,                  'note':'Tunnel endpoint (remote)'},
                {'n':'Protocol',    'v':'IP protocol 47',        'note':'RFC 2784'},
            ]})
        else:
            pkt.update({'proto':f'IPv4-p{proto}','summary':f'IPv4 proto={proto} {src_ip}\u2192{dst_ip}'})
    elif et == 0x86DD and len(pay) >= 40:
        tc   = ((pay[0]&0xf)<<4)|(pay[1]>>4)
        flow = ((pay[1]&0xf)<<16)|struct.unpack('!H',pay[2:4])[0]
        plen = struct.unpack('!H',pay[4:6])[0]; nxt=pay[6]; hop=pay[7]
        s6 = ':'.join(f'{struct.unpack("!H",pay[8+i*2:10+i*2])[0]:04x}' for i in range(8))
        d6 = ':'.join(f'{struct.unpack("!H",pay[24+i*2:26+i*2])[0]:04x}' for i in range(8))
        pkt.update({'proto':'IPv6','src_ip':s6,'dst_ip':d6,'summary':f'IPv6 {s6[:16]}… → {d6[:16]}…'})
        pkt['layers'].append({'title':'IPv6 — Internet Protocol v6  (RFC 8200)','color':'#06b6d4','fields':[
            {'n':'Traffic Class', 'v':str(tc),         'note':'DSCP+ECN for IPv6'},
            {'n':'Flow Label',    'v':f'0x{flow:05x}', 'note':'Identifies same-flow packets'},
            {'n':'Payload Len',   'v':f'{plen} bytes', 'note':'Data after IPv6 header'},
            {'n':'Next Header',   'v':str(nxt),        'note':f'{"TCP" if nxt==6 else "UDP" if nxt==17 else "ICMPv6" if nxt==58 else str(nxt)}'},
            {'n':'Hop Limit',     'v':str(hop),        'note':'IPv4 TTL equivalent'},
            {'n':'Source IPv6',   'v':s6,              'note':'128-bit source'},
            {'n':'Dest IPv6',     'v':d6,              'note':'128-bit destination'},
        ]})
    elif et == 0x888E and len(pay) >= 4:
        ver=pay[0]; ptype=pay[1]
        pt_str={0:'EAP-Packet',1:'EAPOL-Start',2:'EAPOL-Logoff',3:'EAPOL-Key'}.get(ptype,f'Type-{ptype}')
        pkt.update({'proto':'EAPoL','summary':f'EAPoL 802.1X {pt_str} v{ver}'})
        pkt['layers'].append({'title':'EAPoL — 802.1X Port Authentication  (IEEE 802.1X)','color':'#f97316','fields':[
            {'n':'Version',    'v':str(ver), 'note':'EAPoL version'},
            {'n':'Packet Type','v':pt_str,   'note':'EAP message type'},
            {'n':'Purpose',    'v':'Port-based NAC — device must auth before port opens','note':''},
        ]})
    elif et == 0x88CC:
        pkt.update({'proto':'LLDP','summary':'LLDP — Link Layer Discovery'})
        pkt['layers'].append({'title':'LLDP — Link Layer Discovery Protocol  (IEEE 802.1AB)','color':'#8b5cf6','fields':[
            {'n':'Destination','v':dst_mac,                      'note':'01:80:c2:00:00:0e = LLDP multicast'},
            {'n':'Source',     'v':src_mac,                      'note':'MAC of advertising device'},
            {'n':'Purpose',    'v':'Device and topology discovery','note':'Advertises system name, port, capabilities'},
            {'n':'Scope',      'v':'Local segment only',         'note':'Not forwarded by switches'},
        ]})
    elif et in (0x2000, 0x2004, 0x2003, 0x2005):
        # CDP=0x2000, PAgP=0x2004, DTP=0x2003, VTP=0x2005 — Cisco L2 discovery/control protocols
        # Also recognise by destination MAC 01:00:0c:cc:cc:cc (Cisco multicast)
        _CISCO_ET = {0x2000:'CDP', 0x2004:'PAgP', 0x2003:'DTP', 0x2005:'VTP'}
        _cisco_proto = _CISCO_ET.get(et, f'Cisco-0x{et:04x}')
        _CISCO_NAMES = {'CDP':'Cisco Discovery Protocol', 'PAgP':'Port Aggregation Protocol',
                        'DTP':'Dynamic Trunking Protocol', 'VTP':'VLAN Trunking Protocol'}
        _cisco_full = _CISCO_NAMES.get(_cisco_proto, _cisco_proto)
        # Parse CDP TLVs if EtherType == 0x2000
        cdp_ver=0; cdp_ttl=0; cdp_cksum=0; cdp_device=''; cdp_port=''; cdp_platform=''
        if et == 0x2000 and len(pay) >= 4:
            cdp_ver   = pay[0]; cdp_ttl   = pay[1]
            cdp_cksum = struct.unpack('!H', pay[2:4])[0]
            tlv_off = 4
            while tlv_off + 4 <= len(pay):
                tlv_t = struct.unpack('!H', pay[tlv_off:tlv_off+2])[0]
                tlv_l = struct.unpack('!H', pay[tlv_off+2:tlv_off+4])[0]
                if tlv_l < 4: break
                tlv_v = pay[tlv_off+4:tlv_off+tlv_l]
                if tlv_t == 0x0001: cdp_device   = tlv_v.decode('ascii','replace')
                elif tlv_t == 0x0003: cdp_port   = tlv_v.decode('ascii','replace')
                elif tlv_t == 0x0006: cdp_platform = tlv_v.decode('ascii','replace')
                tlv_off += max(tlv_l, 4)
            # Fallback: extract printable string from raw payload
            if not cdp_device:
                _raw = pay.decode('latin-1','replace')
                if 'Cisco' in _raw or 'cdp' in _raw.lower():
                    cdp_device = _raw.replace('\x00','').strip()[:50]
        pkt.update({'proto': _cisco_proto,
                    'summary': f'{_cisco_proto} — {_cisco_full}  src={src_mac}'
                               + (f'  device={cdp_device[:30]}' if cdp_device else '')
                               + (f'  port={cdp_port}'         if cdp_port   else '')})
        _cdp_fields = [
            {'n':'Protocol',    'v':_cisco_full,               'note':f'Cisco proprietary L2 {_cisco_proto}'},
            {'n':'EtherType',   'v':f'0x{et:04x}',            'note':f'Identifies {_cisco_proto} frames'},
            {'n':'Dest MAC',    'v':dst_mac,                   'note':'01:00:0c:cc:cc:cc = Cisco L2 multicast'},
            {'n':'Source MAC',  'v':src_mac,                   'note':'Originating switch/router port'},
        ]
        if et == 0x2000:
            _cdp_fields += [
                {'n':'CDP Version', 'v':f'v{cdp_ver}',           'note':'CDP protocol version'},
                {'n':'TTL',         'v':f'{cdp_ttl} seconds',    'note':'Neighbour info validity window'},
                {'n':'Checksum',    'v':f'0x{cdp_cksum:04x}',   'note':'Error detection'},
                {'n':'Device ID',   'v':cdp_device or '(none)', 'note':'Sending device hostname'},
                {'n':'Port ID',     'v':cdp_port   or '(none)', 'note':'Sending interface name'},
                {'n':'Platform',    'v':cdp_platform or '(none)','note':'Hardware platform model'},
            ]
        _cdp_fields.append({'n':'Note','v':'L2 only — not forwarded beyond local segment','note':''})
        pkt['layers'].append({'title':f'{_cisco_proto} — {_cisco_full}  (Cisco proprietary)',
                              'color':'#0ea5e9', 'fields':_cdp_fields})
    else:
        # Check if Cisco multicast MAC but unknown Cisco EtherType
        _is_cisco_mc = dst_mac.lower().startswith('01:00:0c')
        if _is_cisco_mc:
            pkt.update({'proto':'CDP', 'summary':f'Cisco L2 (0x{et:04x})  src={src_mac} → {dst_mac}'})
            pkt['layers'].append({'title':f'Cisco Proprietary  (EtherType 0x{et:04x})','color':'#0ea5e9','fields':[
                {'n':'EtherType', 'v':f'0x{et:04x}', 'note':'Cisco-assigned L2 protocol'},
                {'n':'Dest MAC',  'v':dst_mac,        'note':'Cisco multicast — CDP/VTP/DTP family'},
                {'n':'Src MAC',   'v':src_mac,        'note':''},
            ]})
        else:
            et_label = f'ET-0x{et:04x}'
            pkt.update({'proto':et_label,'summary':f'Unknown EtherType 0x{et:04x}'})
            pkt['layers'].append({'title':f'Unknown / Proprietary  (EtherType 0x{et:04x})','color':'#475569','fields':[
                {'n':'EtherType','v':f'0x{et:04x}','note':'Unrecognised protocol'},
                {'n':'Src MAC',  'v':src_mac,       'note':''},
                {'n':'Dst MAC',  'v':dst_mac,       'note':''},
            ]})
    return pkt

def parse_all(raw):
    return [p for i,r in enumerate(raw) for p in [_parse_one(i,r)] if p]

# ── tshark enrichment ─────────────────────────────────────────────────────────

def _find_tshark():
    """Auto-detect tshark binary path across platforms."""
    import shutil
    candidates = [
        shutil.which('tshark'),
        r'C:\Program Files\Wireshark\tshark.exe',
        r'C:\Program Files (x86)\Wireshark\tshark.exe',
        '/usr/bin/tshark',
        '/usr/local/bin/tshark',
        '/opt/homebrew/bin/tshark',
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None

def _run_tshark(pcap_path):
    """Run tshark -T json on a PCAP and return dict keyed by frame number."""
    tshark = _find_tshark()
    if not tshark:
        return {}
    try:
        import subprocess
        result = subprocess.run(
            [tshark, '-r', pcap_path, '-T', 'json', '-e', 'frame.number',
             '-e', 'frame.protocols', '-e', '_ws.col.Info',
             '-e', 'ip.src', '-e', 'ip.dst',
             '-e', 'bootp.option.dhcp', '-e', 'dns.qry.name', '-e', 'dns.flags.response',
             '-e', 'snmp.community', '-e', 'snmp.pdu_type',
             '-e', 'snmp.trap.enterprise', '-e', 'snmp.trap.genericTrap',
             '-e', 'snmp.trap.specificTrap', '-e', 'snmp.version',
             '-e', 'snmp.name', '-e', 'snmp.value.string'],
            # snmp.name + snmp.value.string extract varbind OID names + values
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            return {}
        import json as _j
        raw_json = _j.loads(result.stdout)
        out = {}
        for pkt in raw_json:
            src = pkt.get('_source', {}).get('layers', {})
            fnum_list = src.get('frame.number', ['0'])
            fnum = int(fnum_list[0]) if fnum_list else 0
            protocols = src.get('frame.protocols', [''])[0] if src.get('frame.protocols') else ''
            info = src.get('_ws.col.Info', [''])[0] if src.get('_ws.col.Info') else ''
            dhcp_type = src.get('bootp.option.dhcp', [''])[0] if src.get('bootp.option.dhcp') else ''
            dns_name = src.get('dns.qry.name', [''])[0] if src.get('dns.qry.name') else ''
            dns_resp       = src.get('dns.flags.response', [''])[0] if src.get('dns.flags.response') else ''
            snmp_community = src.get('snmp.community', [''])[0] if src.get('snmp.community') else ''
            snmp_pdu_type  = src.get('snmp.pdu_type',  [''])[0] if src.get('snmp.pdu_type')  else ''
            snmp_enterprise= src.get('snmp.trap.enterprise', [''])[0] if src.get('snmp.trap.enterprise') else ''
            snmp_generic   = src.get('snmp.trap.genericTrap', [''])[0] if src.get('snmp.trap.genericTrap') else ''
            snmp_specific  = src.get('snmp.trap.specificTrap', [''])[0] if src.get('snmp.trap.specificTrap') else ''
            snmp_version   = src.get('snmp.version', [''])[0] if src.get('snmp.version') else ''
            # varbind names + values come as parallel lists from tshark
            snmp_vb_names  = src.get('snmp.name', [])          # list of OID names
            snmp_vb_values = src.get('snmp.value.string', [])   # list of string values
            snmp_varbinds  = list(zip(snmp_vb_names, snmp_vb_values)) if snmp_vb_names else []
            out[fnum] = {
                'protocols':      protocols,
                'info':           info,
                'dhcp_type':      dhcp_type,
                'dns_name':       dns_name,
                'dns_resp':       dns_resp,
                'snmp_community': snmp_community,
                'snmp_pdu_type':  snmp_pdu_type,
                'snmp_enterprise':snmp_enterprise,
                'snmp_generic':   snmp_generic,
                'snmp_specific':  snmp_specific,
                'snmp_version':   snmp_version,
                'snmp_varbinds':  snmp_varbinds,
            }
        return out
    except Exception as e:
        print(f'  [tshark] Error: {e}')
        return {}

def _merge_tshark(packets, tshark_data):
    """Enrich parsed packets with tshark dissection data."""
    if not tshark_data:
        return
    DHCP_TYPES = {'1':'Discover','2':'Offer','3':'Request','4':'Decline',
                  '5':'ACK','6':'NAK','7':'Release','8':'Inform'}
    enriched = 0
    for pkt in packets:
        fnum = pkt.get('id', 0)
        ts = tshark_data.get(fnum)
        if not ts:
            continue
        enriched += 1
        # Store raw tshark protocol stack and info
        pkt['tshark_protocols'] = ts['protocols']
        pkt['tshark_info'] = ts['info']
        # Enrich DHCP message type from tshark
        if ts['dhcp_type'] and ts['dhcp_type'] in DHCP_TYPES:
            pkt['dhcp_msg_type'] = 'DHCP ' + DHCP_TYPES[ts['dhcp_type']]
        # Enrich DNS query name
        if ts['dns_name']:
            pkt['dns_query'] = ts['dns_name']
        if ts['dns_resp']:
            pkt['dns_qr'] = 'Response' if ts['dns_resp'] == '1' else 'Query'
        # Enrich SNMP trap fields from tshark
        _has_snmp = (ts.get('snmp_community') or ts.get('snmp_pdu_type')
                     or 'snmp' in ts.get('protocols', ''))
        if _has_snmp:
            pkt['snmp_community'] = ts.get('snmp_community', '')
            pkt['snmp_pdu_type']  = ts.get('snmp_pdu_type', '')
            pkt['snmp_enterprise']= ts.get('snmp_enterprise', '')
            pkt['snmp_generic']   = ts.get('snmp_generic', '')
            pkt['snmp_specific']  = ts.get('snmp_specific', '')
            pkt['snmp_version']   = ts.get('snmp_version', '')
            pkt['snmp_varbinds']  = ts.get('snmp_varbinds', [])  # [(name, value), ...]
            # Upgrade proto from bare UDP → SNMP / SNMP-Trap when tshark confirms
            if pkt.get('proto') in ('UDP', 'TCP'):
                pdu = ts.get('snmp_pdu_type', '')
                if pdu in ('4', '7'):  # Trap-v1 (4) or SNMPv2-Trap (7)
                    pkt['proto'] = 'SNMP-Trap'
                else:
                    pkt['proto'] = 'SNMP'
                pkt['summary'] = (f'{pkt["proto"]}  '
                    f'{pkt.get("src_ip","?")}:{pkt.get("src_port","")} → '
                    f'{pkt.get("dst_ip","?")}:{pkt.get("dst_port","")}')
        # If our binary parser couldn't identify the protocol, use tshark's
        proto_stack = ts['protocols']
        if proto_stack and (pkt.get('proto') in ('UDP', 'TCP')
                            or pkt.get('proto', '').startswith('ET-')):
            # Extract the highest-layer protocol from tshark
            layers = proto_stack.split(':')
            # Pick the most informative layer (skip eth, ip, tcp, udp)
            skip = {'eth','ethertype','ip','ipv6','tcp','udp','data','frame'}
            for layer in reversed(layers):
                if layer.lower() not in skip:
                    pkt['proto'] = layer.upper()
                    break
    print(f'  [tshark] Enriched {enriched} packets')

# ══════════════════════════════════════════════════════════════════════════════
#  ANOMALY DETECTION ENGINE — L2–L7 Hybrid (Rule + ML + AI)
#  Schema: Extreme Switch Engine Protocol Coverage
# ══════════════════════════════════════════════════════════════════════════════

# ── Severity levels ──────────────────────────────────────────────────────────
SEV_CRITICAL = 'critical'
SEV_HIGH     = 'high'
SEV_MEDIUM   = 'medium'
SEV_LOW      = 'low'
SEV_INFO     = 'info'

_SEV_ORDER = {SEV_CRITICAL:5, SEV_HIGH:4, SEV_MEDIUM:3, SEV_LOW:2, SEV_INFO:1}

# ── Feature Extraction (L2–L7) ──────────────────────────────────────────────

def _extract_features(packets, analysis):
    """Extract L2–L7 features from parsed packets for anomaly detection.
    Returns a feature dict consumed by rule engine and ML scorer."""
    total = len(packets)
    if total == 0:
        return {}

    ts_list = [p.get('ts', 0) for p in packets]
    duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 0.001

    # ── L2 Features ─────────────────────────────────────────────────────────
    mac_to_ports = {}        # mac → set of (vlan, dst_mac) pairs (proxy for ports)
    mac_timeline = {}        # mac → list of timestamps
    vlan_set = set()
    lldp_neighbors = {}      # src_mac → set of neighbor identifiers
    stp_tc_count = 0
    stp_root_ids = set()
    broadcast_count = 0
    unique_macs = set()

    for p in packets:
        sm = p.get('src_mac', '')
        dm = p.get('dst_mac', '')
        vid = p.get('vlan_id')
        proto = p.get('proto', '')

        if sm:
            unique_macs.add(sm)
            mac_to_ports.setdefault(sm, set()).add((vid, dm))
            mac_timeline.setdefault(sm, []).append(p.get('ts', 0))
        if dm:
            unique_macs.add(dm)
            if dm == 'ff:ff:ff:ff:ff:ff':
                broadcast_count += 1
        if vid is not None:
            vlan_set.add(vid)
        if proto == 'LLDP':
            lldp_neighbors.setdefault(sm, set()).add(dm)
        if proto == 'STP' or 'stp' in proto.lower():
            stp_tc_count += 1

    # MAC flapping: same MAC seen with many different destination-contexts
    mac_flap_candidates = {}
    for mac, contexts in mac_to_ports.items():
        vlan_partner_set = set()
        for vid, dm in contexts:
            vlan_partner_set.add((vid, dm))
        if len(vlan_partner_set) > 10:
            mac_flap_candidates[mac] = len(vlan_partner_set)

    # MAC learning rate: unique MACs per second
    mac_rate = len(unique_macs) / max(duration, 0.001)

    # ── L3 Features ─────────────────────────────────────────────────────────
    ip_mac_map = {}          # ip → set of MACs
    ttl_distribution = {}    # ttl → count
    frag_count = 0
    route_protos = {'BGP': 0, 'OSPF': 0, 'RIP': 0, 'IS-IS': 0, 'VRRP': 0}
    multicast_pkts = 0
    igmp_joins = 0
    igmp_leaves = 0

    for p in packets:
        sip = p.get('src_ip', '')
        sm = p.get('src_mac', '')
        ttl = p.get('ttl')
        proto = p.get('proto', '')

        if sip and sm:
            ip_mac_map.setdefault(sip, set()).add(sm)
        if ttl is not None:
            ttl_distribution[ttl] = ttl_distribution.get(ttl, 0) + 1

        # Fragment detection from hex layers
        for layer in p.get('layers', []):
            for f in layer.get('fields', []):
                if f.get('n') == 'Flags' and 'MF' in str(f.get('v', '')):
                    frag_count += 1
                if f.get('n') == 'Fragment Offset':
                    try:
                        foff = int(str(f.get('v', '0')).split()[0])
                        if foff > 0:
                            frag_count += 1
                    except (ValueError, IndexError):
                        pass

        # Routing protocol counters
        pu = proto.upper()
        if pu in route_protos:
            route_protos[pu] += 1

        # Multicast detection
        dip = p.get('dst_ip', '')
        if dip:
            parts = dip.split('.')
            if len(parts) == 4:
                try:
                    if 224 <= int(parts[0]) <= 239:
                        multicast_pkts += 1
                except ValueError:
                    pass
        if proto == 'IGMP':
            icmp_type = p.get('icmp_type')
            if icmp_type in (0x16, 0x22):
                igmp_joins += 1
            elif icmp_type == 0x17:
                igmp_leaves += 1

    # IP spoofing: one IP mapping to multiple MACs
    ip_multi_mac = {ip: macs for ip, macs in ip_mac_map.items() if len(macs) > 1}

    # TTL anomaly: find dominant TTL and outliers
    ttl_total = sum(ttl_distribution.values())
    ttl_dominant = max(ttl_distribution, key=ttl_distribution.get) if ttl_distribution else 0
    ttl_dominant_pct = ttl_distribution.get(ttl_dominant, 0) / max(ttl_total, 1)
    ttl_outliers = {t: c for t, c in ttl_distribution.items()
                    if abs(t - ttl_dominant) > 32 and c > 2}

    # ── L4 Features ─────────────────────────────────────────────────────────
    tcp_pkts = analysis.get('tcp', [])
    udp_pkts = analysis.get('udp', [])
    tcp_syn = analysis.get('tcp_syn', 0)
    tcp_synack = analysis.get('tcp_synack', 0)
    tcp_rst = analysis.get('tcp_rst', 0)
    tcp_fin = analysis.get('tcp_fin', 0)

    # Connection tracking
    syn_sources = {}         # src_ip → count of SYN
    half_open = 0            # SYN without SYN-ACK
    rst_rate = tcp_rst / max(duration, 0.001)
    retransmissions = 0
    null_xmas_count = 0

    # TCP window tracking for zero-window detection
    zero_window_count = 0

    # UDP rate tracking
    udp_rate = len(udp_pkts) / max(duration, 0.001)
    udp_amplification = []   # (src, dst, ratio) candidates

    # Port scan detection
    dst_ports_by_src = {}    # src_ip → set of dst_ports

    for p in tcp_pkts:
        flags = p.get('tcp_flags', '')
        sip = p.get('src_ip', '')
        dip = p.get('dst_ip', '')
        dp = p.get('dst_port')
        win = p.get('tcp_window', -1)

        if flags == 'SYN':
            syn_sources[sip] = syn_sources.get(sip, 0) + 1
        if 'SYN' in flags and 'ACK' not in flags:
            half_open += 1
        # Invalid flag combos
        if flags == '' or flags is None:
            null_xmas_count += 1  # NULL scan
        elif set(flags.replace(' ', '').split(',')).issuperset({'FIN', 'PSH', 'URG'}):
            null_xmas_count += 1  # XMAS scan
        if win == 0:
            zero_window_count += 1
        if sip and dp:
            dst_ports_by_src.setdefault(sip, set()).add(dp)

    half_open = max(0, tcp_syn - tcp_synack)

    # Port scan: source hitting many different ports
    port_scanners = {ip: len(ports) for ip, ports in dst_ports_by_src.items()
                     if len(ports) > 15}

    # UDP amplification: find large response / small request patterns
    udp_flows = {}  # (src,dst) → {'out_bytes':0, 'in_bytes':0}
    for p in udp_pkts:
        sip = p.get('src_ip', '')
        dip = p.get('dst_ip', '')
        flen = p.get('frame_len', 0)
        if sip and dip:
            k = (sip, dip)
            udp_flows.setdefault(k, {'bytes': 0, 'count': 0})
            udp_flows[k]['bytes'] += flen
            udp_flows[k]['count'] += 1
    for (s, d), v in udp_flows.items():
        rev = udp_flows.get((d, s))
        if rev and v['bytes'] > 0 and rev['bytes'] > v['bytes'] * 5:
            udp_amplification.append({
                'reflector': d, 'target': s,
                'ratio': round(rev['bytes'] / max(v['bytes'], 1), 1),
                'response_bytes': rev['bytes']
            })

    # ── L5–L6 Features (Session/Presentation) ──────────────────────────────
    tls_versions = {}
    ssh_sessions = {}        # (src,dst) → {count, first_ts, last_ts}
    snmp_sources = set()
    auth_failures = {}       # (src_ip) → count

    for p in packets:
        proto = p.get('proto', '')
        sip = p.get('src_ip', '')
        dip = p.get('dst_ip', '')

        # TLS version detection from layers
        if proto in ('HTTPS', 'HTTPS-Alt', 'IMAPS', 'POP3S', 'SMTPS', 'LDAPS', 'SIPS'):
            for layer in p.get('layers', []):
                for f in layer.get('fields', []):
                    v = str(f.get('v', ''))
                    if 'TLS' in f.get('n', '') or 'SSL' in f.get('n', ''):
                        tls_versions[v] = tls_versions.get(v, 0) + 1

        # SSH session tracking
        if proto == 'SSH':
            k = (sip, dip)
            if k not in ssh_sessions:
                ssh_sessions[k] = {'count': 0, 'first_ts': p.get('ts', 0), 'last_ts': p.get('ts', 0)}
            ssh_sessions[k]['count'] += 1
            ssh_sessions[k]['last_ts'] = p.get('ts', 0)

        # SNMP source tracking
        if proto in ('SNMP', 'SNMP-Trap'):
            snmp_sources.add(sip)

    # SSH brute force: many short sessions from same source
    ssh_brute_candidates = {}
    for (s, d), info in ssh_sessions.items():
        sess_dur = info['last_ts'] - info['first_ts']
        if info['count'] > 5 and sess_dur < 10:
            ssh_brute_candidates[s] = ssh_brute_candidates.get(s, 0) + 1

    # ── L7 Features (Application) ──────────────────────────────────────────
    dhcp_servers = set()
    dhcp_requests = 0
    dhcp_timeline = []       # timestamps of DHCP requests
    dns_queries = {}         # query_name → count
    dns_nxdomain = 0
    dns_query_rate = 0
    http_methods = {}        # method → count
    http_errors = 0
    radius_failures = {}     # src_ip → failure count
    syslog_count = 0

    # Track no-response patterns across protocols
    no_response = {
        'ARP': {'sent': 0, 'replied': 0},
        'DNS': {'sent': 0, 'replied': 0},
        'ICMP': {'sent': 0, 'replied': 0},
        'DHCP': {'sent': 0, 'replied': 0},
        'NTP': {'sent': 0, 'replied': 0},
        'SNMP': {'sent': 0, 'replied': 0},
        'RADIUS': {'sent': 0, 'replied': 0},
        'SIP': {'sent': 0, 'replied': 0},
        'LDAP': {'sent': 0, 'replied': 0},
        'HTTP': {'sent': 0, 'replied': 0},
    }

    for p in packets:
        proto = p.get('proto', '')
        sip = p.get('src_ip', '')
        dp = p.get('dst_port')
        sp = p.get('src_port')

        # ARP no-response
        if proto == 'ARP':
            if p.get('arp_op') == 'REQUEST':
                no_response['ARP']['sent'] += 1
            elif p.get('arp_op') == 'REPLY':
                no_response['ARP']['replied'] += 1

        # DHCP tracking
        if proto in ('DHCP-Server', 'DHCP-Client'):
            dhcp_type = p.get('dhcp_msg_type', '')
            if 'Offer' in dhcp_type or 'ACK' in dhcp_type:
                dhcp_servers.add(sip)
            if 'Discover' in dhcp_type or 'Request' in dhcp_type:
                dhcp_requests += 1
                dhcp_timeline.append(p.get('ts', 0))
                no_response['DHCP']['sent'] += 1
            elif 'Offer' in dhcp_type or 'ACK' in dhcp_type:
                no_response['DHCP']['replied'] += 1

        # DNS tracking
        if proto == 'DNS':
            qname = p.get('dns_query', '')
            if qname:
                dns_queries[qname] = dns_queries.get(qname, 0) + 1
            if dp == 53:
                no_response['DNS']['sent'] += 1
            elif sp == 53:
                no_response['DNS']['replied'] += 1

        # ICMP no-response
        if proto == 'ICMP':
            if p.get('icmp_type') == 8:
                no_response['ICMP']['sent'] += 1
            elif p.get('icmp_type') == 0:
                no_response['ICMP']['replied'] += 1

        # HTTP tracking
        if proto in ('HTTP', 'HTTP-Alt'):
            no_response['HTTP']['sent'] += 1
        elif proto in ('HTTPS', 'HTTPS-Alt'):
            no_response['HTTP']['sent'] += 1

        # SNMP no-response
        if proto == 'SNMP':
            if dp in (161, 162):
                no_response['SNMP']['sent'] += 1
            elif sp in (161, 162):
                no_response['SNMP']['replied'] += 1

        # NTP
        if proto == 'NTP':
            if dp == 123:
                no_response['NTP']['sent'] += 1
            elif sp == 123:
                no_response['NTP']['replied'] += 1

        # RADIUS
        if proto in ('RADIUS-Auth', 'RADIUS-Acct'):
            if dp in (1812, 1813):
                no_response['RADIUS']['sent'] += 1
            elif sp in (1812, 1813):
                no_response['RADIUS']['replied'] += 1

        # SIP
        if proto in ('SIP', 'SIPS'):
            if dp in (5060, 5061):
                no_response['SIP']['sent'] += 1
            elif sp in (5060, 5061):
                no_response['SIP']['replied'] += 1

        # LDAP
        if proto in ('LDAP', 'LDAPS'):
            if dp in (389, 636):
                no_response['LDAP']['sent'] += 1
            elif sp in (389, 636):
                no_response['LDAP']['replied'] += 1

        # Syslog
        if proto == 'Syslog':
            syslog_count += 1

    # DNS entropy scoring for tunneling detection
    dns_high_entropy = []
    for qname, cnt in dns_queries.items():
        if len(qname) > 30:
            # Simple entropy measure: unique chars / length
            _chars = set(qname.replace('.', ''))
            _entropy = len(_chars) / max(len(qname.replace('.', '')), 1)
            if _entropy > 0.7 and len(qname) > 50:
                dns_high_entropy.append({'name': qname, 'entropy': round(_entropy, 2), 'count': cnt})

    # DHCP starvation: rapid requests in short window
    dhcp_starvation = False
    if len(dhcp_timeline) > 20:
        dhcp_timeline.sort()
        for i in range(len(dhcp_timeline) - 10):
            if dhcp_timeline[i + 10] - dhcp_timeline[i] < 5:  # 10 requests in 5s
                dhcp_starvation = True
                break

    # DNS query rate
    dns_query_rate = sum(dns_queries.values()) / max(duration, 0.001)

    return {
        # L2
        'l2': {
            'unique_macs': len(unique_macs),
            'mac_rate': round(mac_rate, 2),
            'mac_flap_candidates': mac_flap_candidates,
            'vlans': sorted(vlan_set),
            'broadcast_count': broadcast_count,
            'broadcast_pct': round(broadcast_count / max(total, 1) * 100, 1),
            'lldp_neighbors': {k: len(v) for k, v in lldp_neighbors.items()},
            'stp_tc_count': stp_tc_count,
        },
        # L3
        'l3': {
            'ip_multi_mac': ip_multi_mac,
            'ttl_dominant': ttl_dominant,
            'ttl_dominant_pct': round(ttl_dominant_pct * 100, 1),
            'ttl_outliers': ttl_outliers,
            'frag_count': frag_count,
            'route_protos': route_protos,
            'multicast_pkts': multicast_pkts,
            'igmp_joins': igmp_joins,
            'igmp_leaves': igmp_leaves,
        },
        # L4
        'l4': {
            'tcp_syn': tcp_syn,
            'tcp_synack': tcp_synack,
            'tcp_rst': tcp_rst,
            'tcp_fin': tcp_fin,
            'half_open': half_open,
            'rst_rate': round(rst_rate, 2),
            'null_xmas_count': null_xmas_count,
            'zero_window_count': zero_window_count,
            'syn_sources': syn_sources,
            'port_scanners': port_scanners,
            'udp_rate': round(udp_rate, 2),
            'udp_amplification': udp_amplification,
        },
        # L5-L6
        'l5l6': {
            'tls_versions': tls_versions,
            'ssh_sessions': len(ssh_sessions),
            'ssh_brute_candidates': ssh_brute_candidates,
            'snmp_sources': list(snmp_sources),
        },
        # L7
        'l7': {
            'dhcp_servers': list(dhcp_servers),
            'dhcp_requests': dhcp_requests,
            'dhcp_starvation': dhcp_starvation,
            'dns_queries_unique': len(dns_queries),
            'dns_query_rate': round(dns_query_rate, 2),
            'dns_high_entropy': dns_high_entropy,
            'syslog_count': syslog_count,
            'no_response': no_response,
        },
        # Meta
        'duration': round(duration, 3),
        'total': total,
    }


# ── Rule Engine (Deterministic Detection) ────────────────────────────────────

def _rule_engine(features, analysis):
    """Apply deterministic rules across L2–L7. Returns list of anomaly dicts."""
    findings = []

    def _add(category, layer, title, severity, detail, evidence=''):
        findings.append({
            'category': category, 'layer': layer, 'title': title,
            'severity': severity, 'detail': detail, 'evidence': evidence,
        })

    l2 = features.get('l2', {})
    l3 = features.get('l3', {})
    l4 = features.get('l4', {})
    l5 = features.get('l5l6', {})
    l7 = features.get('l7', {})
    total = features.get('total', 0)
    duration = features.get('duration', 0.001)

    # ── L2 Rules ────────────────────────────────────────────────────────────
    # MAC flapping
    for mac, ctx_count in l2.get('mac_flap_candidates', {}).items():
        _add('MAC/FDB', 'L2', f'MAC Flapping: {mac}', SEV_HIGH,
             f'MAC {mac} seen in {ctx_count} different contexts — possible loop or misconfiguration',
             f'contexts={ctx_count}')

    # MAC flooding
    if l2.get('mac_rate', 0) > 50:
        _add('MAC/FDB', 'L2', 'MAC Flood', SEV_HIGH,
             f'MAC learning rate: {l2["mac_rate"]}/s — CAM table overflow attack possible',
             f'unique_macs={l2.get("unique_macs",0)} rate={l2["mac_rate"]}/s')

    # Broadcast storm
    bcast_pct = l2.get('broadcast_pct', 0)
    if bcast_pct > 30:
        _add('Loop/Storm', 'L2', 'Broadcast Storm', SEV_CRITICAL,
             f'{bcast_pct}% of traffic is broadcast — likely L2 loop',
             f'broadcast={l2.get("broadcast_count",0)} pct={bcast_pct}%')
    elif bcast_pct > 15:
        _add('Loop/Storm', 'L2', 'High Broadcast Ratio', SEV_MEDIUM,
             f'{bcast_pct}% broadcast traffic — monitor for loops',
             f'broadcast={l2.get("broadcast_count",0)}')

    # STP topology changes
    if l2.get('stp_tc_count', 0) > 5:
        _add('STP/Ring', 'L2', 'Topology Change Storm', SEV_HIGH,
             f'{l2["stp_tc_count"]} STP topology change events — frequent reconvergence',
             f'tc_count={l2["stp_tc_count"]}')

    # ── L3 Rules ────────────────────────────────────────────────────────────
    # IP spoofing (IP maps to multiple MACs)
    for ip, macs in l3.get('ip_multi_mac', {}).items():
        if len(macs) > 2:
            _add('IP', 'L3', f'IP Spoofing Suspect: {ip}', SEV_HIGH,
                 f'IP {ip} seen from {len(macs)} different MACs — possible ARP spoofing/MITM',
                 f'macs={",".join(sorted(macs)[:5])}')

    # TTL anomaly
    for ttl_val, cnt in l3.get('ttl_outliers', {}).items():
        _add('IP', 'L3', f'TTL Anomaly: TTL={ttl_val}', SEV_LOW,
             f'{cnt} packets with unusual TTL={ttl_val} (dominant={l3.get("ttl_dominant",0)} at {l3.get("ttl_dominant_pct",0)}%)',
             f'outlier_ttl={ttl_val} count={cnt}')

    # Fragmentation attack
    if l3.get('frag_count', 0) > 20:
        _add('IP', 'L3', 'Fragmentation Attack', SEV_MEDIUM,
             f'{l3["frag_count"]} fragmented packets — possible evasion or Teardrop attack',
             f'frag_count={l3["frag_count"]}')

    # Multicast flood without IGMP joins
    if l3.get('multicast_pkts', 0) > 50 and l3.get('igmp_joins', 0) == 0:
        _add('Multicast', 'L3', 'Multicast Flood', SEV_MEDIUM,
             f'{l3["multicast_pkts"]} multicast packets with no IGMP joins — uncontrolled flood',
             f'mcast={l3["multicast_pkts"]} joins={l3.get("igmp_joins",0)}')

    # ── L4 Rules ────────────────────────────────────────────────────────────
    # SYN flood
    tcp_syn = l4.get('tcp_syn', 0)
    tcp_synack = l4.get('tcp_synack', 0)
    if tcp_syn > 20:
        ratio = tcp_syn / max(tcp_synack, 1)
        sev = SEV_CRITICAL if ratio > 10 else SEV_HIGH if ratio > 5 else SEV_MEDIUM
        _add('TCP', 'L4', f'SYN Flood: {tcp_syn} SYN packets', sev,
             f'SYN/SYN-ACK ratio: {ratio:.1f}:1 — {"confirmed" if ratio>5 else "possible"} SYN flood',
             f'syn={tcp_syn} synack={tcp_synack} ratio={ratio:.1f}')

    # Half-open connections
    half_open = l4.get('half_open', 0)
    if half_open > 10:
        _add('TCP', 'L4', f'Half-Open Connections: {half_open}', SEV_MEDIUM,
             f'{half_open} incomplete TCP handshakes — resource exhaustion risk',
             f'half_open={half_open}')

    # NULL/XMAS scan
    if l4.get('null_xmas_count', 0) > 0:
        _add('TCP', 'L4', f'Stealth Scan: {l4["null_xmas_count"]} NULL/XMAS packets', SEV_HIGH,
             'Invalid TCP flag combinations detected — reconnaissance activity',
             f'null_xmas={l4["null_xmas_count"]}')

    # RST storm
    if l4.get('tcp_rst', 0) > 10:
        _add('TCP', 'L4', f'RST Storm: {l4["tcp_rst"]} RST packets', SEV_MEDIUM,
             f'RST rate: {l4.get("rst_rate",0)}/s — connection rejections or port scan responses',
             f'rst={l4["tcp_rst"]} rate={l4.get("rst_rate",0)}/s')

    # Port scan
    for ip, port_count in l4.get('port_scanners', {}).items():
        _add('TCP', 'L4', f'Port Scan from {ip}: {port_count} ports', SEV_HIGH,
             f'{ip} probed {port_count} unique destination ports — active reconnaissance',
             f'scanner={ip} ports={port_count}')

    # Zero window
    if l4.get('zero_window_count', 0) > 5:
        _add('TCP', 'L4', f'TCP Zero Window: {l4["zero_window_count"]}', SEV_LOW,
             'Receiver advertising zero window — backpressure or resource exhaustion',
             f'zero_win={l4["zero_window_count"]}')

    # UDP flood
    if l4.get('udp_rate', 0) > 500:
        _add('UDP', 'L4', f'UDP Flood: {l4["udp_rate"]:.0f} pkt/s', SEV_HIGH,
             f'UDP packet rate {l4["udp_rate"]:.0f}/s exceeds threshold — volumetric attack',
             f'udp_rate={l4["udp_rate"]:.0f}/s')

    # UDP amplification
    for amp in l4.get('udp_amplification', []):
        _add('UDP', 'L4',
             f'Amplification: {amp["reflector"]}→{amp["target"]} ({amp["ratio"]}x)',
             SEV_HIGH,
             f'Reflector {amp["reflector"]} sending {amp["ratio"]}x more data to {amp["target"]} — DDoS amplification',
             f'ratio={amp["ratio"]}x bytes={amp["response_bytes"]}')

    # ── L5–L6 Rules ─────────────────────────────────────────────────────────
    # SSH brute force
    for ip, count in l5.get('ssh_brute_candidates', {}).items():
        _add('SSH', 'L5', f'SSH Brute Force from {ip}', SEV_HIGH,
             f'{count} rapid SSH sessions from {ip} — credential stuffing suspected',
             f'source={ip} sessions={count}')

    # ── L7 Rules ────────────────────────────────────────────────────────────
    # Rogue DHCP
    dhcp_servers = l7.get('dhcp_servers', [])
    if len(dhcp_servers) > 1:
        _add('DHCP', 'L7', f'Rogue DHCP: {len(dhcp_servers)} servers', SEV_CRITICAL,
             f'Multiple DHCP servers: {", ".join(dhcp_servers)} — rogue server or misconfiguration',
             f'servers={",".join(dhcp_servers)}')

    # DHCP starvation
    if l7.get('dhcp_starvation'):
        _add('DHCP', 'L7', 'DHCP Starvation Attack', SEV_CRITICAL,
             f'{l7.get("dhcp_requests",0)} DHCP requests in rapid succession — address pool exhaustion',
             f'requests={l7.get("dhcp_requests",0)}')

    # DNS tunneling
    for entry in l7.get('dns_high_entropy', []):
        _add('DNS', 'L7', f'DNS Tunneling Suspect: {entry["name"][:40]}…', SEV_HIGH,
             f'High-entropy domain (score={entry["entropy"]}) queried {entry["count"]}x — data exfiltration risk',
             f'entropy={entry["entropy"]} domain={entry["name"][:60]}')

    # High DNS query rate
    if l7.get('dns_query_rate', 0) > 100:
        _add('DNS', 'L7', f'DNS Query Spike: {l7["dns_query_rate"]:.0f}/s', SEV_MEDIUM,
             'Abnormally high DNS query rate — possible DGA or tunneling activity',
             f'rate={l7["dns_query_rate"]:.0f}/s unique={l7.get("dns_queries_unique",0)}')

    # No-response anomalies (universal tracker)
    for proto_name, stats in l7.get('no_response', {}).items():
        sent = stats.get('sent', 0)
        replied = stats.get('replied', 0)
        if sent > 5 and replied == 0:
            _add(proto_name, 'L3-L7', f'{proto_name}: {sent} requests, 0 responses', SEV_MEDIUM,
                 f'All {sent} {proto_name} requests went unanswered — service down or filtered',
                 f'sent={sent} replied=0')
        elif sent > 10 and replied > 0 and replied / sent < 0.3:
            loss_pct = round((1 - replied / sent) * 100, 1)
            _add(proto_name, 'L3-L7', f'{proto_name}: {loss_pct}% response loss', SEV_LOW,
                 f'{sent} sent, only {replied} replied ({loss_pct}% loss)',
                 f'sent={sent} replied={replied} loss={loss_pct}%')

    # ARP-specific from analysis
    arp = analysis.get('arp', [])
    arp_unanswered = analysis.get('arp_unanswered', {})
    arp_gratuitous = analysis.get('arp_gratuitous', [])

    if analysis.get('arp_reqs_total', 0) > 20:
        _add('ARP', 'L2', f'ARP Storm: {analysis["arp_reqs_total"]} requests', SEV_MEDIUM,
             f'High ARP request volume — possible scanning or misconfigured hosts',
             f'requests={analysis["arp_reqs_total"]}')

    if len(arp_unanswered) > 5:
        _add('ARP', 'L2', f'ARP: {len(arp_unanswered)} unanswered pairs', SEV_LOW,
             f'{len(arp_unanswered)} ARP requests without replies — dead hosts or ACL filtering',
             f'unanswered={len(arp_unanswered)}')

    if arp_gratuitous:
        _add('ARP', 'L2', f'Gratuitous ARP: {len(arp_gratuitous)} packets', SEV_MEDIUM,
             f'{len(arp_gratuitous)} unsolicited ARP replies — possible IP conflict or MITM',
             f'gratuitous={len(arp_gratuitous)}')

    # ICMP flood
    icmp_req = analysis.get('icmp_req', 0)
    if icmp_req > 10:
        _add('ICMP', 'L3', f'ICMP Flood: {icmp_req} Echo Requests', SEV_MEDIUM,
             f'{icmp_req} ping requests — reconnaissance or DDoS ping flood',
             f'echo_req={icmp_req}')

    return findings


# ── ML Scoring Pipeline ──────────────────────────────────────────────────────

def _ml_score(features):
    """Lightweight statistical anomaly scoring (Isolation Forest-inspired).
    No external ML library required. Uses z-score and ratio-based outlier detection.
    Returns list of anomaly dicts with confidence scores."""
    findings = []
    total = features.get('total', 0)
    duration = features.get('duration', 0.001)
    if total < 10:
        return findings

    l4 = features.get('l4', {})
    l7 = features.get('l7', {})

    # ── Statistical Baselines ───────────────────────────────────────────────
    pkt_rate = total / max(duration, 0.001)

    # Protocol distribution entropy (Shannon)
    # Low entropy = dominated by one protocol = suspicious
    proto_counts = {}
    for layer_key in ('l2', 'l3', 'l4', 'l5l6', 'l7'):
        layer = features.get(layer_key, {})
        for k, v in layer.items():
            if isinstance(v, (int, float)) and v > 0:
                proto_counts[k] = v

    # SYN/ACK ratio scoring
    syn = l4.get('tcp_syn', 0)
    synack = l4.get('tcp_synack', 0)
    if syn > 5:
        syn_ratio = syn / max(synack, 1)
        # Normal: ~1:1, Attack: >5:1
        if syn_ratio > 3:
            confidence = min(99, int(50 + syn_ratio * 5))
            findings.append({
                'category': 'ML:Connection', 'layer': 'L4',
                'title': f'Anomalous SYN/ACK ratio: {syn_ratio:.1f}:1',
                'severity': SEV_HIGH if syn_ratio > 5 else SEV_MEDIUM,
                'detail': f'ML confidence: {confidence}% — statistical deviation from normal handshake pattern',
                'evidence': f'syn={syn} synack={synack} ratio={syn_ratio:.1f} confidence={confidence}%',
            })

    # Burst detection: packets-per-second variance
    if duration > 1 and total > 50:
        # Divide capture into 1s buckets
        ts_min = features.get('duration', 0)
        # Use a simpler heuristic: compare first half vs second half rate
        half = total // 2
        first_half_duration = duration / 2
        # If we see high RST rate, flag as anomalous burst
        rst_rate = l4.get('rst_rate', 0)
        if rst_rate > 10:
            confidence = min(95, int(40 + rst_rate * 2))
            findings.append({
                'category': 'ML:Temporal', 'layer': 'L4',
                'title': f'RST burst: {rst_rate:.1f}/s',
                'severity': SEV_MEDIUM,
                'detail': f'ML confidence: {confidence}% — abnormal TCP reset rate suggests service disruption',
                'evidence': f'rst_rate={rst_rate:.1f}/s confidence={confidence}%',
            })

    # DNS behavioral scoring
    dns_rate = l7.get('dns_query_rate', 0)
    dns_unique = l7.get('dns_queries_unique', 0)
    if dns_rate > 10 and dns_unique > 0:
        # High rate with many unique queries = suspicious
        diversity = dns_unique / max(dns_rate * duration, 1)
        if diversity > 0.8 and dns_unique > 20:
            confidence = min(90, int(50 + diversity * 30))
            findings.append({
                'category': 'ML:Behavioral', 'layer': 'L7',
                'title': f'DNS anomaly: {dns_unique} unique queries at {dns_rate:.0f}/s',
                'severity': SEV_MEDIUM,
                'detail': f'ML confidence: {confidence}% — high query diversity suggests DGA or tunneling',
                'evidence': f'unique={dns_unique} rate={dns_rate:.0f}/s diversity={diversity:.2f}',
            })

    # Communication graph anomaly: single source hitting many destinations
    l4_scanners = l4.get('port_scanners', {})
    for ip, ports in l4_scanners.items():
        confidence = min(98, int(60 + ports * 0.5))
        findings.append({
            'category': 'ML:Graph', 'layer': 'L4',
            'title': f'Graph anomaly: {ip} → {ports} ports',
            'severity': SEV_HIGH,
            'detail': f'ML confidence: {confidence}% — fan-out pattern consistent with reconnaissance',
            'evidence': f'source={ip} ports={ports} confidence={confidence}%',
        })

    return findings


# ── Cross-Layer Correlation ──────────────────────────────────────────────────

def _cross_layer_correlate(rule_findings, ml_findings, features, analysis):
    """Correlate signals across layers for composite anomaly detection.
    Returns list of cross-layer anomaly dicts."""
    findings = []
    all_findings = rule_findings + ml_findings

    # Build indexes
    by_category = {}
    by_layer = {}
    for f in all_findings:
        by_category.setdefault(f['category'], []).append(f)
        by_layer.setdefault(f['layer'], []).append(f)

    l3 = features.get('l3', {})
    l4 = features.get('l4', {})

    # ── ip_mac_mismatch: L2+L3 inconsistency ───────────────────────────────
    if l3.get('ip_multi_mac') and 'ARP' in by_category:
        overlap_ips = set(l3['ip_multi_mac'].keys())
        if overlap_ips:
            findings.append({
                'category': 'Cross-Layer', 'layer': 'L2+L3',
                'title': f'ARP+IP Mismatch: {len(overlap_ips)} IPs with multiple MACs',
                'severity': SEV_CRITICAL,
                'detail': (f'ARP anomalies correlate with IP-to-MAC inconsistency for '
                           f'{", ".join(sorted(overlap_ips)[:3])} — strong MITM indicator'),
                'evidence': f'ips={",".join(sorted(overlap_ips)[:5])}',
            })

    # ── auth_then_anomaly: login + suspicious traffic ───────────────────────
    ssh_brute = features.get('l5l6', {}).get('ssh_brute_candidates', {})
    scanners = l4.get('port_scanners', {})
    for ip in set(ssh_brute.keys()) & set(scanners.keys()):
        findings.append({
            'category': 'Cross-Layer', 'layer': 'L4+L5',
            'title': f'Auth→Scan Chain: {ip}',
            'severity': SEV_CRITICAL,
            'detail': f'{ip} performed SSH brute-force AND port scanning — compromised host or attacker',
            'evidence': f'ssh_sessions={ssh_brute[ip]} ports_scanned={scanners[ip]}',
        })

    # ── SYN flood + RST storm = confirmed attack ────────────────────────────
    has_syn_flood = any('SYN Flood' in f['title'] for f in all_findings)
    has_rst_storm = any('RST' in f['title'] for f in all_findings)
    if has_syn_flood and has_rst_storm:
        findings.append({
            'category': 'Cross-Layer', 'layer': 'L4',
            'title': 'Confirmed DoS: SYN Flood + RST Storm',
            'severity': SEV_CRITICAL,
            'detail': 'SYN flood detected alongside RST storm — target is actively rejecting attack connections',
            'evidence': f'syn={l4.get("tcp_syn",0)} rst={l4.get("tcp_rst",0)}',
        })

    # ── DHCP starvation + rogue DHCP = network takeover ─────────────────────
    has_starvation = any('Starvation' in f['title'] for f in all_findings)
    has_rogue_dhcp = any('Rogue DHCP' in f['title'] for f in all_findings)
    if has_starvation and has_rogue_dhcp:
        findings.append({
            'category': 'Cross-Layer', 'layer': 'L2+L7',
            'title': 'DHCP Takeover: Starvation + Rogue Server',
            'severity': SEV_CRITICAL,
            'detail': 'DHCP pool exhaustion combined with rogue DHCP server — classic network hijack',
            'evidence': f'servers={features.get("l7",{}).get("dhcp_servers",[])}',
        })

    # ── routing_change + traffic_shift ──────────────────────────────────────
    route_protos = l3.get('route_protos', {})
    if any(v > 10 for v in route_protos.values()) and has_syn_flood:
        findings.append({
            'category': 'Cross-Layer', 'layer': 'L3+L4',
            'title': 'Routing Disruption + Attack Traffic',
            'severity': SEV_HIGH,
            'detail': f'High routing protocol activity ({route_protos}) coinciding with attack traffic — possible hijack',
            'evidence': f'route_protos={route_protos}',
        })

    return findings


# ── AI Anomaly Integration — Sequential 4-Step Pipeline ─────────────────────
# Step 1: Protocol Classification  → verifies detected protocols vs port expectations
# Step 2: Flow Construction        → groups packets into logical sessions
# Step 3: Anomaly Detection        → validates rule/ML findings with full context
# Step 4: Root Cause + Next Actions → synthesizes incidents with CLI remediation

def _pipeline_call_ai(system_prompt, user_prompt, max_tokens=1200):
    """Low-level AI call with custom system prompt for each pipeline step.
    Returns raw text string or '' on any failure."""
    import urllib.request, urllib.error
    try:
        if AI_BACKEND == 'claude' and CLAUDE_API_KEY:
            data = json.dumps({
                'model': CLAUDE_MODEL, 'max_tokens': max_tokens,
                'system': system_prompt,
                'messages': [{'role': 'user', 'content': user_prompt}],
            }).encode()
            req = urllib.request.Request(
                'https://api.anthropic.com/v1/messages', data=data, method='POST',
                headers={'Content-Type': 'application/json',
                         'x-api-key': CLAUDE_API_KEY,
                         'anthropic-version': '2023-06-01'})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())['content'][0]['text']
        if AI_BACKEND == 'openai' and OPENAI_API_KEY:
            data = json.dumps({
                'model': 'gpt-4o', 'max_tokens': max_tokens,
                'messages': [{'role': 'system', 'content': system_prompt},
                             {'role': 'user',   'content': user_prompt}],
            }).encode()
            req = urllib.request.Request(
                'https://api.openai.com/v1/chat/completions', data=data, method='POST',
                headers={'Content-Type': 'application/json',
                         'Authorization': f'Bearer {OPENAI_API_KEY}'})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())['choices'][0]['message']['content']
        # Ollama fallback
        data = json.dumps({
            'model': OLLAMA_MODEL, 'stream': False,
            'prompt': system_prompt + '\n\n' + user_prompt,
            'options': {'num_predict': max_tokens},
        }).encode()
        req = urllib.request.Request(
            'http://localhost:11434/api/generate', data=data, method='POST',
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=180) as r:
            return json.loads(r.read())['response']
    except Exception as e:
        print(f'  [pipeline] AI call failed: {e}')
        return ''


def _pipeline_parse_json(raw):
    """Strip markdown fences and parse JSON. Returns None on failure."""
    if not raw:
        return None
    text = raw.strip()
    if text.startswith('```'):
        lines = text.split('\n')
        text = '\n'.join(lines[1:])
        if text.rstrip().endswith('```'):
            text = text.rstrip()[:-3].strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        for sc, ec in (('[', ']'), ('{', '}')):
            s = text.find(sc); e = text.rfind(ec)
            if s != -1 and e > s:
                try:
                    return json.loads(text[s:e+1])
                except json.JSONDecodeError:
                    pass
        return None


# ── Step 1: Protocol Classification ──────────────────────────────────────────

_SYS_STEP1 = (
    "You are a senior network protocol analyst with expert RFC knowledge. "
    "You receive a summary of protocol flows from a packet capture. "
    "Validate whether each detected protocol matches expected behaviour for its port/transport. "
    "Flag mismatches, tunnelling, and protocol impersonation. "
    "Output ONLY valid JSON — no prose, no markdown fences."
)

def _pipeline_step1_classify(features, analysis):
    """Step 1 — Protocol Classification. Returns dict or {}."""
    print('  [pipeline] Step 1: Protocol classification...')
    pc = analysis.get('proto_counts', {})
    total = features.get('total', 0)
    duration = features.get('duration', 0)

    # Build top flows
    flow_counts = {}
    for p in analysis.get('all_packets', [])[:2000]:
        sip = p.get('src_ip',''); dip = p.get('dst_ip','')
        sp = p.get('src_port',''); dp = p.get('dst_port','')
        proto = p.get('proto','?')
        if sip and dip:
            k = (sip, sp, dip, dp, proto)
            flow_counts[k] = flow_counts.get(k, 0) + 1
    top_flows = sorted(flow_counts.items(), key=lambda x: x[1], reverse=True)[:15]
    flows_str = '\n'.join(
        f'  {s}:{sp} -> {d}:{dp} [{pr}] x{cnt}'
        for (s,sp,d,dp,pr),cnt in top_flows
    ) or '  (none)'

    # Flag unusual ports
    unusual = []
    for p in analysis.get('all_packets', [])[:1000]:
        dp = p.get('dst_port'); proto = p.get('proto','')
        if dp and dp in SERVICES and proto not in ('TCP','UDP','?','') and proto != SERVICES[dp]:
            unusual.append(f'port {dp} (expected {SERVICES[dp]}): got {proto}')
    unusual = list(dict.fromkeys(unusual))[:8]

    proto_str = '\n'.join(
        f'  {k}: {v}' for k,v in sorted(pc.items(), key=lambda x:x[1], reverse=True)[:20]
    ) or '  (none)'

    prompt = (
        f"Capture: {total} packets over {round(duration,2)}s\n\n"
        f"Protocol distribution:\n{proto_str}\n\n"
        f"Top flows (src:sp -> dst:dp [proto] xcount):\n{flows_str}\n\n"
        f"Unusual port/protocol combinations:\n"
        + ('\n'.join(f'  {u}' for u in unusual) or '  (none)') +
        '\n\nReturn JSON:\n'
        '{"classifications":[{"proto":"<name>","expected":true,"confidence":"High","note":"<reason>","port_mismatch":false}],'
        '"suspicious_protos":["<proto>"],"summary":"<one sentence>"}'
    )
    result = _pipeline_parse_json(_pipeline_call_ai(_SYS_STEP1, prompt, 700))
    if isinstance(result, dict):
        print(f'  [pipeline]   -> {len(result.get("classifications",[]))} classified, '
              f'{len(result.get("suspicious_protos",[]))} suspicious')
        return result
    print('  [pipeline]   -> Step 1 failed, continuing')
    return {}


# ── Step 2: Flow Construction ─────────────────────────────────────────────────

_SYS_STEP2 = (
    "You are a network session analyst expert in TCP/IP flow reconstruction. "
    "You receive packet statistics and protocol classification. "
    "Identify logical sessions, flag broken/incomplete sessions, and detect attack patterns. "
    "Output ONLY valid JSON — no prose, no markdown fences."
)

def _pipeline_step2_flows(features, analysis, step1):
    """Step 2 — Flow Construction. Returns dict or {}."""
    print('  [pipeline] Step 2: Flow construction...')
    l4 = features.get('l4', {}); l7 = features.get('l7', {})

    # Per-source stats
    src_stats = {}
    for p in analysis.get('all_packets', [])[:2000]:
        sip = p.get('src_ip',''); dip = p.get('dst_ip',''); proto = p.get('proto','?')
        if sip:
            if sip not in src_stats: src_stats[sip] = {'protos':set(),'dsts':set(),'pkts':0}
            src_stats[sip]['protos'].add(proto); src_stats[sip]['dsts'].add(dip)
            src_stats[sip]['pkts'] += 1
    flow_str = '\n'.join(
        f'  {ip}: {v["pkts"]}pkts -> {len(v["dsts"])} dsts via {sorted(v["protos"])}'
        for ip,v in sorted(src_stats.items(), key=lambda x:x[1]['pkts'], reverse=True)[:10]
    ) or '  (none)'

    no_resp = l7.get('no_response', {})
    nr_str = '\n'.join(
        f'  {proto}: sent={s.get("sent",0)} replied={s.get("replied",0)} '
        f'loss={round((1-s.get("replied",0)/max(s.get("sent",1),1))*100,0):.0f}%'
        for proto,s in no_resp.items() if s.get('sent',0) > 0
    ) or '  (none)'

    prompt = (
        f"Step 1 result — suspicious: {step1.get('suspicious_protos',[])} | {step1.get('summary','N/A')}\n\n"
        f"Per-source flow stats:\n{flow_str}\n\n"
        f"TCP: SYN={l4.get('tcp_syn',0)} SYN-ACK={l4.get('tcp_synack',0)} "
        f"RST={l4.get('tcp_rst',0)} FIN={l4.get('tcp_fin',0)} "
        f"half-open={l4.get('half_open',0)} zero-win={l4.get('zero_window_count',0)}\n\n"
        f"ARP: completed={len(analysis.get('arp_completed',{}))} "
        f"unanswered={len(analysis.get('arp_unanswered',{}))}\n\n"
        f"No-response by protocol:\n{nr_str}\n\n"
        'Return JSON:\n'
        '{"sessions":[{"session_id":"s001","type":"completed|broken|one_way|attack",'
        '"protocol":"<proto>","src_ip":"<ip>","dst_ip":"<ip>","description":"<one sentence>","anomalous":false}],'
        '"broken_session_count":0,"one_way_flow_count":0,"attack_session_count":0,"summary":"<one sentence>"}\n'
        'Limit to 12 most significant sessions.'
    )
    result = _pipeline_parse_json(_pipeline_call_ai(_SYS_STEP2, prompt, 900))
    if isinstance(result, dict):
        print(f'  [pipeline]   -> {len(result.get("sessions",[]))} sessions '
              f'({result.get("broken_session_count",0)} broken, '
              f'{result.get("one_way_flow_count",0)} one-way, '
              f'{result.get("attack_session_count",0)} attack)')
        return result
    print('  [pipeline]   -> Step 2 failed, continuing')
    return {}


# ── Step 3: Anomaly Detection (AI-augmented) ──────────────────────────────────

_SYS_STEP3 = (
    "You are a senior network security analyst. "
    "You receive pre-computed rule/ML anomaly findings enriched with protocol classifications "
    "and reconstructed session data. "
    "Validate each finding, flag false positives, and detect missed anomalies. "
    "Output ONLY valid JSON — no prose, no markdown fences."
)

def _pipeline_step3_anomalies(features, analysis, rule_findings, step1, step2):
    """Step 3 — AI-Augmented Anomaly Detection. Returns dict or {}."""
    print('  [pipeline] Step 3: AI anomaly detection and validation...')
    l4 = features.get('l4', {}); l7 = features.get('l7', {})

    findings_str = '\n'.join(
        f'  [{f["severity"].upper():<8}] [{f.get("layer","?"):<6}] {f["title"]}'
        + (f' | {f.get("evidence","")[:70]}' if f.get('evidence') else '')
        for f in rule_findings[:25]
    ) or '  (no findings)'

    prompt = (
        f"Step 1 — Protocol: suspicious={step1.get('suspicious_protos',[])} | {step1.get('summary','N/A')}\n"
        f"Step 2 — Sessions: broken={step2.get('broken_session_count',0)} "
        f"one_way={step2.get('one_way_flow_count',0)} attack={step2.get('attack_session_count',0)} | "
        f"{step2.get('summary','N/A')}\n\n"
        f"Rule/ML findings ({len(rule_findings)} total):\n{findings_str}\n\n"
        f"Capture stats: pkts={features.get('total',0)} dur={features.get('duration',0):.1f}s "
        f"SYN={l4.get('tcp_syn',0)} SYN-ACK={l4.get('tcp_synack',0)} "
        f"RST={l4.get('tcp_rst',0)} half-open={l4.get('half_open',0)} "
        f"DNS-rate={l7.get('dns_query_rate',0):.1f}/s "
        f"DHCP-servers={l7.get('dhcp_servers',[])} starvation={l7.get('dhcp_starvation',False)}\n\n"
        'Return JSON:\n'
        '{"validated":[{"title":"<exact finding title>","confirmed":true,"severity":"Critical|High|Medium|Low|Info",'
        '"protocol":"<proto>","reason":"<one sentence>","missed_by_rules":false}],'
        '"new_findings":[{"title":"AI: <title>","severity":"High","protocol":"<proto>","layer":"L4",'
        '"detail":"<description>","evidence":"<stats>","confirmed":true,"missed_by_rules":true}],'
        '"false_positive_titles":["<title>"],'
        '"summary":"<one sentence>"}'
    )
    result = _pipeline_parse_json(_pipeline_call_ai(_SYS_STEP3, prompt, 1200))
    if isinstance(result, dict):
        confirmed = sum(1 for v in result.get('validated',[]) if v.get('confirmed'))
        print(f'  [pipeline]   -> {confirmed} confirmed, '
              f'{len(result.get("false_positive_titles",[]))} dismissed, '
              f'{len(result.get("new_findings",[]))} new AI findings')
        return result
    print('  [pipeline]   -> Step 3 failed, continuing')
    return {}


# ── Step 4: Root Cause + Next Actions ────────────────────────────────────────

_SYS_STEP4 = (
    "You are a senior network engineer with deep troubleshooting expertise. "
    "You receive a complete anomaly analysis from a multi-step AI pipeline. "
    "Synthesize confirmed findings into incidents with root causes and CLI remediation steps. "
    "Output ONLY valid JSON — no prose, no markdown fences."
)

def _pipeline_step4_rootcause(step1, step2, step3):
    """Step 4 — Root Cause + Next Actions. Returns dict or {}."""
    print('  [pipeline] Step 4: Root cause analysis + next actions...')

    proto_issues = '\n'.join(
        f'  [{c.get("confidence","?")}] {c.get("proto","?")} — {c.get("note","")}'
        for c in step1.get('classifications', [])
        if not c.get('expected', True) or c.get('port_mismatch')
    ) or '  (none)'

    confirmed_str = '\n'.join(
        f'  [{v.get("severity","?"):<8}] {v.get("title","?")} — {v.get("reason","")[:70]}'
        for v in step3.get('validated', []) if v.get('confirmed')
    ) or '  (none)'

    new_str = '\n'.join(
        f'  [{f.get("severity","?"):<8}] {f.get("title","?")} — {f.get("detail","")[:70]}'
        for f in step3.get('new_findings', [])
    ) or '  (none)'

    prompt = (
        f"Protocol issues (Step 1):\n{proto_issues}\n\n"
        f"Session findings (Step 2): broken={step2.get('broken_session_count',0)} "
        f"one-way={step2.get('one_way_flow_count',0)} attack={step2.get('attack_session_count',0)}\n\n"
        f"Confirmed anomalies (Step 3):\n{confirmed_str}\n\n"
        f"New AI findings (Step 3):\n{new_str}\n\n"
        f"False positives dismissed: {len(step3.get('false_positive_titles',[]))}\n\n"
        'Return JSON:\n'
        '{"incidents":[{"name":"<short name>","severity":"Critical|High|Medium|Low",'
        '"root_cause":"<precise one sentence>","affected_protocols":["<proto>"],'
        '"affected_hosts":["<ip>"],'
        '"next_actions":["<specific action with CLI command if applicable>"],'
        '"finding_titles":["<title>"]}],'
        '"narrative":"<2-3 sentence paragraph: what happened, how detected, risk level>",'
        '"risk_score":<0-100>,'
        '"priority_action":"<single most important action right now>"}\n'
        'Limit to 6 incidents. Merge related minor findings.'
    )
    result = _pipeline_parse_json(_pipeline_call_ai(_SYS_STEP4, prompt, 1200))
    if isinstance(result, dict):
        print(f'  [pipeline]   -> {len(result.get("incidents",[]))} incidents | '
              f'risk={result.get("risk_score","N/A")}/100')
        return result
    print('  [pipeline]   -> Step 4 failed, continuing')
    return {}


# ── Pipeline Orchestrator ─────────────────────────────────────────────────────

def _run_ai_pipeline(features, analysis, rule_findings):
    """
    Run Steps 1-4 sequentially, threading context forward.
    Graceful degradation: each step is optional.
    Returns unified dict consumed by detect_anomalies().
    """
    print('  [pipeline] Starting sequential AI pipeline (4 steps)...')
    step1 = _pipeline_step1_classify(features, analysis)
    step2 = _pipeline_step2_flows(features, analysis, step1)
    step3 = _pipeline_step3_anomalies(features, analysis, rule_findings, step1, step2)
    step4 = _pipeline_step4_rootcause(step1, step2, step3)
    print('  [pipeline] Pipeline complete.')
    return {
        'validated':             step3.get('validated', []),
        'new_findings':          step3.get('new_findings', []),
        'false_positive_titles': step3.get('false_positive_titles', []),
        'incidents':             step4.get('incidents', []),
        'narrative':             step4.get('narrative', step3.get('summary', '')),
        'risk_score':            step4.get('risk_score'),
        'priority_action':       step4.get('priority_action', ''),
        'step1': step1, 'step2': step2, 'step3': step3, 'step4': step4,
    }


# ── Main Anomaly Detection Orchestrator ──────────────────────────────────────

def detect_anomalies(packets, analysis):
    """Full hybrid anomaly detection pipeline: features → rules → ML → correlation → AI.
    Returns list of anomaly dicts and AI narrative."""
    print('  [anomaly] Extracting L2–L7 features...')
    features = _extract_features(packets, analysis)

    print('  [anomaly] Running rule engine...')
    rule_findings = _rule_engine(features, analysis)
    print(f'  [anomaly]   → {len(rule_findings)} rule-based findings')

    print('  [anomaly] Running ML scoring...')
    ml_findings = _ml_score(features)
    print(f'  [anomaly]   → {len(ml_findings)} ML-scored findings')

    print('  [anomaly] Cross-layer correlation...')
    cross_findings = _cross_layer_correlate(rule_findings, ml_findings, features, analysis)
    print(f'  [anomaly]   → {len(cross_findings)} cross-layer findings')

    all_findings = rule_findings + ml_findings + cross_findings

    # Deduplicate: same title should not appear twice
    seen_titles = set()
    deduped = []
    for f in all_findings:
        if f['title'] not in seen_titles:
            seen_titles.add(f['title'])
            deduped.append(f)
    all_findings = deduped

    # Sort by severity
    all_findings.sort(key=lambda f: _SEV_ORDER.get(f['severity'], 0), reverse=True)

    # ── Sequential AI Pipeline (Steps 1-4) ──────────────────────────────────
    ai_narrative    = ''
    ai_risk_score   = None
    ai_pipeline_out = {}
    priority_action = ''
    incidents       = []

    print('  [anomaly] Running sequential AI pipeline (4 steps)...')
    ai_pipeline_out = _run_ai_pipeline(features, analysis, all_findings)

    ai_narrative    = ai_pipeline_out.get('narrative', '')
    ai_risk_score   = ai_pipeline_out.get('risk_score')
    priority_action = ai_pipeline_out.get('priority_action', '')
    incidents       = ai_pipeline_out.get('incidents') or []

    # Apply Step 3 validations to existing findings
    fp_titles = set(ai_pipeline_out.get('false_positive_titles') or [])
    validated_map = {v['title']: v for v in (ai_pipeline_out.get('validated') or [])
                     if isinstance(v, dict)}
    for f in all_findings:
        v = validated_map.get(f['title'])
        if v:
            f['ai_confirmed'] = v.get('confirmed', True)
            f['ai_reason']    = v.get('reason', '')
            f['ai_mitigation'] = ''
            ai_sev = v.get('severity', '').lower()
            if ai_sev in _SEV_ORDER:
                f['severity'] = ai_sev
        if f['title'] in fp_titles:
            f['ai_confirmed'] = False
            f['ai_reason']    = 'Dismissed by AI: likely false positive in context'

    # Inject Step 3 new AI-detected findings
    for nf in ai_pipeline_out.get('new_findings', []):
        if not isinstance(nf, dict):
            continue
        title = nf.get('title', '')
        if title and title not in seen_titles:
            seen_titles.add(title)
            all_findings.append({
                'category':    nf.get('protocol', 'AI'),
                'layer':       nf.get('layer', 'AI'),
                'title':       title,
                'severity':    nf.get('severity', SEV_MEDIUM).lower(),
                'detail':      nf.get('detail', ''),
                'evidence':    nf.get('evidence', ''),
                'ai_confirmed': True,
                'ai_reason':   'Detected by sequential AI pipeline — missed by rule engine',
                'ai_mitigation': '',
            })

    # Re-sort after injections
    all_findings.sort(key=lambda f: _SEV_ORDER.get(f['severity'], 0), reverse=True)

    if ai_risk_score is not None:
        print(f'  [anomaly]   → Pipeline complete | risk score: {ai_risk_score}/100')
        if priority_action:
            print(f'  [anomaly]   → Priority: {priority_action[:80]}')
    else:
        print('  [anomaly]   → AI pipeline produced no risk score (AI may be unavailable)')

    total = len(all_findings)
    crit = sum(1 for f in all_findings if f['severity'] == SEV_CRITICAL)
    high = sum(1 for f in all_findings if f['severity'] == SEV_HIGH)
    print(f'  [anomaly] Complete: {total} findings ({crit} critical, {high} high)')

    return {
        'findings': all_findings,
        'features': features,
        'ai_narrative': ai_narrative,
        'ai_risk_score': ai_risk_score,
        'priority_action': priority_action,
        'incidents': incidents,
        'ai_pipeline': ai_pipeline_out,
        'summary': {
            'total': total,
            'critical': crit,
            'high': high,
            'medium': sum(1 for f in all_findings if f['severity'] == SEV_MEDIUM),
            'low': sum(1 for f in all_findings if f['severity'] == SEV_LOW),
            'info': sum(1 for f in all_findings if f['severity'] == SEV_INFO),
        },
    }


# ── Anomaly HTML Renderer ───────────────────────────────────────────────────

_SEV_COLORS = {
    SEV_CRITICAL: '#ef4444',
    SEV_HIGH: '#f97316',
    SEV_MEDIUM: '#f59e0b',
    SEV_LOW: '#3b82f6',
    SEV_INFO: '#6b7280',
}
_SEV_ICONS = {
    SEV_CRITICAL: '🔴',
    SEV_HIGH: '🟠',
    SEV_MEDIUM: '🟡',
    SEV_LOW: '🔵',
    SEV_INFO: 'ℹ️',
}

def _render_anom_html(anomaly_result):
    """Render anomaly detection results as dashboard-ready HTML.
    Shows: risk score → priority action → incidents → AI narrative → findings."""
    if not anomaly_result or not anomaly_result.get('findings'):
        return '<div class="ok-row"><span>✓</span><span>No anomalies detected — traffic looks normal</span></div>'

    findings        = anomaly_result['findings'] or []
    summary         = anomaly_result.get('summary') or {}
    narrative       = anomaly_result.get('ai_narrative', '')
    risk_score      = anomaly_result.get('ai_risk_score')
    priority_action = anomaly_result.get('priority_action', '')
    incidents       = anomaly_result.get('incidents') or []

    html = ''

    # ── Summary badges + risk score ───────────────────────────────────────────
    html += '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center">'
    for sev_key, label in [(SEV_CRITICAL,'Critical'),(SEV_HIGH,'High'),(SEV_MEDIUM,'Medium'),(SEV_LOW,'Low')]:
        cnt = summary.get(sev_key, 0)
        if cnt > 0:
            html += (f'<span class="badge" style="background:{_SEV_COLORS[sev_key]};'
                     f'font-size:11px;padding:3px 8px">{cnt} {label}</span>')
    if risk_score is not None:
        rc = '#ef4444' if risk_score > 70 else '#f59e0b' if risk_score > 40 else '#10b981'
        html += (f'<span class="badge" style="background:{rc};font-size:11px;'
                 f'padding:3px 8px;margin-left:auto">Risk Score: {risk_score}/100</span>')
    html += '</div>'

    # ── Priority action (Step 4) ──────────────────────────────────────────────
    if priority_action:
        html += (
            f'<div style="background:#1a0a0a;border:1px solid #ef4444;border-radius:6px;'
            f'padding:8px 12px;margin-bottom:10px;font-size:12px;'
            f'display:flex;gap:8px;align-items:flex-start">'
            f'<span style="color:#ef4444;font-size:16px;flex-shrink:0">⚡</span>'
            f'<div><strong style="color:#ef4444">Priority Action:</strong> '
            f'<span style="color:#fca5a5">{priority_action}</span></div>'
            f'</div>'
        )

    # ── Incidents panel (Step 4) ──────────────────────────────────────────────
    if incidents:
        _INC_COLORS = {'Critical':'#ef4444','High':'#f97316','Medium':'#f59e0b','Low':'#3b82f6'}
        html += ('<div style="margin-bottom:12px">'
                 '<div style="font-size:11px;color:#6b7280;margin-bottom:6px;'
                 'text-transform:uppercase;letter-spacing:0.05em">📋 Incident Summary</div>')
        for inc in incidents[:5]:
            inc_sev   = inc.get('severity', 'Medium')
            inc_color = _INC_COLORS.get(inc_sev, '#6b7280')
            actions_html = ''.join(
                f'<li style="margin:2px 0;color:#94a3b8;font-size:11px">{a}</li>'
                for a in (inc.get('next_actions') or [])
            )
            hosts  = ', '.join((inc.get('affected_hosts') or [])[:3])
            protos = ', '.join((inc.get('affected_protocols') or [])[:4])
            html += (
                f'<div style="background:#0f172a;border:1px solid {inc_color}33;'
                f'border-left:3px solid {inc_color};border-radius:6px;'
                f'padding:8px 12px;margin-bottom:6px">'
                f'<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">'
                f'<span class="badge" style="background:{inc_color};font-size:9px;padding:1px 5px">'
                f'{inc_sev}</span>'
                f'<strong style="font-size:12px;color:#e2e8f0">{inc.get("name","Incident")}</strong>'
                + (f'<span style="margin-left:auto;font-size:10px;color:#475569">{protos}</span>' if protos else '') +
                f'</div>'
                + (f'<div style="font-size:11px;color:#f59e0b;margin-bottom:3px">'
                   f'Root cause: {inc.get("root_cause","")}</div>'
                   if inc.get('root_cause') else '') +
                (f'<div style="font-size:10px;color:#64748b;margin-bottom:4px">Hosts: {hosts}</div>' if hosts else '') +
                (f'<ul style="margin:4px 0 0 12px;padding:0">{actions_html}</ul>' if actions_html else '') +
                f'</div>'
            )
        html += '</div>'

    # ── AI narrative (Step 4) ─────────────────────────────────────────────────
    if narrative:
        html += (
            f'<div style="background:var(--card-bg,#1a1f2e);border-left:3px solid #8b5cf6;'
            f'padding:8px 12px;margin-bottom:10px;border-radius:4px;font-size:12px;'
            f'color:var(--txt-muted,#94a3b8)">'
            f'<strong style="color:#8b5cf6">🤖 AI Analysis:</strong> {narrative}</div>'
        )

    # ── Individual findings ───────────────────────────────────────────────────
    dismissed_f = [f for f in findings if f.get('ai_confirmed') is False]
    active_f    = [f for f in findings if f.get('ai_confirmed') is not False]

    for f in active_f[:25]:
        sev   = f['severity']
        icon  = _SEV_ICONS.get(sev, '⚠')
        color = _SEV_COLORS.get(sev, '#6b7280')

        ai_badge = ''
        if f.get('ai_confirmed') is True:
            badge_label = '★ AI-detected' if f.get('title','').startswith('AI:') else '✓ AI confirmed'
            badge_color = '#8b5cf6' if f.get('title','').startswith('AI:') else '#10b981'
            ai_badge = f' <span style="color:{badge_color};font-size:10px">{badge_label}</span>'

        reason_html = ''
        if f.get('ai_reason'):
            reason_html = (f'<div style="color:#64748b;font-size:10px;margin-top:2px;font-style:italic">'
                           f'AI: {f["ai_reason"]}</div>')

        mit_html = ''
        if f.get('ai_mitigation'):
            mit_html = (f'<div style="color:#10b981;font-size:10px;margin-top:2px">'
                        f'💡 {f["ai_mitigation"]}</div>')

        html += (
            f'<div class="anom-row" style="border-left:3px solid {color};padding-left:8px;margin-bottom:6px">'
            f'<div style="display:flex;align-items:center;gap:6px">'
            f'<span style="font-size:14px">{icon}</span>'
            f'<span class="badge sm" style="background:{color};font-size:9px;padding:1px 5px">{f["layer"]}</span>'
            f'<strong style="font-size:12px">{f["title"]}</strong>{ai_badge}'
            f'</div>'
            f'<div style="font-size:11px;color:var(--txt-muted,#94a3b8);margin-top:2px">{f["detail"]}</div>'
            f'{reason_html}{mit_html}'
            f'</div>'
        )

    if len(active_f) > 25:
        html += f'<div class="muted sm" style="padding:4px 0">… and {len(active_f)-25} more findings</div>'

    # Collapsed dismissed section
    if dismissed_f:
        dismissed_rows = ''.join(
            f'<div style="font-size:11px;color:#475569;padding:2px 0;opacity:0.6">'
            f'⚪ {f["title"]}</div>'
            for f in dismissed_f
        )
        html += (
            f'<details style="margin-top:8px">'
            f'<summary style="font-size:11px;color:#475569;cursor:pointer">'
            f'{len(dismissed_f)} finding(s) dismissed as false positives by AI</summary>'
            f'<div style="padding:6px 0">{dismissed_rows}</div>'
            f'</details>'
        )

    return html


# ── Analysis ──────────────────────────────────────────────────────────────────

def analyse(packets):
    pc={}; src_ips={}; dst_ips={}; services={}
    arp=[]; icmp=[]; tcp=[]; udp=[]; other=[]
    proto_buckets={}
    
    # Application-layer protocols derived from underlying transport
    TCP_APP_PROTOS = {'FTP', 'FTP-Data', 'SSH', 'Telnet', 'SMTP', 'SMTPS', 'HTTP', 'HTTPS', 
                      'HTTP-Alt', 'HTTPS-Alt', 'POP3', 'POP3S', 'IMAP', 'IMAPS', 'LDAP', 'LDAPS',
                      'SMB', 'NetBIOS-SSN', 'RDP', 'SIP', 'SIPS', 'MSSQL', 'Oracle', 'MySQL', 
                      'PostgreSQL', 'MongoDB', 'Redis', 'VNC', 'Kerberos'}
    UDP_APP_PROTOS = {'DNS', 'DHCP-Server', 'DHCP-Client', 'TFTP', 'NBNS', 'NetBIOS-DGM',
                      'NTP', 'SNMP', 'SNMP-Trap', 'Syslog', 'RIP', 'OpenVPN', 'RTP', 'SIP'}

    for p in packets:
        proto = p.get('proto','?')
        pc[proto] = pc.get(proto,0)+1
        
        # Categorize into main buckets (for analysis)
        if proto == 'ARP':
            arp.append(p)
        elif proto == 'ICMP':
            icmp.append(p)
        elif proto in TCP_APP_PROTOS or proto == 'TCP':
            tcp.append(p)
        elif proto in UDP_APP_PROTOS or proto == 'UDP':
            udp.append(p)
        else:
            other.append(p)
        
        proto_buckets.setdefault(proto,[]).append(p)
        if p.get('src_ip'): src_ips[p['src_ip']] = src_ips.get(p['src_ip'],0)+1
        if p.get('dst_ip'): dst_ips[p['dst_ip']] = dst_ips.get(p['dst_ip'],0)+1
        if p.get('service'): services[p['service']] = services.get(p['service'],0)+1

    # ARP pair analysis
    arp_reqs = sum(1 for p in arp if p.get('arp_op')=='REQUEST')
    arp_reps = sum(1 for p in arp if p.get('arp_op')=='REPLY')
    arp_pairs = {}
    for p in arp:
        op = p.get('arp_op','')
        if op == 'REQUEST': key = (p.get('src_ip','?'), p.get('dst_ip','?'))
        elif op == 'REPLY':  key = (p.get('dst_ip','?'), p.get('src_ip','?'))
        else: key = (p.get('src_ip','?'), p.get('dst_ip','?'))
        if key not in arp_pairs: arp_pairs[key] = {'req':0,'rep':0,'req_mac':'','rep_mac':''}
        if op == 'REQUEST': arp_pairs[key]['req']+=1; arp_pairs[key]['req_mac']=p.get('arp_src_mac','')
        elif op == 'REPLY':  arp_pairs[key]['rep']+=1; arp_pairs[key]['rep_mac']=p.get('arp_src_mac','')
    arp_completed  = {k:v for k,v in arp_pairs.items() if v['req']>0 and v['rep']>0}
    arp_unanswered = {k:v for k,v in arp_pairs.items() if v['req']>0 and v['rep']==0}
    arp_gratuitous = [p for p in arp if p.get('arp_op')=='REPLY' and p.get('src_ip')==p.get('dst_ip')]

    # TCP breakdown
    tcp_syn    = sum(1 for p in tcp if p.get('tcp_flags','')=='SYN')
    tcp_synack = sum(1 for p in tcp if 'SYN' in p.get('tcp_flags','') and 'ACK' in p.get('tcp_flags',''))
    tcp_ack    = sum(1 for p in tcp if p.get('tcp_flags','')=='ACK')
    tcp_psh    = sum(1 for p in tcp if 'PSH' in p.get('tcp_flags',''))
    tcp_fin    = sum(1 for p in tcp if 'FIN' in p.get('tcp_flags',''))
    tcp_rst    = sum(1 for p in tcp if 'RST' in p.get('tcp_flags',''))

    # ICMP breakdown
    icmp_req  = sum(1 for p in icmp if p.get('icmp_type')==8)
    icmp_rep  = sum(1 for p in icmp if p.get('icmp_type')==0)
    icmp_unr  = sum(1 for p in icmp if p.get('icmp_type')==3)
    icmp_ttl  = sum(1 for p in icmp if p.get('icmp_type')==11)

    total_bytes = sum(p.get('frame_len',0) for p in packets)
    proto_bytes = {}
    for p in packets:
        pr = p.get('proto','?')
        proto_bytes[pr] = proto_bytes.get(pr,0) + p.get('frame_len',0)

    # ── SNMP Trap analysis ──────────────────────────────────────────────────
    trap_analysis = {}
    try:
        from snmp_trap_analyzer import parse_trap_packets, analyse_traps as _analyse_traps
        _trap_session = parse_trap_packets(packets)
        trap_analysis = _analyse_traps(_trap_session)
    except Exception:
        pass

    # ── Build partial result for anomaly engine ─────────────────────────────
    _partial = {
        'total':len(packets), 'proto_counts':pc,
        'arp':arp,'icmp':icmp,'tcp':tcp,'udp':udp,'other':other,
        'proto_buckets':proto_buckets,
        'src_ips':dict(sorted(src_ips.items(),key=lambda x:x[1],reverse=True)[:10]),
        'dst_ips':dict(sorted(dst_ips.items(),key=lambda x:x[1],reverse=True)[:10]),
        'services':services,'all_packets':packets,
        'arp_reqs_total':arp_reqs,'arp_reps_total':arp_reps,
        'arp_pairs':arp_pairs,'arp_completed':arp_completed,
        'arp_unanswered':arp_unanswered,'arp_gratuitous':arp_gratuitous,
        'tcp_syn':tcp_syn,'tcp_synack':tcp_synack,'tcp_ack':tcp_ack,
        'tcp_psh':tcp_psh,'tcp_fin':tcp_fin,'tcp_rst':tcp_rst,
        'icmp_req':icmp_req,'icmp_rep':icmp_rep,'icmp_unr':icmp_unr,'icmp_ttl':icmp_ttl,
        'total_bytes':total_bytes,'proto_bytes':proto_bytes,
    }

    # ── Hybrid Anomaly Detection (L2–L7) ────────────────────────────────────
    anomaly_result = detect_anomalies(packets, _partial)
    # Legacy compat: flat list of anomaly strings for old code paths
    anom = [f['title'] for f in anomaly_result.get('findings', [])]

    _partial['anomalies'] = anom
    _partial['anomaly_result'] = anomaly_result
    _partial['trap_analysis'] = trap_analysis
    return _partial

# ═══════════════════════════════════════════════════════════════════════════════
#  EMBEDDED RAG ENGINE  (knowledge_retriever — inline, no external file needed)
#
#  Architecture:
#    _BUILTIN_KB        — static protocol/RFC knowledge dictionary (EAPoL, RADIUS,
#                         ARP, STP, LLDP, TCP, ICMP, DHCP, DNS, SNMP, OSPF, BGP,
#                         VLAN, LACP, IGMP, IPv6, NTP, VRRP + EXOS CLI references)
#    _EmbeddedKB        — loads _BUILTIN_KB + merges any user files from
#                         knowledge_base/ directory alongside this script
#    _TFIDFIndex        — zero-dependency cosine-similarity retriever over TF-IDF
#                         vectors; upgrades to sentence-transformers if installed
#    _RAGRetriever      — singleton wrapper: builds index on first call, then fast
#                         in-memory lookups on every subsequent call
#    retrieve_context() — public function called by ask_ai(); returns a formatted
#                         grounding-context string injected before every AI prompt
#
#  Usage (called automatically by ask_ai()):
#    ctx = retrieve_context(['EAPoL', 'RADIUS', 'TCP'], extra_query='timeout')
#    prompt = ctx + "\n\n## User Query\n\n" + user_question
# ═══════════════════════════════════════════════════════════════════════════════
# Aliases used locally in this module section
_math    = math
_hashlib = hashlib

# ── Built-in knowledge base ────────────────────────────────────────────────────
_BUILTIN_KB: dict = {
    "_meta": {"version": 2, "built": "2025-01-01"},
    "EAPoL": {
        "rfc": "IEEE 802.1X", "layer": "L2",
        "aliases": ["802.1X", "8021X", "dot1x", "netlogin"],
        "chunks": [
            {"id": "EAPoL_overview", "title": "EAPoL / 802.1X Overview",
             "text": ("EAP over LAN (EAPoL) is defined by IEEE 802.1X and provides port-based "
                      "network access control. A supplicant (client) must authenticate to an "
                      "authenticator (switch) before the port is opened. The authenticator "
                      "forwards EAP messages to a RADIUS authentication server. "
                      "Packet types: 0=EAP-Packet, 1=EAPOL-Start, 2=EAPOL-Logoff, 3=EAPOL-Key. "
                      "EAP methods include EAP-TLS (certificate), PEAP, EAP-MD5, EAP-FAST."),
             "tags": ["802.1X", "NAC", "authentication", "supplicant"],
             "source": "IEEE 802.1X-2020"},
            {"id": "EAPoL_handshake", "title": "EAPoL 4-Step Handshake",
             "text": ("802.1X authentication flow: "
                      "1) Supplicant sends EAPOL-Start (or switch sends EAP-Request/Identity on link-up). "
                      "2) Switch sends EAP-Request/Identity to supplicant. "
                      "3) Supplicant replies EAP-Response/Identity. "
                      "4) Switch proxies to RADIUS server (Access-Request). "
                      "5) RADIUS sends EAP challenge (Access-Challenge). "
                      "6) Supplicant responds to challenge. "
                      "7) RADIUS sends Access-Accept or Access-Reject. "
                      "8) Switch sends EAP-Success or EAP-Failure, opens/blocks port. "
                      "Reauthentication: switch sends EAP-Request after session-timeout. "
                      "Timeout: if supplicant doesn't respond within retransmission window, "
                      "switch retransmits EAP-Request up to max-reauth-req times then sends EAP-Failure."),
             "tags": ["EAP", "handshake", "RADIUS", "authentication"],
             "source": "IEEE 802.1X-2020 §8"},
            {"id": "EAPoL_exos", "title": "EXOS 802.1X / NetLogin Configuration",
             "text": ("EXOS Switch Engine commands for 802.1X (NetLogin): "
                      "  enable netlogin dot1x                    -- enable 802.1X globally "
                      "  configure netlogin dot1x timers          -- set auth/quiet/tx timers "
                      "  configure netlogin radius primary        -- set RADIUS server "
                      "  configure netlogin radius reauthentication [enable|disable] "
                      "  show netlogin                            -- global status "
                      "  show netlogin port <port>               -- per-port auth state "
                      "  show netlogin session                   -- active sessions "
                      "  clear netlogin state port <port>        -- force reauthentication "
                      "Key timers: quiet-period (30s), tx-period (30s), supp-timeout (30s), "
                      "server-timeout (30s), max-req (2), reauth-period (3600s)."),
             "tags": ["EXOS", "netlogin", "dot1x", "CLI", "configuration"],
             "source": "Switch Engine v33.6.1 User Guide — Network Login"},
            {"id": "EAPoL_timing_race", "title": "EAPoL Timing Race Condition",
             "text": ("Common timing issue: After 'configure netlogin radius reauthentication resume', "
                      "the switch immediately sends EAP-Request/Identity. If the supplicant is not "
                      "yet ready the EAP-Request is missed and the switch enters quiet-period. "
                      "Fix: Add a delay in the supplicant before sending EAPOL-Start after resume, "
                      "OR use a passive receive loop: listen for EAP-Request from switch rather "
                      "than sending EAPOL-Start proactively."),
             "tags": ["timing", "race condition", "reauthentication", "quiet-period"],
             "source": "Internal EXOS automation runbook"},
        ]
    },
    "RADIUS": {
        "rfc": "RFC 2865", "layer": "L7",
        "aliases": ["RADIUS-Auth", "RADIUS-Acct", "AAA"],
        "chunks": [
            {"id": "RADIUS_overview", "title": "RADIUS Protocol Overview",
             "text": ("RADIUS (Remote Authentication Dial-In User Service) defined in RFC 2865. "
                      "Transport: UDP port 1812 (auth), 1813 (accounting), 3799 (CoA/Disconnect). "
                      "Packet types: Access-Request(1), Access-Accept(2), Access-Reject(3), "
                      "Access-Challenge(11), Accounting-Request(4), Accounting-Response(5). "
                      "RADIUS CoA (RFC 5176): dynamic authorisation, disconnect-message. "
                      "NAS-IP-Address (attr 4), User-Name (attr 1), EAP-Message (attr 79), "
                      "Message-Authenticator (attr 80) required for EAP."),
             "tags": ["RADIUS", "AAA", "authentication", "RFC 2865", "UDP 1812"],
             "source": "RFC 2865, RFC 2866"},
            {"id": "RADIUS_exos", "title": "EXOS RADIUS Configuration",
             "text": ("EXOS RADIUS commands: "
                      "  configure radius primary server <IP> <port> shared-secret <secret> vr VR-Default "
                      "  configure radius timeout <seconds>       -- default 3s "
                      "  configure radius retransmit <count>      -- default 3 retries "
                      "  show radius                              -- server config and statistics "
                      "  show radius statistics                   -- access-accept/reject/challenge counts "
                      "  show netlogin dot1x counters             -- per-port RADIUS exchange counts "
                      "RADIUS failure mode: configure netlogin fail-safe to allow or block port."),
             "tags": ["EXOS", "RADIUS", "CLI", "configuration", "timeout"],
             "source": "Switch Engine v33.6.1 User Guide — RADIUS"},
        ]
    },
    "ARP": {
        "rfc": "RFC 826", "layer": "L2",
        "aliases": ["arp", "address resolution"],
        "chunks": [
            {"id": "ARP_overview", "title": "ARP Protocol",
             "text": ("Address Resolution Protocol (RFC 826). Maps IPv4 addresses to MAC addresses. "
                      "ARP Request: broadcast (ff:ff:ff:ff:ff:ff), opcode=1, 'Who has <IP>? Tell <sender>'. "
                      "ARP Reply: unicast, opcode=2. "
                      "Gratuitous ARP: sender IP == target IP, used for IP conflict detection and "
                      "to update ARP caches after failover (VRRP, MLAG). "
                      "ARP poisoning: attacker sends gratuitous ARP to redirect traffic (MITM). "
                      "Stale ARP: cached entry no longer valid — causes routing black holes."),
             "tags": ["ARP", "RFC 826", "MAC", "IP", "gratuitous ARP"],
             "source": "RFC 826"},
            {"id": "ARP_exos", "title": "EXOS ARP Commands",
             "text": ("EXOS ARP commands: "
                      "  show iparp                     -- ARP table "
                      "  show iparp statistics           -- request/reply counts "
                      "  clear iparp                    -- flush ARP table "
                      "  configure iparp timeout <min>  -- default 20 min "
                      "  configure iparp-inspection     -- dynamic ARP inspection (DAI) "
                      "ARP anomalies: same IP with multiple MACs indicates ARP spoofing."),
             "tags": ["EXOS", "ARP", "CLI", "DAI"],
             "source": "Switch Engine v33.6.1 — ARP"},
        ]
    },
    "STP": {
        "rfc": "IEEE 802.1D", "layer": "L2",
        "aliases": ["RSTP", "spanning-tree", "loop prevention"],
        "chunks": [
            {"id": "STP_overview", "title": "STP / RSTP Overview",
             "text": ("Spanning Tree Protocol (IEEE 802.1D) prevents L2 loops. "
                      "RSTP (IEEE 802.1w) converges in 1-2 seconds vs STP's 30-50 seconds. "
                      "Port states: Discarding, Learning, Forwarding. "
                      "Topology Change (TC): BPDUs flooded when port goes Forwarding — causes "
                      "MAC table flush. TCN storm: rapid TCs (>5/sec) indicate instability. "
                      "BPDU Guard: disable port if BPDU received on edge port."),
             "tags": ["STP", "RSTP", "loop", "topology change"],
             "source": "IEEE 802.1D-2004"},
            {"id": "STP_exos", "title": "EXOS STP Commands",
             "text": ("EXOS spanning tree commands: "
                      "  show stpd                            -- all STP domains "
                      "  show stpd <domain> ports             -- per-port STP state "
                      "  show stpd detail                     -- topology change counters "
                      "  configure stpd <domain> mode [802.1d|802.1w|802.1s] "
                      "  enable stpd edge-safeguard ports <port>  -- BPDU guard "
                      "Topology change storm: check 'show stpd detail' for TC count."),
             "tags": ["EXOS", "STP", "CLI", "topology change"],
             "source": "Switch Engine v33.6.1 — STP"},
        ]
    },
    "LLDP": {
        "rfc": "IEEE 802.1AB", "layer": "L2",
        "aliases": ["link-layer discovery", "LLDP-MED"],
        "chunks": [
            {"id": "LLDP_overview", "title": "LLDP Protocol",
             "text": ("Link Layer Discovery Protocol (IEEE 802.1AB). Devices advertise identity "
                      "and capabilities to directly-connected neighbours. "
                      "Multicast destination: 01:80:C2:00:00:0E. "
                      "TLVs: Chassis ID, Port ID, TTL, System Name, System Description. "
                      "LLDP-MED: Network Policy TLV carries VLAN+DSCP for VoIP phones. "
                      "Sent every 30s by default. TTL = hold-time (typically 120s)."),
             "tags": ["LLDP", "discovery", "topology", "LLDP-MED"],
             "source": "IEEE 802.1AB-2016"},
            {"id": "LLDP_exos", "title": "EXOS LLDP Commands",
             "text": ("EXOS LLDP commands: "
                      "  enable lldp ports all              -- enable LLDP "
                      "  show lldp neighbors                -- all discovered neighbours "
                      "  show lldp port <port> neighbors detail "
                      "  configure lldp-med network-policy voice vlan <id> dscp <n> "
                      "Common issue: LLDP neighbor missing — check if LLDP is enabled "
                      "on the port and if holdtime has expired."),
             "tags": ["EXOS", "LLDP", "CLI", "LLDP-MED"],
             "source": "Switch Engine v33.6.1 — LLDP"},
        ]
    },
    "TCP": {
        "rfc": "RFC 793", "layer": "L4",
        "aliases": ["TCP/IP", "transmission control"],
        "chunks": [
            {"id": "TCP_states", "title": "TCP State Machine and Flags",
             "text": ("TCP (RFC 793) is a reliable, connection-oriented transport protocol. "
                      "3-way handshake: SYN → SYN-ACK → ACK. "
                      "RST: abrupt connection reset — caused by port closed, firewall, or OS terminating. "
                      "RST storm indicates service rejection or DoS. "
                      "SYN flood: many SYN without completing handshake — half-open exhaustion. "
                      "Zero window: receiver's buffer full — backpressure stall. "
                      "TCP retransmission: segment not ACKed within RTO → retransmit (exponential backoff). "
                      "Port scan: single source hitting many destination ports."),
             "tags": ["TCP", "SYN", "RST", "handshake", "port scan"],
             "source": "RFC 793"},
        ]
    },
    "ICMP": {
        "rfc": "RFC 792", "layer": "L3",
        "aliases": ["ping", "traceroute"],
        "chunks": [
            {"id": "ICMP_types", "title": "ICMP Types and Meanings",
             "text": ("ICMP (RFC 792) provides error reporting and diagnostics for IP. "
                      "Type 0: Echo Reply. Type 3: Destination Unreachable "
                      "(Code 0=Net, 1=Host, 2=Protocol, 3=Port, 4=Fragmentation Needed). "
                      "Type 5: Redirect. Type 8: Echo Request. "
                      "Type 11: Time Exceeded — Code 0=TTL expired (traceroute), "
                      "Code 1=Fragment reassembly timeout. "
                      "ICMP type 3/code 4 (Fragmentation Needed): MTU mismatch — "
                      "check 'configure ports <port> mtu' on EXOS."),
             "tags": ["ICMP", "ping", "traceroute", "MTU", "unreachable"],
             "source": "RFC 792"},
        ]
    },
    "DHCP": {
        "rfc": "RFC 2131", "layer": "L7",
        "aliases": ["DHCP-Server", "DHCP-Client", "dynamic host"],
        "chunks": [
            {"id": "DHCP_flow", "title": "DHCP DORA Process",
             "text": ("DHCP (RFC 2131) dynamically assigns IP addresses. "
                      "DORA: Discover → Offer → Request → ACK. "
                      "Discover: broadcast (src=0.0.0.0, dst=255.255.255.255, UDP src=68, dst=67). "
                      "NAK: server declines request. "
                      "Rogue DHCP server: use DHCP Snooping to prevent. "
                      "DHCP starvation: attacker sends many Discovers with spoofed MACs. "
                      "Lease renewal: client unicasts Request at T1 (50% of lease)."),
             "tags": ["DHCP", "DORA", "rogue DHCP", "starvation", "snooping"],
             "source": "RFC 2131"},
            {"id": "DHCP_exos", "title": "EXOS DHCP Snooping",
             "text": ("EXOS DHCP commands: "
                      "  enable dhcp-snooping                   -- prevent rogue DHCP "
                      "  configure dhcp-snooping trust port <p> -- trust uplink ports "
                      "  show dhcp-client                       -- client leases "
                      "  show dhcpv4 server statistics          -- offer/ack/nak counts "
                      "DHCP relay: 'configure bootprelay add <server-IP> vlan <name>'."),
             "tags": ["EXOS", "DHCP", "snooping", "relay", "CLI"],
             "source": "Switch Engine v33.6.1 — DHCP"},
        ]
    },
    "DNS": {
        "rfc": "RFC 1035", "layer": "L7",
        "aliases": ["domain name", "name resolution"],
        "chunks": [
            {"id": "DNS_overview", "title": "DNS Protocol",
             "text": ("DNS (RFC 1035) resolves domain names to IP addresses. "
                      "UDP port 53 for queries, TCP port 53 for zone transfers. "
                      "Query types: A, AAAA, CNAME, MX, PTR, NS, SOA, TXT. "
                      "NXDOMAIN: domain does not exist. "
                      "DNS tunneling: data exfiltration via high-entropy subdomains. "
                      "DGA: malware generating pseudo-random domains — high NXDOMAIN ratio. "
                      "DNS amplification: small query causes large response — DDoS reflection."),
             "tags": ["DNS", "NXDOMAIN", "tunneling", "DGA", "amplification"],
             "source": "RFC 1035"},
        ]
    },
    "SNMP": {
        "rfc": "RFC 3411", "layer": "L7",
        "aliases": ["SNMP-Trap", "MIB", "network management"],
        "chunks": [
            {"id": "SNMP_overview", "title": "SNMP Protocol",
             "text": ("SNMP (RFC 3411) monitors and manages network devices. "
                      "UDP port 161 (queries), 162 (traps). "
                      "PDU types: GetRequest, GetNextRequest, GetBulkRequest, SetRequest, Trap. "
                      "SNMPv1/v2c: community string (plaintext). "
                      "SNMPv3: authentication (MD5/SHA) and encryption (DES/AES). "
                      "SNMP Trap: unsolicited notification (link up/down, threshold crossed)."),
             "tags": ["SNMP", "MIB", "trap", "community"],
             "source": "RFC 3411-3418"},
            {"id": "SNMP_exos", "title": "EXOS SNMP Configuration",
             "text": ("EXOS SNMP commands: "
                      "  configure snmp community readwrite <name> "
                      "  configure snmpv3 add user <name> authentication md5/sha ... "
                      "  configure snmp trap receiver <IP> community <name> "
                      "  show snmp statistics                      -- packet counters "
                      "MIB walk: 'snmpwalk -v 2c -c <community> <switch-IP> 1.3.6.1'"),
             "tags": ["EXOS", "SNMP", "CLI", "trap", "SNMPv3"],
             "source": "Switch Engine v33.6.1 — SNMP"},
        ]
    },
    "OSPF": {
        "rfc": "RFC 2328", "layer": "L3",
        "aliases": ["OSPFv2", "OSPFv3", "link-state routing"],
        "chunks": [
            {"id": "OSPF_overview", "title": "OSPF Overview",
             "text": ("OSPF (RFC 2328) is a link-state routing protocol. "
                      "Multicast: 224.0.0.5 (all OSPF routers). IP protocol 89. "
                      "Adjacency states: Down → Init → 2-Way → ExStart → Exchange → Loading → Full. "
                      "Hello interval: 10s on broadcast. Dead interval: 4x hello. "
                      "Neighbour stuck in Exstart: MTU mismatch. "
                      "Neighbour flapping: link instability or hello timer mismatch."),
             "tags": ["OSPF", "routing", "adjacency", "LSA"],
             "source": "RFC 2328"},
            {"id": "OSPF_exos", "title": "EXOS OSPF Commands",
             "text": ("EXOS OSPF commands: "
                      "  enable ospf                               -- enable OSPF "
                      "  enable ospf on vlan <name>               -- enable on interface "
                      "  show ospf neighbor                        -- adjacency table "
                      "  show ospf lsdb                           -- link-state database "
                      "OSPF not forming adjacency: check 'show ospf interface' for "
                      "hello/dead timer mismatch or area ID mismatch."),
             "tags": ["EXOS", "OSPF", "CLI", "routing"],
             "source": "Switch Engine v33.6.1 — OSPF"},
        ]
    },
    "BGP": {
        "rfc": "RFC 4271", "layer": "L3",
        "aliases": ["eBGP", "iBGP", "border gateway"],
        "chunks": [
            {"id": "BGP_overview", "title": "BGP Overview",
             "text": ("BGP (RFC 4271) is the inter-AS routing protocol. TCP port 179. "
                      "BGP states: Idle, Connect, Active, OpenSent, OpenConfirm, Established. "
                      "Messages: OPEN, UPDATE, NOTIFICATION, KEEPALIVE. "
                      "BGP session reset: NOTIFICATION message with error code. "
                      "BGP flapping: session repeatedly dropping — causes route churn."),
             "tags": ["BGP", "routing", "AS", "session", "TCP 179"],
             "source": "RFC 4271"},
            {"id": "BGP_exos", "title": "EXOS BGP Commands",
             "text": ("EXOS BGP commands: "
                      "  enable bgp                               -- enable BGP "
                      "  create bgp neighbor <IP> remote-AS <ASN> "
                      "  show bgp neighbor                        -- all peers "
                      "  show bgp summary                         -- peer states and prefix counts "
                      "BGP peer stuck in Active: TCP connection failing — check IP reachability "
                      "and firewall allowing TCP 179."),
             "tags": ["EXOS", "BGP", "CLI", "routing"],
             "source": "Switch Engine v33.6.1 — BGP"},
        ]
    },
    "VLAN": {
        "rfc": "IEEE 802.1Q", "layer": "L2",
        "aliases": ["802.1Q", "dot1q", "virtual LAN", "trunk"],
        "chunks": [
            {"id": "VLAN_overview", "title": "VLAN / 802.1Q Tagging",
             "text": ("VLAN tagging (IEEE 802.1Q) inserts a 4-byte tag between MAC src and EtherType. "
                      "Tag: TPID (0x8100) | PCP (3 bits QoS) | DEI | VID (12 bits, 1-4094). "
                      "Access port: untagged frames. Trunk port: carries multiple VLANs with tags. "
                      "VLAN mismatch: port in wrong VLAN causes connectivity failure. "
                      "Q-in-Q: two 802.1Q headers for service provider encapsulation."),
             "tags": ["VLAN", "802.1Q", "trunk", "tag", "QinQ"],
             "source": "IEEE 802.1Q-2018"},
            {"id": "VLAN_exos", "title": "EXOS VLAN Commands",
             "text": ("EXOS VLAN commands: "
                      "  create vlan <name> tag <id>              -- create VLAN "
                      "  configure vlan <name> add ports <p> tagged     -- trunk "
                      "  configure vlan <name> add ports <p> untagged   -- access "
                      "  show vlan                                -- all VLANs "
                      "  show fdb vlan <name>                     -- MAC table for VLAN "
                      "Key: EXOS uses VLAN names (not numbers) for most commands."),
             "tags": ["EXOS", "VLAN", "CLI", "trunk", "tagged"],
             "source": "Switch Engine v33.6.1 — VLANs"},
        ]
    },
    "LACP": {
        "rfc": "IEEE 802.3ad", "layer": "L2",
        "aliases": ["LAG", "link aggregation", "port channel", "MLAG"],
        "chunks": [
            {"id": "LACP_overview", "title": "LACP / Link Aggregation",
             "text": ("LACP (IEEE 802.3ad) aggregates multiple links into one logical port. "
                      "Slow LACP: PDUs every 30s. Fast LACP: PDUs every 1s (detects failure in 3s). "
                      "LAG not forming: mismatched speed/duplex, LACP mode mismatch, "
                      "or partner not sending LACP PDUs. "
                      "MLAG: Multi-switch LAG across two switches for redundant uplinks."),
             "tags": ["LACP", "LAG", "aggregation", "MLAG"],
             "source": "IEEE 802.1AX-2020"},
            {"id": "LACP_exos", "title": "EXOS LAG/MLAG Commands",
             "text": ("EXOS LAG commands: "
                      "  enable sharing <master-port> grouping <port-list> algorithm address-based L2 lacp "
                      "  show sharing                             -- all LAGs "
                      "  show lacp counters                      -- PDU counters "
                      "  show mlag                               -- MLAG pairs "
                      "MLAG issue: check ISC (inter-switch connection) link is up."),
             "tags": ["EXOS", "LAG", "MLAG", "LACP", "CLI"],
             "source": "Switch Engine v33.6.1 — LAG/MLAG"},
        ]
    },
    "IGMP": {
        "rfc": "RFC 3376", "layer": "L3",
        "aliases": ["multicast", "IGMP snooping", "PIM"],
        "chunks": [
            {"id": "IGMP_overview", "title": "IGMP / Multicast Overview",
             "text": ("IGMP (RFC 3376) manages IPv4 multicast group membership. "
                      "IGMPv2: Leave (0x17), Membership Query (0x11). "
                      "IGMPv3: source-specific multicast (SSM). "
                      "IGMP Snooping: switch listens to IGMP to limit multicast flooding. "
                      "Without snooping: multicast flooded like broadcast on all ports."),
             "tags": ["IGMP", "multicast", "snooping", "PIM"],
             "source": "RFC 3376"},
        ]
    },
    "IPv6": {
        "rfc": "RFC 8200", "layer": "L3",
        "aliases": ["ICMPv6", "NDP", "IPv6 routing"],
        "chunks": [
            {"id": "IPv6_overview", "title": "IPv6 Overview",
             "text": ("IPv6 (RFC 8200) uses 128-bit addresses. No broadcast — uses multicast. "
                      "Link-local: fe80::/10. Global unicast: 2000::/3. "
                      "NDP (RFC 4861) replaces ARP: NS/NA for address resolution, "
                      "RS/RA for prefix/gateway discovery. "
                      "ICMPv6: Type 135=NS, 136=NA, 133=RS, 134=RA. "
                      "SLAAC: stateless address autoconfiguration from RA prefix."),
             "tags": ["IPv6", "NDP", "ICMPv6", "SLAAC"],
             "source": "RFC 8200, RFC 4861"},
        ]
    },
    "NTP": {
        "rfc": "RFC 5905", "layer": "L7",
        "aliases": ["time synchronisation", "clock"],
        "chunks": [
            {"id": "NTP_overview", "title": "NTP Protocol",
             "text": ("NTP (RFC 5905) synchronises clocks. UDP port 123. "
                      "Stratum 0: atomic/GPS. Stratum 1: directly connected. Max stratum 15. "
                      "NTP amplification: 'monlist' returns 600 recently-seen clients — DDoS vector. "
                      "High jitter: affects VoIP, TLS certificates, syslog timestamps. "
                      "EXOS: 'configure ntp server add <IP>' and 'show ntp' to verify."),
             "tags": ["NTP", "time", "stratum", "amplification"],
             "source": "RFC 5905"},
        ]
    },
    "VRRP": {
        "rfc": "RFC 5798", "layer": "L3",
        "aliases": ["gateway redundancy", "first-hop redundancy"],
        "chunks": [
            {"id": "VRRP_overview", "title": "VRRP Overview",
             "text": ("VRRP (RFC 5798) provides first-hop gateway redundancy. "
                      "Virtual IP shared between master and backup routers. "
                      "Multicast 224.0.0.18, IP protocol 112. "
                      "Master sends advertisements every ~1s. "
                      "Backup promotes to master if no advertisement within 3x interval. "
                      "VRRP flapping: roles switching frequently — check network stability."),
             "tags": ["VRRP", "gateway", "redundancy", "failover"],
             "source": "RFC 5798"},
        ]
    },
}


# ── TF-IDF index (zero external-dependency retriever) ─────────────────────────

class _TFIDFIndex:
    """Lightweight cosine-similarity retriever — no ML libraries needed."""

    def __init__(self):
        self._docs: list = []
        self._tfidf: list = []
        self._idf: dict = {}
        self._built = False

    def _tokenize(self, text: str) -> list:
        text = text.lower()
        text = re.sub(r'[^a-z0-9.\-_/]', ' ', text)
        return [t for t in text.split() if len(t) >= 2]

    def add_documents(self, docs: list):
        self._docs = docs
        N = len(docs)
        if N == 0:
            return
        tfs = []
        df: dict = {}
        for doc in docs:
            tokens = self._tokenize(doc['text'])
            freq: dict = {}
            for t in tokens:
                freq[t] = freq.get(t, 0) + 1
            max_f = max(freq.values()) if freq else 1
            tf = {t: c / max_f for t, c in freq.items()}
            tfs.append(tf)
            for t in freq:
                df[t] = df.get(t, 0) + 1
        self._idf = {t: _math.log((N + 1) / (c + 1)) + 1 for t, c in df.items()}
        self._tfidf = []
        for tf in tfs:
            vec = {t: tf[t] * self._idf.get(t, 1.0) for t in tf}
            norm = _math.sqrt(sum(v * v for v in vec.values())) or 1.0
            self._tfidf.append({t: v / norm for t, v in vec.items()})
        self._built = True

    def search(self, query: str, top_k: int = 5) -> list:
        if not self._built:
            return []
        q_tokens = self._tokenize(query)
        q_freq: dict = {}
        for t in q_tokens:
            q_freq[t] = q_freq.get(t, 0) + 1
        max_f = max(q_freq.values()) if q_freq else 1
        q_vec: dict = {}
        for t, c in q_freq.items():
            q_vec[t] = (c / max_f) * self._idf.get(t, _math.log(2.0) + 1)
        q_norm = _math.sqrt(sum(v * v for v in q_vec.values())) or 1.0
        q_vec = {t: v / q_norm for t, v in q_vec.items()}
        scores = []
        for i, doc_vec in enumerate(self._tfidf):
            score = sum(q_vec[t] * doc_vec.get(t, 0.0) for t in q_vec)
            scores.append((score, i))
        scores.sort(reverse=True)
        results = []
        for score, idx in scores[:top_k]:
            if score > 0.01:
                results.append({**self._docs[idx]['meta'],
                                 'text': self._docs[idx]['text'],
                                 'score': round(score, 4)})
        return results


# ── Optional sentence-transformers upgrade ────────────────────────────────────

def _make_rag_index():
    """Return best available index: dense embeddings if available, else TF-IDF."""
    try:
        from sentence_transformers import SentenceTransformer
        import numpy as np

        class _STIndex:
            def __init__(self):
                self._model = SentenceTransformer('all-MiniLM-L6-v2')
                self._docs = []
                self._embeddings = None

            def add_documents(self, docs):
                self._docs = docs
                self._embeddings = self._model.encode(
                    [d['text'] for d in docs], show_progress_bar=False, convert_to_numpy=True)
                norms = np.linalg.norm(self._embeddings, axis=1, keepdims=True)
                self._embeddings /= np.where(norms == 0, 1, norms)

            def search(self, query, top_k=5):
                if self._embeddings is None:
                    return []
                q = self._model.encode([query], convert_to_numpy=True)
                q /= (np.linalg.norm(q) or 1.0)
                scores = (self._embeddings @ q.T).flatten()
                idxs = np.argsort(scores)[::-1][:top_k]
                return [{**self._docs[i]['meta'], 'text': self._docs[i]['text'],
                         'score': round(float(scores[i]), 4)}
                        for i in idxs if scores[i] > 0.20]

        print('  [RAG] Using sentence-transformers (dense embeddings)')
        return _STIndex()
    except ImportError:
        print('  [RAG] Using TF-IDF index (install sentence-transformers for better quality)')
        return _TFIDFIndex()


# ── Knowledge base loader ─────────────────────────────────────────────────────

class _EmbeddedKB:
    """Loads _BUILTIN_KB and merges any user files from knowledge_base/ directory."""

    def __init__(self):
        self._data: dict = {}
        self._load()

    def _load(self):
        self._data = {k: v for k, v in _BUILTIN_KB.items()}
        # Merge user-supplied rfc_index.json if present
        kb_dir = Path(__file__).parent / 'knowledge_base'
        idx_file = kb_dir / 'rfc_index.json'
        if idx_file.exists():
            try:
                with open(idx_file, 'r', encoding='utf-8') as f:
                    user_kb = json.load(f)
                merged = 0
                for key, val in user_kb.items():
                    if key.startswith('_'):
                        continue
                    if key in self._data:
                        existing_ids = {c['id'] for c in self._data[key].get('chunks', [])}
                        for chunk in val.get('chunks', []):
                            if chunk['id'] not in existing_ids:
                                self._data[key].setdefault('chunks', []).append(chunk)
                                merged += 1
                    else:
                        self._data[key] = val
                        merged += 1
                print(f'  [RAG] Merged {merged} entries from {idx_file}')
            except Exception as e:
                print(f'  [RAG] Warning: could not load {idx_file}: {e}')
        # Ingest .txt / .md files from knowledge_base/exos|rfcs|protocols|runbooks
        if kb_dir.exists():
            for subdir in ('exos', 'rfcs', 'protocols', 'runbooks'):
                d = kb_dir / subdir
                if not d.exists():
                    continue
                for f in list(d.glob('*.txt')) + list(d.glob('*.md')):
                    self._ingest_text_file(f, kb_dir)

    def _ingest_text_file(self, path, kb_dir):
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
            key = path.stem.upper().replace('-', '_').replace(' ', '_')
            chunks = []
            current = ''
            chunk_id = 0
            for para in re.split(r'\n{2,}', text):
                if len(current) + len(para) < 600:
                    current += para + '\n\n'
                else:
                    if current.strip():
                        chunks.append({'id': f'{key}_{chunk_id}',
                                       'title': f'{path.stem} (chunk {chunk_id})',
                                       'text': current.strip(),
                                       'tags': [path.stem],
                                       'source': str(path.relative_to(kb_dir))})
                        chunk_id += 1
                    current = para + '\n\n'
            if current.strip():
                chunks.append({'id': f'{key}_{chunk_id}',
                               'title': f'{path.stem} (chunk {chunk_id})',
                               'text': current.strip(),
                               'tags': [path.stem],
                               'source': str(path.relative_to(kb_dir))})
            if chunks:
                if key not in self._data:
                    self._data[key] = {'rfc': '', 'layer': 'unknown', 'aliases': [], 'chunks': []}
                existing_ids = {c['id'] for c in self._data[key].get('chunks', [])}
                for c in chunks:
                    if c['id'] not in existing_ids:
                        self._data[key]['chunks'].append(c)
        except Exception as e:
            print(f'  [RAG] Warning: could not ingest {path}: {e}')

    def get_entry(self, proto: str):
        proto_up = proto.upper().replace('-', '').replace('_', '').replace('.', '')
        for key, val in self._data.items():
            if key.startswith('_') or not isinstance(val, dict):
                continue
            if key.upper().replace('-', '').replace('_', '') == proto_up:
                return val
            for alias in val.get('aliases', []):
                if alias.upper().replace('-', '').replace('_', '').replace('.', '') == proto_up:
                    return val
        return None

    def all_chunks(self) -> list:
        docs = []
        for key, val in self._data.items():
            if key.startswith('_') or not isinstance(val, dict):
                continue
            for chunk in val.get('chunks', []):
                docs.append({
                    'text': chunk.get('text', ''),
                    'meta': {
                        'protocol': key,
                        'chunk_id': chunk.get('id', ''),
                        'title': chunk.get('title', ''),
                        'source': chunk.get('source', ''),
                        'tags': chunk.get('tags', []),
                        'rfc': val.get('rfc', ''),
                        'layer': val.get('layer', ''),
                    }
                })
        return docs


# ── Singleton RAG retriever ───────────────────────────────────────────────────

class _RAGRetriever:
    """
    Singleton. First call builds the TF-IDF (or dense) index over the full
    knowledge base; subsequent calls are fast in-memory lookups.
    """
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._ready = False
        return cls._instance

    def _build(self):
        if self._ready:
            return
        t0 = time.time()
        self._kb = _EmbeddedKB()
        self._index = _make_rag_index()
        docs = self._kb.all_chunks()
        self._index.add_documents(docs)
        self._ready = True
        print(f'  [RAG] Index ready in {time.time()-t0:.2f}s ({len(docs)} chunks, '
              f'{len([k for k in self._kb._data if not k.startswith("_")])} protocols)')

    def search(self, query: str, top_k: int = 5) -> list:
        self._build()
        return self._index.search(query, top_k=top_k)

    def get_protocol(self, proto: str):
        self._build()
        return self._kb.get_entry(proto)


# ── Public RAG API — called by ask_ai() ──────────────────────────────────────

_MAX_RAG_CHARS = 6000
_MAX_RAG_CHUNKS = 8


def retrieve_context(protocols: list, extra_query: str = '') -> str:
    """
    Given detected protocol names from the PCAP, retrieve and format the most
    relevant knowledge-base chunks as grounding context to inject before the
    AI prompt.  Returns a formatted string (or '' if nothing found).

    Called automatically by ask_ai() — no manual invocation needed.
    """
    retriever = _RAGRetriever()
    seen: set = set()
    collected: list = []

    # Pass 1 — exact protocol match (highest priority)
    for proto in protocols[:10]:
        entry = retriever.get_protocol(proto)
        if not entry:
            continue
        for chunk in entry.get('chunks', [])[:3]:
            cid = chunk.get('id', '')
            if cid not in seen:
                seen.add(cid)
                collected.append({
                    'protocol': proto,
                    'title': chunk.get('title', proto),
                    'text': chunk.get('text', ''),
                    'source': chunk.get('source', entry.get('rfc', '')),
                    'rfc': entry.get('rfc', ''),
                    'score': 1.0,
                })

    # Pass 2 — TF-IDF / semantic search for extra context
    if extra_query or len(collected) < 3:
        query_parts = protocols[:6] + ([extra_query] if extra_query else [])
        query = ' '.join(query_parts).strip()
        if query:
            for r in retriever.search(query, top_k=6):
                cid = r.get('chunk_id', '')
                if cid not in seen and r.get('score', 0) > 0.05:
                    seen.add(cid)
                    collected.append({
                        'protocol': r.get('protocol', ''),
                        'title': r.get('title', ''),
                        'text': r.get('text', ''),
                        'source': r.get('source', r.get('rfc', '')),
                        'rfc': r.get('rfc', ''),
                        'score': r.get('score', 0),
                    })

    collected = collected[:_MAX_RAG_CHUNKS]
    if not collected:
        return ''

    lines = [
        '## Knowledge Base Context (verified EXOS + RFC reference material)',
        '',
        'Use the following authoritative reference material when answering. '
        'Prefer this over general training knowledge for EXOS CLI commands and RFC specifics.',
        '',
    ]
    char_count = sum(len(l) for l in lines)

    for chunk in collected:
        section = (
            f'### {chunk["title"]}'
            + (f'  [{chunk["rfc"]}]' if chunk.get('rfc') else '')
            + '\n' + chunk['text']
            + (f'\n_Source: {chunk["source"]}_' if chunk.get('source') else '')
            + '\n'
        )
        if char_count + len(section) > _MAX_RAG_CHARS:
            remaining = _MAX_RAG_CHARS - char_count - 50
            if remaining > 200:
                lines.append(section[:remaining] + '\n...[truncated]')
            break
        lines.append(section)
        char_count += len(section)

    return '\n'.join(lines)


def add_runbook_chunk(protocol: str, title: str, text: str,
                      tags: list = None, source: str = 'internal runbook') -> bool:
    """
    Add a custom knowledge chunk at runtime (e.g. from UI or automation scripts).
    Persisted to knowledge_base/runbooks/ for next startup.  Returns True on success.
    """
    try:
        retriever = _RAGRetriever()
        retriever._build()
        kb = retriever._kb
        entry = kb.get_entry(protocol)
        chunk_id = f'{protocol.upper()}_{_hashlib.md5(title.encode()).hexdigest()[:8]}'
        new_chunk = {'id': chunk_id, 'title': title, 'text': text,
                     'tags': tags or [protocol], 'source': source}
        if entry:
            existing_ids = {c['id'] for c in entry.get('chunks', [])}
            if chunk_id not in existing_ids:
                entry.setdefault('chunks', []).append(new_chunk)
        else:
            kb._data[protocol.upper()] = {
                'rfc': '', 'layer': 'unknown', 'aliases': [], 'chunks': [new_chunk]}
        kb_dir = Path(__file__).parent / 'knowledge_base' / 'runbooks'
        kb_dir.mkdir(parents=True, exist_ok=True)
        (kb_dir / f'{protocol.upper()}_{chunk_id}.txt').write_text(
            f'# {title}\n\n{text}\n\nSource: {source}\n', encoding='utf-8')
        retriever._ready = False  # Force re-index on next call
        retriever._build()
        print(f'  [RAG] Added runbook chunk: {chunk_id}')
        return True
    except Exception as e:
        print(f'  [RAG] Failed to add runbook chunk: {e}')
        return False


def get_rag_stats() -> dict:
    """Return KB statistics — useful for the /status endpoint or debug UI."""
    retriever = _RAGRetriever()
    retriever._build()
    protocols = [k for k in retriever._kb._data if not k.startswith('_')]
    total_chunks = sum(len(retriever._kb._data[p].get('chunks', []))
                       for p in protocols if isinstance(retriever._kb._data[p], dict))
    return {
        'protocols': len(protocols),
        'total_chunks': total_chunks,
        'protocol_list': sorted(protocols),
        'index_type': type(retriever._index).__name__,
    }


# ── AI backend ────────────────────────────────────────────────────────────────

RFC_SYSTEM = (
    "You are a senior network engineer, protocol analyst, and security expert.\n"
    "You have complete knowledge of all RFCs (RFC 791 IPv4, RFC 793 TCP, RFC 768 UDP, "
    "RFC 792 ICMP, RFC 826 ARP, RFC 8200 IPv6, RFC 2865 RADIUS, RFC 2131 DHCP, "
    "RFC 1035 DNS, RFC 5905 NTP, RFC 4253 SSH, RFC 3411 SNMP, RFC 4271 BGP, "
    "IEEE 802.1AB LLDP, IEEE 802.1X EAPoL, IEEE 802.1Q VLAN).\n\n"
    "When analysing packets ALWAYS explain:\n"
    "1. **Protocol**: Name + RFC/IEEE standard\n"
    "2. **Header Fields**: Every field name, value, and exact meaning\n"
    "3. **Direction**: Source MAC/IP/Port -> Destination MAC/IP/Port\n"
    "4. **Purpose**: What this packet is doing on the network\n"
    "5. **OSI Layer**: Which layer (L2/L3/L4/L7) and why\n"
    "6. **State**: For TCP - connection state. For ICMP - type/code meaning\n"
    "7. **Security**: Any anomalies, attacks, or policy violations\n"
    "8. **Troubleshooting**: What issues this packet might indicate\n\n"
    "Be precise, technical, and reference specific RFC sections where relevant."
)

CHAT_SYSTEM = (
    "You are a concise AI network analyst assistant embedded in a PCAP analysis dashboard. "
    "The user may ask follow-up questions about a network capture or general networking topics.\n\n"
    "Rules:\n"
    "- Keep answers SHORT (2-5 sentences for simple questions, bullet points for lists).\n"
    "- Only expand into a long answer if the question genuinely requires it (e.g. 'explain in detail').\n"
    "- Remember context from earlier in this conversation — do NOT re-introduce yourself each turn.\n"
    "- Reference RFC/IEEE standards when relevant but stay concise.\n"
    "- For PCAP-specific questions, use the capture context provided."
)

# In-memory chat history for the Chat tab (capped at last 20 turns)
_CHAT_HISTORY = []
_CHAT_HISTORY_MAX = 20  # number of user+assistant turn pairs to keep

def _is_mcp_query(prompt):
    """Check if a prompt contains EXOS/switch management keywords → route to MCP."""
    low = prompt.lower()
    return any(kw in low for kw in MCP_KEYWORDS)


def _mcp_session():
    """
    Open an SSE session with FastMCP server.
    Returns (sock, session_post_url, sse_reader_fn)

    FastMCP protocol:
      1. GET /sse  → server sends:  event: endpoint\\ndata: /messages/?session_id=XYZ
      2. POST /messages/?session_id=XYZ  → send JSON-RPC
         responses arrive on the SSE stream as:  event: message\\ndata: {...json...}
    """
    import socket, threading, queue, urllib.parse, time

    parsed   = urllib.parse.urlparse(MCP_SERVER_URL)
    raw_host = parsed.hostname or 'localhost'
    # 0.0.0.0 is a server bind address — connect to loopback instead
    connect_host = '127.0.0.1' if raw_host in ('0.0.0.0', '::') else raw_host
    port     = parsed.port or 80
    sse_path = parsed.path or '/sse'
    # Use the connect host in base_url so POST also goes to loopback
    base_url = f'{parsed.scheme}://{connect_host}:{port}'

    # ── Open raw TCP socket for SSE stream ───────────────────────────────────
    sock = socket.create_connection((connect_host, port), timeout=10)
    sock.sendall((
        f'GET {sse_path} HTTP/1.1\r\n'
        f'Host: {connect_host}:{port}\r\n'
        f'Accept: text/event-stream\r\n'
        f'Cache-Control: no-cache\r\n'
        f'Connection: keep-alive\r\n'
        f'\r\n'
    ).encode())

    # ── Skip HTTP response headers ───────────────────────────────────────────
    buf = b''
    while b'\r\n\r\n' not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError('SSE socket closed before headers completed')
        buf += chunk
    header_end = buf.index(b'\r\n\r\n') + 4
    leftover   = buf[header_end:]

    # ── Background thread: continuously read SSE stream into a queue ─────────
    msg_queue    = queue.Queue()
    endpoint_evt = threading.Event()
    session_url  = [None]
    raw_buf      = [leftover.decode('utf-8', errors='replace')]
    stop_evt     = threading.Event()

    def _sse_reader():
        """Read bytes from sock, parse SSE events, put JSON messages in queue."""
        sock.settimeout(60)
        while not stop_evt.is_set():
            try:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                raw_buf[0] += chunk.decode('utf-8', errors='replace')
            except socket.timeout:
                continue
            except Exception:
                break

            # Normalise line endings: SSE spec allows \r\n or \n
            raw_buf[0] = raw_buf[0].replace('\r\n', '\n').replace('\r', '\n')

            # Parse complete SSE event blocks (separated by double newline)
            while '\n\n' in raw_buf[0]:
                block, raw_buf[0] = raw_buf[0].split('\n\n', 1)
                event_type = ''
                data_str   = ''
                for line in block.splitlines():
                    if line.startswith('event:'):
                        event_type = line[6:].strip()
                    elif line.startswith('data:'):
                        data_str = line[5:].strip()

                if event_type == 'endpoint' and data_str:
                    session_url[0] = base_url + data_str
                    endpoint_evt.set()

                elif event_type == 'message' and data_str:
                    try:
                        msg_queue.put(json.loads(data_str))
                    except Exception:
                        pass

    reader_thread = threading.Thread(target=_sse_reader, daemon=True)
    reader_thread.start()

    # ── Wait for the endpoint event ──────────────────────────────────────────
    if not endpoint_evt.wait(timeout=10):
        stop_evt.set()
        sock.close()
        raise RuntimeError(
            f'MCP server at {MCP_SERVER_URL} connected but never sent an endpoint event.\n'
            'Ensure it is a FastMCP/mcp-python server.'
        )

    print(f'  [MCP] Session URL: {session_url[0]}')
    return sock, session_url[0], msg_queue, stop_evt


def _mcp_jsonrpc(session_url, msg_queue, method, params, req_id, read_timeout=20):
    """
    POST one JSON-RPC request to the session URL, then wait for
    the matching response to arrive on the SSE message queue.
    """
    import urllib.request, time, queue as _q

    payload = json.dumps({
        'jsonrpc': '2.0',
        'id':      req_id,
        'method':  method,
        'params':  params or {},
    }).encode()

    req = urllib.request.Request(
        session_url, data=payload, method='POST',
        headers={'Content-Type': 'application/json'},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        _ = r.read()   # 202 Accepted

    # Drain the queue looking for our response id
    deadline = time.time() + read_timeout
    pending  = []
    while time.time() < deadline:
        try:
            msg = msg_queue.get(timeout=0.2)
            if msg.get('id') == req_id:
                # Put back anything we drained that wasn't ours
                for m in pending:
                    msg_queue.put(m)
                return msg
            else:
                pending.append(msg)
        except _q.Empty:
            continue

    for m in pending:
        msg_queue.put(m)
    raise RuntimeError(f'Timeout waiting for JSON-RPC response: method={method} id={req_id}')


def _mcp_list_tools():
    """
    Open SSE session, initialize, list tools.
    Returns (tools_list, sock, session_url, msg_queue, stop_evt)
    """
    sock, session_url, msg_queue, stop_evt = _mcp_session()

    try:
        # Initialize
        init = _mcp_jsonrpc(session_url, msg_queue, 'initialize', {
            'protocolVersion': '2024-11-05',
            'capabilities':    {},
            'clientInfo':      {'name': 'netscope', 'version': '1.0'},
        }, req_id=1, read_timeout=10)
        server_info = init.get('result', {}).get('serverInfo', {})
        print(f'  [MCP] Init OK: {server_info}')

        # Send initialized notification (required by spec)
        import urllib.request
        urllib.request.urlopen(urllib.request.Request(
            session_url,
            data=json.dumps({'jsonrpc':'2.0','method':'notifications/initialized','params':{}}).encode(),
            method='POST',
            headers={'Content-Type': 'application/json'},
        ), timeout=5).read()

        # List tools
        tools_resp = _mcp_jsonrpc(session_url, msg_queue, 'tools/list', {}, req_id=2, read_timeout=10)
        tools = tools_resp.get('result', {}).get('tools', [])
        return tools, sock, session_url, msg_queue, stop_evt

    except Exception:
        stop_evt.set()
        try: sock.close()
        except: pass
        raise


def _mcp_call_tool(session_url, msg_queue, tool_name, arguments):
    """Call one MCP tool and return its text output."""
    resp = _mcp_jsonrpc(session_url, msg_queue, 'tools/call', {
        'name':      tool_name,
        'arguments': arguments,
    }, req_id=3, read_timeout=30)

    if resp.get('error'):
        return f"Tool error: {resp['error'].get('message', str(resp['error']))}"

    parts = []
    for block in resp.get('result', {}).get('content', []):
        if block.get('type') == 'text' and block.get('text'):
            parts.append(block['text'])
    return '\n'.join(parts) if parts else json.dumps(resp.get('result', {}), indent=2)


def _pick_tool_via_llm(prompt, tools, switch_ip=''):
    """
    Ask Ollama to select the right MCP tool and build its arguments from the
    actual tools the server advertises.  No tool names are hardcoded here.

    Flow:
      1. Narrow 400+ tools to ~25 topic-relevant candidates using the USER'S
         keywords matched against actual TOOL NAMES from the server.
         run_cli is excluded from this pool — it is an internal fallback only.
      2. Pass those candidates + their descriptions to Ollama (JSON mode).
         Ollama returns {"tool": "<name>", "args": {<arguments>}}.
      3. Validate the returned name exists and args are non-empty.
         Always inject switch_ip into args if we have it.
      4. On any failure (bad name, empty args, timeout) → fall back to
         run_cli with an LLM-generated 'show ...' CLI command string.

    Returns (tool_name, arguments_dict).
    """
    import re as _re
    import urllib.request as _ur

    # ── "list tools" shortcut ──────────────────────────────────────────────
    if _re.search(r'list.*tool|available tool|what tool', prompt.lower()):
        return '__list_tools__', {}

    # Separate run_cli from the pool so Ollama never sees it as a candidate.
    # It's our fallback; we don't want Ollama picking it without valid args.
    run_cli_tool = next((t for t in tools if t['name'] == 'run_cli'), None)
    specialised  = [t for t in tools if t['name'] != 'run_cli']

    # ── Step 1: narrow specialised tools by topic keywords in tool NAMES ──
    TOPIC_MAP = [
        (['vlan'],                       'vlan'),
        (['port', 'interface'],          'interface'),
        (['ospf'],                       'ospf'),
        (['bgp'],                        'bgp'),
        (['route', 'routing', 'iproute'],'route'),
        (['acl', 'policy'],              'acl'),
        (['lag', 'aggregation'],         'lag'),
        (['mlag'],                       'mlag'),
        (['version', 'firmware'],        'version'),
        (['health', 'system'],           'system'),
        (['lldp', 'neighbor'],           'lldp'),
        (['stp', 'spanning'],            'stp'),
        (['dhcp'],                       'dhcp'),
        (['ipv6'],                       'ipv6'),
        (['arp'],                        'arp'),
        (['snmp'],                       'snmp'),
        (['qos'],                        'qos'),
        (['tunnel', 'vxlan'],            'vxlan'),
        (['security'],                   'security'),
        (['fdb', 'mac.*table'],          'fdb'),
    ]
    pl = prompt.lower()
    topic_hits = {topic for kws, topic in TOPIC_MAP
                  if any(_re.search(kw, pl) for kw in kws)}

    if topic_hits:
        candidates = [t for t in specialised
                      if any(hit in t['name'].lower() for hit in topic_hits)]
    else:
        candidates = list(specialised)

    candidates = candidates[:25]   # keep Ollama prompt manageable

    # ── Step 2: ask Ollama to pick from the live tool list ────────────────
    if candidates:
        tool_desc = '\n'.join(
            f'{t["name"]}: {t.get("description", "(no description)")}'
            for t in candidates
        )
        ip_hint = f'Switch IP: {switch_ip}' if switch_ip else 'Switch IP: not provided'
        system_prompt = (
            'You are an ExtremeXOS network assistant.\n'
            'Select the single best tool from the list below that answers the user query.\n'
            'Every EXOS tool requires a "switch_ip" argument.\n'
            'Respond with ONLY a JSON object, no markdown:\n'
            '{"tool": "<exact_tool_name>", "args": {"switch_ip": "<ip>", ...other_args...}}\n'
        )
        user_msg = (
            f'User query: {prompt}\n'
            f'{ip_hint}\n\n'
            f'Tools (name: description):\n{tool_desc}\n\n'
            f'Return JSON only.'
        )
        try:
            data = json.dumps({
                'model': OLLAMA_MODEL,
                'messages': [
                    {'role': 'system', 'content': system_prompt},
                    {'role': 'user',   'content': user_msg},
                ],
                'stream': False,
                'format': 'json',
                'options': {'num_predict': 256, 'temperature': 0},
            }).encode()
            req = _ur.Request(
                'http://localhost:11434/api/chat', data=data,
                method='POST', headers={'Content-Type': 'application/json'}
            )
            with _ur.urlopen(req, timeout=30) as r:
                resp_data = json.loads(r.read())
            content  = resp_data.get('message', {}).get('content', '{}')
            picked   = json.loads(content)
            tool_name = str(picked.get('tool', '')).strip()
            args      = picked.get('args', {})
            if not isinstance(args, dict):
                args = {}

            valid_names = {t['name'] for t in specialised}
            if tool_name in valid_names:
                # Always guarantee switch_ip is present in args
                if switch_ip and 'switch_ip' not in args:
                    args['switch_ip'] = switch_ip
                print(f'  [MCP] LLM picked tool: {tool_name}  args={args}')
                return tool_name, args
            print(f'  [MCP] LLM returned unknown/invalid tool: {tool_name!r}')
        except Exception as e:
            print(f'  [MCP] LLM tool selection failed: {e}')

    # ── Step 3: fallback → run_cli with a generated CLI command ───────────
    if run_cli_tool and switch_ip:
        print('  [MCP] Falling back to run_cli')
        try:
            cli_data = json.dumps({
                'model': OLLAMA_MODEL,
                'messages': [
                    {'role': 'system', 'content':
                        'You are an ExtremeXOS CLI expert. '
                        'Reply with ONLY the single EXOS CLI command (no IP address, '
                        'no explanation, no markdown). Just the command string itself.'},
                    {'role': 'user', 'content':
                        f'What is the EXOS CLI command to: {prompt}'},
                ],
                'stream': False,
                'options': {'num_predict': 64, 'temperature': 0},
            }).encode()
            req2 = _ur.Request(
                'http://localhost:11434/api/chat', data=cli_data,
                method='POST', headers={'Content-Type': 'application/json'}
            )
            with _ur.urlopen(req2, timeout=20) as r2:
                cli_resp = json.loads(r2.read())
            cli_cmd = cli_resp.get('message', {}).get('content', '').strip()
            # Strip any surrounding quotes or backticks Ollama might add
            cli_cmd = cli_cmd.strip('`"\' \n')
            if cli_cmd:
                print(f'  [MCP] run_cli fallback: switch_ip={switch_ip!r} command={cli_cmd!r}')
                return 'run_cli', {'switch_ip': switch_ip, 'command': cli_cmd}
        except Exception as e2:
            print(f'  [MCP] run_cli fallback failed: {e2}')

    return None, {}


def _ask_mcp(prompt):
    """
    Talk directly to the locally running exos-mcp-server via FastMCP SSE protocol.
    No Claude API key required — works entirely locally with Ollama.

    Architecture:
        Browser → /api/chat
            → _ask_mcp()
                1. GET /sse              → get session URL
                2. POST session URL      → initialize + tools/list  (via SSE queue)
                3. POST session URL      → tools/call  (live switch data)
                4. Ollama                → format raw output for display
    """
    sock = stop_evt = None
    print(f'  [MCP] Connecting to {MCP_SERVER_URL} ...')

    # Step 1 — open SSE session and discover tools
    try:
        tools, sock, session_url, msg_queue, stop_evt = _mcp_list_tools()
        print(f'  [MCP] {len(tools)} tools: {[t["name"] for t in tools[:10]]}')
    except Exception as e:
        return (
            f"**Cannot connect to MCP server at `{MCP_SERVER_URL}`**\n\n"
            f"Error: {e}\n\n"
            "**Checklist:**\n"
            f"1. Is exos-mcp-server running?  `python exos_mcp_server.py`\n"
            f"2. Is it listening on port 8000?\n"
            "3. Check the server terminal for errors."
        )

    if not tools:
        if stop_evt: stop_evt.set()
        if sock:
            try: sock.close()
            except: pass
        return (
            f"MCP server at `{MCP_SERVER_URL}` connected but returned no tools.\n"
            "Check exos-mcp-server configuration and switch IP settings."
        )

    try:
        # Extract IP from prompt (last match = user's target switch)
        import re as _re
        ip_matches = _re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', prompt)
        switch_ip  = ip_matches[-1] if ip_matches else ''
        if switch_ip:
            print(f'  [MCP] Extracted IP from prompt: {switch_ip}')

        # Step 2 — let Ollama pick the tool and build its arguments
        tool_name, arguments = _pick_tool_via_llm(prompt, tools, switch_ip)

        # Special: list tools
        if tool_name == '__list_tools__':
            lines = [f'**Available MCP tools on `{MCP_SERVER_NAME}`:**\n']
            for t in tools:
                desc = t.get('description', 'No description')
                lines.append(f'• **{t["name"]}** — {desc}')
            return '\n'.join(lines)

        if not tool_name:
            return (
                "**Could not determine which MCP tool to use.**\n\n"
                "Try rephrasing your query, or include the switch IP directly.\n"
                "Example: `show vlans on 10.127.32.224`"
            )

        print(f'  [MCP] Calling tool: {tool_name}  args={arguments}')

        # Step 3 — call the tool
        raw_output = _mcp_call_tool(session_url, msg_queue, tool_name, arguments)
        print(f'  [MCP] Tool returned {len(raw_output)} chars')

        if not raw_output:
            return f"**MCP tool `{tool_name}` returned empty output.** Check switch connectivity."

        # Step 4 — Ollama formats the raw output
        format_prompt = (
            f"You are an ExtremeXOS (EXOS) / Extreme Networks expert assistant.\n"
            f"The user asked: {prompt}\n\n"
            f"The live switch returned this output from tool `{tool_name}`:\n\n"
            f"{raw_output}\n\n"
            f"Present this in a clear, structured format. Use tables where useful. "
            f"Explain important values. Flag any issues you see."
        )

        try:
            import urllib.request as _ur
            data = json.dumps({
                'model': OLLAMA_MODEL, 'prompt': format_prompt,
                'stream': False, 'options': {'num_predict': 1024},
            }).encode()
            req = _ur.Request('http://localhost:11434/api/generate', data=data,
                              method='POST', headers={'Content-Type': 'application/json'})
            with _ur.urlopen(req, timeout=120) as r:
                formatted = json.loads(r.read()).get('response', raw_output)
            return f"**[Live via MCP — `{tool_name}`]**\n\n{formatted}"
        except Exception:
            return f"**[Live via MCP — `{tool_name}`]**\n\n```\n{raw_output}\n```"

    finally:
        if stop_evt: stop_evt.set()
        if sock:
            try: sock.close()
            except: pass


def ask_ai(prompt, protocols=None):
    """
    Route prompt to the correct AI backend:
      • EXOS/switch management queries  → MCP server (exos-mcp-server via Claude)
      • PCAP/protocol analysis queries  → configured AI backend (Ollama / Claude / OpenAI)
    """
    # ── MCP routing: EXOS switch queries ────────────────────────────────────
    if MCP_ENABLED and _is_mcp_query(prompt):
        print(f'  [chat] MCP route: EXOS query detected → {MCP_SERVER_URL}')
        # Strip the 'Context:\n{CTX}\n\nQuestion: ' wrapper added by the Chat tab
        # so MCP only sees the user's actual query (avoids picking up PCAP packet IPs)
        user_query = prompt
        if '\n\nQuestion: ' in prompt:
            user_query = prompt.split('\n\nQuestion: ', 1)[1]
        return _ask_mcp(user_query)

    # ── RFC knowledge enrichment for PCAP queries ────────────────────────────
    if protocols:
        try:
            from knowledge_retriever import retrieve_rfc_for_protocols
            rfc_material = retrieve_rfc_for_protocols(protocols)
            if rfc_material:
                prompt = (
                    "## RFC Reference Material (from authoritative sources)\n\n"
                    + rfc_material + "\n\n"
                    + "## User Query\n\n" + prompt
                )
        except Exception:
            pass  # Graceful fallback if knowledge_retriever unavailable
        # Check for unknown protocols not in the knowledge base
        try:
            kb_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   'knowledge_base', 'rfc_index.json')
            if os.path.exists(kb_path):
                with open(kb_path, 'r') as _f:
                    kb = json.load(_f)
                known = {k for k in kb if not k.startswith('_')}
                unknown = [p for p in protocols if p not in known
                           and not p.startswith('ET-')]
                if unknown:
                    disclaimer = (
                        "\n\n**IMPORTANT INSTRUCTION**: The following protocols are NOT in our "
                        "verified knowledge base: " + ', '.join(unknown) + ". "
                        "For these protocols, you MUST explicitly state: "
                        "'⚠️ Protocol [name] is not in the verified knowledge base. "
                        "The following information is based on general knowledge and may not be "
                        "fully accurate. Please verify against official RFC/IEEE documentation.' "
                        "Do NOT present unverified protocol details as facts.\n\n"
                    )
                    prompt = disclaimer + prompt
        except Exception:
            pass

    # ── Normal AI backends ───────────────────────────────────────────────────
    if AI_BACKEND == 'claude' and CLAUDE_API_KEY: return _ask_claude(prompt)
    if AI_BACKEND == 'openai' and OPENAI_API_KEY: return _ask_openai(prompt)
    return _ask_ollama(prompt)

def _ask_ollama(prompt):
    try:
        import urllib.request, json as _j
        full = RFC_SYSTEM + '\n\n' + prompt
        data = _j.dumps({'model':OLLAMA_MODEL,'prompt':full,'stream':False,
                         'options':{'num_predict':4096}}).encode()
        req  = urllib.request.Request('http://localhost:11434/api/generate', data=data,
                   method='POST', headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req, timeout=180) as r:
            return _j.loads(r.read())['response']
    except Exception as e:
        return (f"**Ollama unavailable** ({e})\n\n"
                f"Model: `{OLLAMA_MODEL}`\n\n**To fix:**\n"
                "  1. Run: `ollama serve`\n"
                f"  2. Run: `ollama pull {OLLAMA_MODEL}`\n\n"
                "**Or use:** `--ai claude --claude-key KEY`")

def _ask_claude(prompt):
    try:
        import urllib.request, urllib.error, json as _j
        data = _j.dumps({
            "model": CLAUDE_MODEL,
            "max_tokens": 2000,
            "system": RFC_SYSTEM,
            "messages": [{"role": "user", "content": prompt}]
        }).encode()
        req = urllib.request.Request(
            'https://api.anthropic.com/v1/messages', data=data, method='POST',
            headers={
                'Content-Type': 'application/json',
                'x-api-key': CLAUDE_API_KEY,
                'anthropic-version': '2023-06-01'
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return _j.loads(r.read())['content'][0]['text']
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='replace')
            try:
                err_obj = _j.loads(body)
                msg = err_obj.get('error', {}).get('message', body)
            except Exception:
                msg = body[:300]
            return (
                f"**Claude API error {e.code}**\n\n{msg}\n\n"
                f"Model used: `{CLAUDE_MODEL}`\n\n"
                "**To fix:** Pass the correct model name via `--claude-model MODEL`.\n"
                "Current supported models: `claude-sonnet-4-6`, `claude-opus-4-6`\n\n"
                "**If you see 'credit balance too low':** Top up at https://console.anthropic.com/settings/billing"
            )
    except Exception as e:
        return f"Claude API error: {e}"

def _ask_openai(prompt):
    try:
        import urllib.request, json as _j
        data = _j.dumps({"model":"gpt-4o","max_tokens":2000,
                         "messages":[{"role":"user","content":RFC_SYSTEM+'\n\n'+prompt}]}).encode()
        req = urllib.request.Request('https://api.openai.com/v1/chat/completions', data=data,
                  method='POST', headers={'Content-Type':'application/json',
                  'Authorization':f'Bearer {OPENAI_API_KEY}'})
        with urllib.request.urlopen(req, timeout=60) as r:
            return _j.loads(r.read())['choices'][0]['message']['content']
    except Exception as e:
        return f"OpenAI API error: {e}"

def _ask_chat_with_history(user_message, history):
    """
    Chat-tab LLM call with multi-turn conversation history.
    history: list of {role: 'user'|'assistant', content: str}
    Returns (reply_str, updated_history)
    """
    global _CHAT_HISTORY
    import urllib.request, json as _j, time

    # Build message list: system + history (capped) + new user message
    capped = history[-(2 * _CHAT_HISTORY_MAX):]  # keep last N pairs
    messages = capped + [{'role': 'user', 'content': user_message}]

    try:
        if AI_BACKEND == 'claude' and CLAUDE_API_KEY:
            data = _j.dumps({
                'model': CLAUDE_MODEL,
                'max_tokens': 1024,
                'system': CHAT_SYSTEM,
                'messages': messages
            }).encode()
            req = urllib.request.Request(
                'https://api.anthropic.com/v1/messages', data=data, method='POST',
                headers={'Content-Type': 'application/json',
                         'x-api-key': CLAUDE_API_KEY,
                         'anthropic-version': '2023-06-01'})
            with urllib.request.urlopen(req, timeout=60) as r:
                reply = _j.loads(r.read())['content'][0]['text']

        elif AI_BACKEND == 'openai' and OPENAI_API_KEY:
            oai_msgs = [{'role': 'system', 'content': CHAT_SYSTEM}] + messages
            data = _j.dumps({'model': 'gpt-4o', 'max_tokens': 1024,
                             'messages': oai_msgs}).encode()
            req = urllib.request.Request(
                'https://api.openai.com/v1/chat/completions', data=data, method='POST',
                headers={'Content-Type': 'application/json',
                         'Authorization': f'Bearer {OPENAI_API_KEY}'})
            with urllib.request.urlopen(req, timeout=60) as r:
                reply = _j.loads(r.read())['choices'][0]['message']['content']

        else:
            # Ollama — use /api/chat endpoint for multi-turn support
            ollama_msgs = [{'role': 'system', 'content': CHAT_SYSTEM}] + messages
            data = _j.dumps({
                'model': OLLAMA_MODEL,
                'messages': ollama_msgs,
                'stream': False,
                'options': {'num_predict': 1024}
            }).encode()
            req = urllib.request.Request(
                'http://localhost:11434/api/chat', data=data, method='POST',
                headers={'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=180) as r:
                reply = _j.loads(r.read())['message']['content']

        # Append this turn to history
        updated = capped + [
            {'role': 'user',      'content': user_message},
            {'role': 'assistant', 'content': reply},
        ]
        return reply, updated

    except Exception as e:
        return f"Error: {e}", history

# ═══════════════════════════════════════════════════════════════════════════════
#  DASHBOARD — make_html()
#  Clean rewrite. All JS is inline. Zero CDN dependencies.
# ═══════════════════════════════════════════════════════════════════════════════

def make_html(analysis, pcap_fname, switch_ip=None):
    fname  = os.path.basename(pcap_fname)
    pc     = analysis['proto_counts']
    arp    = analysis['arp']
    icmp   = analysis['icmp']
    tcp    = analysis['tcp']
    udp    = analysis['udp']
    total  = analysis['total']
    anom   = analysis['anomalies']
    svcs   = analysis['services']
    pkts   = analysis['all_packets']
    proto_bytes = analysis.get('proto_bytes', {})
    total_bytes = analysis.get('total_bytes', 0)

    arp_reqs_total = analysis.get('arp_reqs_total', 0)
    arp_reps_total = analysis.get('arp_reps_total', 0)
    arp_pairs      = analysis.get('arp_pairs', {})

    _up_slot = PCAP_SLOTS.get('uploaded')
    _up_fname = os.path.basename(_up_slot['fname']) if _up_slot else 'Uploaded'
    _up_visible = 'uploaded' in PCAP_SLOTS
    arp_completed  = analysis.get('arp_completed', {})
    arp_unanswered = analysis.get('arp_unanswered', {})
    arp_gratuitous = analysis.get('arp_gratuitous', [])

    tcp_syn    = analysis.get('tcp_syn', 0);   tcp_synack = analysis.get('tcp_synack', 0)
    tcp_ack    = analysis.get('tcp_ack', 0);   tcp_psh    = analysis.get('tcp_psh', 0)
    tcp_fin    = analysis.get('tcp_fin', 0);   tcp_rst    = analysis.get('tcp_rst', 0)
    icmp_req   = analysis.get('icmp_req', 0);  icmp_rep   = analysis.get('icmp_rep', 0)
    icmp_unr   = analysis.get('icmp_unr', 0);  icmp_ttl   = analysis.get('icmp_ttl', 0)

    switch_info = f'Switch: {switch_ip}' if switch_ip else 'File Analysis'
    ai_model = (CLAUDE_MODEL      if AI_BACKEND=='claude' else
                 'gpt-4o'          if AI_BACKEND=='openai' else OLLAMA_MODEL)

    # ── Serialise JS data ──────────────────────────────────────────────────────
    labels_js = json.dumps(list(pc.keys()))
    values_js = json.dumps(list(pc.values()))

    _ts0 = pkts[0]['ts'] if pkts else 0
    ts0_js = json.dumps(_ts0)   # passed to JS as _TS0 for relative-time display

    # ── Protocol Request-Response Analysis (RFC-compliant) ──────────────────
    protocol_details_html = ''
    try:
        from protocol_request_response_analyzer import (
            ProtocolRequestResponseAnalyzer,
            generate_protocol_details_html
        )
        analyzer = ProtocolRequestResponseAnalyzer(pkts)
        protocol_details_html = generate_protocol_details_html(analyzer)
    except ImportError:
        protocol_details_html = '<div style="padding:20px;color:#999"><p>Protocol analyzer not available. Make sure protocol_request_response_analyzer.py is present.</p></div>'
    except Exception as e:
        protocol_details_html = f'<div style="padding:20px;color:#ef4444"><p>Error analyzing protocols: {str(e)}</p></div>'

    # ── SNMP Trap Analysis (RFC-compliant) ───────────────────────────────────
    traps_html = ''
    try:
        from snmp_trap_analyzer import generate_traps_html as _gen_traps_html
        traps_html = _gen_traps_html(analysis.get('trap_analysis', {}))
    except ImportError:
        traps_html = '<div style="padding:20px;color:#999">Trap analyzer not available. Ensure snmp_trap_analyzer.py is present.</div>'
    except Exception as e:
        traps_html = f'<div style="padding:20px;color:#ef4444">Error in trap analysis: {str(e)}</div>'

    # ── Flow / sequence diagram data ─────────────────────────────────────────
    # Group packets into conversations (by src-dst pair, regardless of direction)
    _flow_hosts = []
    _host_set = set()
    _flow_arrows = []
    _flow_protos = set()
    _convos = {}
    _svc_protos = {
        'DHCP-Server':'DHCP','DHCP-Client':'DHCP','DHCPv6-Server':'DHCPv6','DHCPv6-Client':'DHCPv6',
        'DNS':'DNS','NTP':'NTP','TFTP':'TFTP','SSH':'SSH','HTTP':'HTTP','HTTPS':'HTTPS',
        'SNMP':'SNMP','Syslog':'Syslog','RADIUS':'RADIUS','RADIUS-Acct':'RADIUS',
        'SMTP':'SMTP','IMAP':'IMAP','POP3':'POP3','FTP':'FTP','FTP-Data':'FTP',
        'LDAP':'LDAP','LDAPS':'LDAPS','RDP':'RDP','Telnet':'Telnet',
        'BGP':'BGP','OSPF':'OSPF','IKE/IPSec':'IKE','RIP':'RIP',
        'MySQL':'MySQL','PostgreSQL':'PostgreSQL','Redis':'Redis','MongoDB':'MongoDB',
        'MQTT':'MQTT','SIP':'SIP','RTP':'RTP',
    }

    # ── Build MAC→IP mapping so we can represent each host by a single identity ──
    # Priority: if a MAC has an IP address seen anywhere in the capture, use the IP.
    # If multiple IPs map to the same MAC, keep the most-seen one.
    _mac_ip_count = {}   # mac → {ip → count}
    _ip_mac_count = {}   # ip  → {mac → count}
    for _p in pkts[:5000]:
        _sm = _p.get('src_mac', ''); _si = _p.get('src_ip', '')
        _dm = _p.get('dst_mac', ''); _di = _p.get('dst_ip', '')
        if _sm and _si and _si != '?':
            _mac_ip_count.setdefault(_sm, {})
            _mac_ip_count[_sm][_si] = _mac_ip_count[_sm].get(_si, 0) + 1
        if _dm and _di and _di != '?':
            _mac_ip_count.setdefault(_dm, {})
            _mac_ip_count[_dm][_di] = _mac_ip_count[_dm].get(_di, 0) + 1
        if _si and _sm:
            _ip_mac_count.setdefault(_si, {})
            _ip_mac_count[_si][_sm] = _ip_mac_count[_si].get(_sm, 0) + 1
        if _di and _dm:
            _ip_mac_count.setdefault(_di, {})
            _ip_mac_count[_di][_dm] = _ip_mac_count[_di].get(_dm, 0) + 1

    # mac → best IP (most-seen), or None if MAC never appeared with an IP
    _mac_to_ip = {
        mac: max(ips, key=ips.get)
        for mac, ips in _mac_ip_count.items() if ips
    }

    def _flow_identity(ip, mac):
        """Return a single canonical identifier for this endpoint.
        Prefer IP. Fall back to MAC. Resolve MAC→IP if the packet had no IP field."""
        if ip and ip != '?':
            return ip
        if mac and mac != '?':
            return _mac_to_ip.get(mac, mac)
        return '?'

    for p in pkts[:2000]:
        src = _flow_identity(p.get('src_ip', ''), p.get('src_mac', ''))
        dst = _flow_identity(p.get('dst_ip', ''), p.get('dst_mac', ''))
        for h in (src, dst):
            if h and h != '?' and h not in _host_set:
                _host_set.add(h)
                _flow_hosts.append(h)
        proto = p.get('proto', '?')
        svc = p.get('service', '')
        display_proto = _svc_protos.get(svc, proto)
        _flow_protos.add(display_proto)

        flags = p.get('tcp_flags', '') or ''
        arp_op = p.get('arp_op', '') or ''
        icmp_str = p.get('icmp_type_str', '') or ''
        sp = p.get('src_port', '')
        dp = p.get('dst_port', '')

        role = 'data'
        if display_proto == 'ARP':
            role = 'request' if arp_op == 'REQUEST' else 'response'
        elif display_proto == 'ICMP':
            if 'Request' in icmp_str or 'request' in icmp_str: role = 'request'
            elif 'Reply' in icmp_str or 'reply' in icmp_str: role = 'response'
        elif display_proto in ('DHCP', 'DHCPv6'):
            if dp in (67, 547): role = 'request'
            elif dp in (68, 546): role = 'response'
            elif sp in (67, 547): role = 'response'
            else: role = 'request'
        elif display_proto == 'DNS':
            if dp == 53: role = 'request'
            elif sp == 53: role = 'response'
        elif proto == 'TCP':
            if 'SYN' in flags and 'ACK' not in flags: role = 'request'
            elif 'SYN' in flags and 'ACK' in flags: role = 'response'
            elif 'FIN' in flags: role = 'request'
            elif 'RST' in flags: role = 'response'
            else:
                pair = tuple(sorted([src, dst]))
                if pair not in _convos: _convos[pair] = (src, dst); role = 'request'
                elif _convos[pair] == (src, dst): role = 'request'
                else: role = 'response'
        elif proto == 'UDP':
            if dp and sp and isinstance(dp, int) and isinstance(sp, int):
                if dp < sp: role = 'request'
                elif sp < dp: role = 'response'
            if role == 'data':
                pair = tuple(sorted([src, dst]))
                if pair not in _convos: _convos[pair] = (src, dst); role = 'request'
                elif _convos[pair] == (src, dst): role = 'request'
                else: role = 'response'

        flag_str = flags or arp_op or icmp_str
        label = display_proto
        if flag_str: label += ' ' + flag_str
        if sp and dp: label += f' {sp}→{dp}'
        _flow_arrows.append({
            'id': p['id'], 't': round(p['ts'] - _ts0, 6),
            'src': src, 'dst': dst,
            'label': label, 'proto': display_proto,
            'flags': flag_str, 'bytes': p.get('frame_len', 0),
            'role': role,
        })
    # Limit hosts to top 20 by packet involvement to keep the diagram readable
    if len(_flow_hosts) > 20:
        _hcount = {}
        for a in _flow_arrows:
            _hcount[a['src']] = _hcount.get(a['src'], 0) + 1
            _hcount[a['dst']] = _hcount.get(a['dst'], 0) + 1
        _flow_hosts = sorted(_flow_hosts, key=lambda h: _hcount.get(h, 0), reverse=True)[:20]
        _fh_set = set(_flow_hosts)
        _flow_arrows = [a for a in _flow_arrows if a['src'] in _fh_set and a['dst'] in _fh_set]
    flow_js = json.dumps({'hosts': _flow_hosts, 'arrows': _flow_arrows,
                          'protos': sorted(_flow_protos)})

    # ── TCP Stream / Handshake data ─────────────────────────────────────────
    _streams = {}   # key=(src_ip,src_port,dst_ip,dst_port) → list of steps
    _arp_pairs = {} # key=(requester_ip, target_ip) → list of steps
    for p in pkts[:3000]:
        proto = p.get('proto', '?')
        if proto == 'TCP':
            sip = p.get('src_ip', '?'); dip = p.get('dst_ip', '?')
            sp = p.get('src_port', 0);  dp = p.get('dst_port', 0)
            # Normalise key so both directions map to the same stream
            if (sip, sp, dip, dp) > (dip, dp, sip, sp):
                key = (dip, dp, sip, sp)
            else:
                key = (sip, sp, dip, dp)
            flags = p.get('tcp_flags', '') or ''
            _streams.setdefault(key, []).append({
                'id': p['id'], 't': round(p['ts'] - _ts0, 6),
                'src': f'{sip}:{sp}', 'dst': f'{dip}:{dp}',
                'flags': flags, 'bytes': p.get('frame_len', 0),
            })
        elif proto == 'ARP':
            sip = p.get('src_ip', '?'); dip = p.get('dst_ip', '?')
            op = p.get('arp_op', '') or ''
            key = tuple(sorted([sip, dip]))
            _arp_pairs.setdefault(key, []).append({
                'id': p['id'], 't': round(p['ts'] - _ts0, 6),
                'src': sip, 'dst': dip, 'op': op,
                'src_mac': p.get('src_mac', ''), 'dst_mac': p.get('dst_mac', ''),
            })
    # Build JSON-ready list (limit to top 100 streams by packet count)
    _stream_list = []
    for key, steps in sorted(_streams.items(), key=lambda x: len(x[1]), reverse=True)[:100]:
        flags_seen = set()
        for s in steps:
            for f in s['flags'].replace(',', ' ').split():
                flags_seen.add(f)
        _stream_list.append({
            'type': 'TCP', 'key': f'{key[0]}:{key[1]} ↔ {key[2]}:{key[3]}',
            'count': len(steps), 'flags': sorted(flags_seen),
            'steps': steps[:200],  # cap per stream
        })
    for key, steps in sorted(_arp_pairs.items(), key=lambda x: len(x[1]), reverse=True)[:50]:
        _stream_list.append({
            'type': 'ARP', 'key': f'{key[0]} ↔ {key[1]}',
            'count': len(steps), 'flags': [],
            'steps': steps[:100],
        })
    stream_js = json.dumps(_stream_list)

    tl_js = json.dumps([
        {'id':p['id'],'x':round(p['ts']-_ts0,6),'y':p.get('frame_len',0),
         'proto':p.get('proto','?'),'src':p.get('src_ip',p.get('src_mac','?')),
         'dst':p.get('dst_ip',p.get('dst_mac','?'))}
        for p in pkts[:2000]
    ])
    pkt_js = json.dumps({
        str(p['id']): {
            'id':p['id'],'proto':p.get('proto','?'),'summary':p.get('summary',''),
            'frame_len':p.get('frame_len',0),'ts':p.get('ts',0),
            'src_ip':p.get('src_ip',p.get('src_mac','?')),
            'dst_ip':p.get('dst_ip',p.get('dst_mac','?')),
            'src_mac':p.get('src_mac',''),'dst_mac':p.get('dst_mac',''),
            'src_port':p.get('src_port',''),'dst_port':p.get('dst_port',''),
            'service':p.get('service',''),'tcp_flags':p.get('tcp_flags',''),
            'tcp_seq':p.get('tcp_seq',''),'tcp_ack':p.get('tcp_ack',''),
            'tcp_window':p.get('tcp_window',''),'tcp_state':p.get('tcp_state',''),
            'ttl':p.get('ttl',''),'icmp_type':p.get('icmp_type',''),
            'icmp_type_str':p.get('icmp_type_str',''),'arp_op':p.get('arp_op',''),
            'vlan_id':p.get('vlan_id',''),'hex_data':p.get('hex_data',[]),
            'layers':p.get('layers',[]),
            'tshark_protocols':p.get('tshark_protocols',''),
            'tshark_info':p.get('tshark_info',''),
            'dhcp_msg_type':p.get('dhcp_msg_type',''),
            'dns_query':p.get('dns_query',''),
            'dns_qr':p.get('dns_qr',''),
            'igmp_type_name':p.get('igmp_type_name',''),
            'snmp_community':p.get('snmp_community',''),
            'snmp_pdu_type':p.get('snmp_pdu_type',''),
            'snmp_enterprise':p.get('snmp_enterprise',''),
        }
        for p in pkts[:10000]
    })
    # Real total packet count (may be > 10000 for very large PCAPs)
    pkt_total_count_js = len(pkts)
    ctx_js = json.dumps({
        'file':fname,'total':total,'switch':switch_info,
        'arp':len(arp),'icmp':len(icmp),'tcp':len(tcp),'udp':len(udp),
        'arp_reqs':arp_reqs_total,'arp_reps':arp_reps_total,
        'arp_completed':len(arp_completed),'arp_unanswered':len(arp_unanswered),
        'icmp_req':icmp_req,'icmp_rep':icmp_rep,
        'tcp_syn':tcp_syn,'tcp_synack':tcp_synack,'tcp_rst':tcp_rst,'tcp_fin':tcp_fin,
        'anomalies':anom,'services':list(svcs.keys())[:15],
        'top_src':list(analysis['src_ips'].items())[:8],
        'top_dst':list(analysis['dst_ips'].items())[:8],
        'total_bytes':total_bytes,
        'ai_narrative': analysis.get('anomaly_result', {}).get('ai_narrative', ''),
        'ai_risk_score': analysis.get('anomaly_result', {}).get('ai_risk_score'),
        'priority_action': analysis.get('anomaly_result', {}).get('priority_action', ''),
        'incidents': analysis.get('anomaly_result', {}).get('incidents', []),
        'protocols': [{'name':p,'count':c,'bytes':proto_bytes.get(p,0)}
                      for p,c in sorted(pc.items(), key=lambda x:x[1], reverse=True)[:30]],
    })
    anom_js = json.dumps(anom)
    # Rich anomaly data for JS (findings with severity, layer, etc.)
    _anomaly_result = analysis.get('anomaly_result', {})
    anom_findings_js = json.dumps([
        {'title': f['title'], 'severity': f['severity'], 'layer': f['layer'],
         'category': f['category'], 'detail': f['detail']}
        for f in _anomaly_result.get('findings', [])
    ][:50]) if _anomaly_result else '[]'
    anom_summary_js = json.dumps(_anomaly_result.get('summary', {})) if _anomaly_result else '{}'

    # ── ARP pair rows ───────────────────────────────────────────────────────────
    arp_pair_rows = ''
    for (src,tgt),v in sorted(arp_pairs.items(), key=lambda x:x[1]['req']+x[1]['rep'], reverse=True)[:60]:
        done = v['req']>0 and v['rep']>0
        grat = src==tgt
        status = ('<span class="badge" style="background:#10b981">✓ COMPLETE</span>' if done
                  else '<span class="badge" style="background:#ef4444">✗ NO REPLY</span>')
        grat_b = '<span class="badge sm" style="background:#f59e0b;color:#000;margin-left:4px">GRAT</span>' if grat else ''
        arp_pair_rows += (
            f'<tr>'
            f'<td class="mono c-acc">{src}</td>'
            f'<td class="mono" style="color:#a78bfa">{tgt}{grat_b}</td>'
            f'<td class="num" style="color:#f59e0b">{v["req"]}</td>'
            f'<td class="num" style="color:#10b981">{v["rep"]}</td>'
            f'<td class="mono sm muted">{v["req_mac"] or "—"}</td>'
            f'<td class="mono sm" style="color:#10b981">{v["rep_mac"] or "—"}</td>'
            f'<td>{status}</td>'
            f'</tr>'
        )
    arp_pair_table = (
        '<table><thead><tr>'
        '<th>Requester IP</th><th>Target IP</th>'
        '<th style="text-align:right">REQ↑</th><th style="text-align:right">REPLY↓</th>'
        '<th>Req MAC</th><th>Replier MAC</th><th>Status</th>'
        '</tr></thead><tbody>' + arp_pair_rows + '</tbody></table>'
    ) if arp_pair_rows else '<p class="empty">No ARP traffic</p>'

    # ── Anomaly HTML ─────────────────────────────────────────────────────────────
    anomaly_result = analysis.get('anomaly_result')
    anom_html = _render_anom_html(anomaly_result) if anomaly_result else (
        ''.join(f'<div class="anom-row"><span class="anom-icon">⚠</span>{a}</div>' for a in anom)
        or '<div class="ok-row"><span>✓</span><span>No anomalies detected — traffic looks normal</span></div>'
    )

    # ── Service cards ─────────────────────────────────────────────────────────────
    svc_html = ''.join(
        f'<div class="svc-card"><div class="svc-name">{s}</div><div class="svc-cnt">{c} pkts</div></div>'
        for s,c in sorted(svcs.items(), key=lambda x:x[1], reverse=True)
    ) or '<span class="muted sm">None detected</span>'

    # ── IP bars ───────────────────────────────────────────────────────────────────
    def ip_bar_html(ip_dict, color):
        mx = max(ip_dict.values(), default=1)
        return ''.join(
            f'<div class="ip-row">'
            f'<span class="ip-addr" style="color:{color}">{ip}</span>'
            f'<div class="ip-track"><div class="ip-fill" style="background:{color};width:{int(c/mx*100)}%"></div></div>'
            f'<span class="ip-cnt muted">{c}</span>'
            f'</div>'
            for ip,c in list(ip_dict.items())[:8]
        ) or '<p class="muted sm" style="padding:4px 0">No IP traffic</p>'

    src_bars = ip_bar_html(analysis['src_ips'], '#00d4ff')
    dst_bars = ip_bar_html(analysis['dst_ips'], '#a78bfa')

    # ── Conversation / Endpoint Statistics ────────────────────────────────────────
    _convos_stats = {}
    for p in pkts[:3000]:
        sip = p.get('src_ip', p.get('src_mac', '?'))
        dip = p.get('dst_ip', p.get('dst_mac', '?'))
        pr = p.get('proto', '?')
        byt = p.get('frame_len', 0)
        key = tuple(sorted([sip, dip]))
        if key not in _convos_stats:
            _convos_stats[key] = {'pkts': 0, 'bytes': 0, 'protos': set(), 'a': key[0], 'b': key[1]}
        _convos_stats[key]['pkts'] += 1
        _convos_stats[key]['bytes'] += byt
        _convos_stats[key]['protos'].add(pr)
    # Top 10 conversations by packet count
    _top_convos = sorted(_convos_stats.values(), key=lambda c: c['pkts'], reverse=True)[:10]
    _convo_mx = max((c['pkts'] for c in _top_convos), default=1)
    convo_html = ''.join(
        f'<div style="display:flex;align-items:center;gap:8px;padding:4px 0;border-bottom:1px solid var(--border)">'
        f'<span style="color:#00d4ff;font:500 10px var(--mono);width:120px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{c["a"]}</span>'
        f'<span style="color:var(--muted);font-size:10px">↔</span>'
        f'<span style="color:#a78bfa;font:500 10px var(--mono);width:120px;flex-shrink:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{c["b"]}</span>'
        f'<div style="flex:1;background:#1e2535;border-radius:2px;height:4px;min-width:40px">'
        f'<div style="background:var(--acc);height:4px;border-radius:2px;width:{int(c["pkts"]/_convo_mx*100)}%"></div></div>'
        f'<span style="color:var(--text);font:600 10px var(--mono);width:50px;text-align:right">{c["pkts"]:,}</span>'
        f'<span style="color:var(--muted);font:400 9px var(--mono);width:60px;text-align:right">{c["bytes"]:,}B</span>'
        f'<span style="font:400 9px var(--mono);color:var(--muted)">{",".join(sorted(c["protos"]))}</span>'
        f'</div>'
        for c in _top_convos
    ) or '<span class="muted sm">No conversations detected</span>'

    # ── Dynamic stat cards ────────────────────────────────────────────────────────
    dyn_cards = ''
    for proto, cnt in sorted(pc.items(), key=lambda x:x[1], reverse=True):
        col = _proto_color(proto)
        rfc = RFC_REF.get(proto,'')
        byt = proto_bytes.get(proto,0)
        _rfc_badge = (
            f'<span style="background:{col}22;color:{col};border:1px solid {col}44;'
            f'border-radius:6px;padding:1px 5px;font-size:9px;white-space:nowrap">'
            f'{rfc}</span>'
        ) if rfc else ''
        dyn_cards += (
            f'<div class="sc" style="--c:{col}">'
            f'<div class="sc-n">{cnt:,}</div>'
            f'<div class="sc-l">{proto}</div>'
            f'<div class="sc-sub">'
            f'<span>Bytes: <b>{byt:,}</b></span>'
            f'{_rfc_badge}'
            f'</div>'
            f'</div>'
        )

    # ── Packet table rows removed (virtual scroll renders rows in JS) ─────────────
    pkt_rows = ''  # kept for template compat — rows rendered by renderTable() via JS

    # ── Protocol filter quick buttons ─────────────────────────────────────────────
    proto_qbtns = ''.join(
        f'<button class="ws-fbtn" onclick="qFilter(\'{p}\')" style="border-color:{_proto_color(p)}55;color:{_proto_color(p)}">{p}</button>'
        for p in sorted(pc.keys(), key=lambda x:pc[x], reverse=True)[:10]
    )

    # ── Timeline color map (JS) ───────────────────────────────────────────────────
    tl_btns = ''.join(
        f'<button class="tl-btn" data-proto="{p}" style="--c:{_proto_color(p)}" onclick="tlFilter(this)">{p}</button>'
        for p in sorted(pc.keys(), key=lambda x:pc[x], reverse=True)[:12]
    )

    # ── TCP flags table ───────────────────────────────────────────────────────────
    tcp_flag_rows = ''.join([
        f'<tr><td><span class="badge" style="background:#10b981">SYN</span></td><td class="num" style="color:#10b981">{tcp_syn}</td><td class="muted sm">New connection</td></tr>',
        f'<tr><td><span class="badge" style="background:#3b82f6">SYN+ACK</span></td><td class="num" style="color:#3b82f6">{tcp_synack}</td><td class="muted sm">Server accepting</td></tr>',
        f'<tr><td><span class="badge" style="background:#475569">ACK</span></td><td class="num">{tcp_ack}</td><td class="muted sm">Acknowledgement</td></tr>',
        f'<tr><td><span class="badge" style="background:#7c5cfc">PSH+ACK</span></td><td class="num" style="color:#7c5cfc">{tcp_psh}</td><td class="muted sm">Data push</td></tr>',
        f'<tr><td><span class="badge" style="background:#f59e0b">FIN</span></td><td class="num" style="color:#f59e0b">{tcp_fin}</td><td class="muted sm">Graceful close</td></tr>',
        f'<tr><td><span class="badge" style="background:#ef4444">RST</span></td><td class="num" style="color:#ef4444">{tcp_rst}</td><td class="muted sm">Abrupt reset</td></tr>',
    ])

    # ── ICMP type rows ────────────────────────────────────────────────────────────
    icmp_rows = ''.join([
        f'<tr><td class="sm" style="color:#ef4444">Echo Request (8)</td><td class="num" style="color:#3b82f6">{icmp_req}</td><td><span class="badge" style="background:#3b82f6">REQ→</span></td></tr>',
        f'<tr><td class="sm" style="color:#10b981">Echo Reply (0)</td><td class="num" style="color:#10b981">{icmp_rep}</td><td><span class="badge" style="background:#10b981">REPLY←</span></td></tr>',
        f'<tr><td class="sm" style="color:#ef4444">Dest Unreachable (3)</td><td class="num" style="color:#ef4444">{icmp_unr}</td><td><span class="badge" style="background:#ef4444">ERROR</span></td></tr>',
        f'<tr><td class="sm" style="color:#f59e0b">Time Exceeded (11)</td><td class="num" style="color:#f59e0b">{icmp_ttl}</td><td><span class="badge" style="background:#f59e0b;color:#000">TTL</span></td></tr>',
    ])

    # ── Services table ────────────────────────────────────────────────────────────
    max_svc = max(svcs.values(), default=1)
    svc_rows = ''.join(
        f'<tr><td class="c-acc" style="font-weight:600">{s}</td>'
        f'<td class="num muted">{c}</td>'
        f'<td><div style="width:80px;background:#1e2535;border-radius:2px;height:4px">'
        f'<div style="background:#00d4ff;height:4px;border-radius:2px;width:{int(c/max_svc*100)}%"></div></div></td>'
        f'</tr>'
        for s,c in sorted(svcs.items(), key=lambda x:x[1], reverse=True)[:20]
    ) or '<tr><td colspan="3" class="muted">None detected</td></tr>'

    # ── ARP analysis table rows ───────────────────────────────────────────────────
    arp_analysis_rows = ''.join([
        f'<tr><td style="color:#f59e0b">Total Requests</td><td class="num" style="color:#f59e0b">{arp_reqs_total}</td><td class="muted sm">Who has IP X?</td></tr>',
        f'<tr><td style="color:#10b981">Reply to Broadcast</td><td class="num" style="color:#10b981">{arp_reps_total}</td><td class="muted sm">X is at MAC Y</td></tr>',
        f'<tr><td style="color:#ef4444">Unanswered</td><td class="num" style="color:#ef4444">{len(arp_unanswered)}</td><td class="muted sm">Host may be down</td></tr>',
        f'<tr><td style="color:#f59e0b">Gratuitous</td><td class="num" style="color:#f59e0b">{len(arp_gratuitous)}</td><td class="muted sm">IP conflict?</td></tr>',
    ])

    # ── Extra protocol panels (beyond ARP/ICMP/TCP/UDP) ───────────────────────────
    KNOWN_TABS = {'ARP','ICMP'}
    extra_tabs_html   = ''
    extra_panels_html = ''
    proto_buckets = analysis.get('proto_buckets', {})
    for proto, pkts_p in sorted(proto_buckets.items(), key=lambda x:len(x[1]), reverse=True):
        if proto in KNOWN_TABS or not pkts_p: continue
        pid = proto.replace('-','_').replace('.','_').replace(':','_').replace('0x','x')
        col = _proto_color(proto)
        extra_tabs_html += (
            f'<button class="ptab" data-panel="pp{pid}" onclick="ptab(this,\'pp{pid}\')" style="--c:{col}">'
            f'{proto} <span class="pcnt">{len(pkts_p)}</span></button>'
        )
        rows = ''
        for pp in pkts_p[:300]:
            src2 = pp.get('src_ip',pp.get('src_mac','?'))
            dst2 = pp.get('dst_ip',pp.get('dst_mac','?'))
            if pp.get('src_port'): src2 += f':{pp["src_port"]}'
            if pp.get('dst_port'): dst2 += f':{pp["dst_port"]}'
            rows += (
                f'<tr onclick="selPkt({pp["id"]})" style="cursor:pointer;border-left:3px solid {col}">'
                f'<td class="muted">{pp["id"]}</td>'
                f'<td class="mono sm c-acc">{src2}</td>'
                f'<td class="muted sm">→</td>'
                f'<td class="mono sm" style="color:#86efac">{dst2}</td>'
                f'<td class="muted sm">{pp.get("frame_len",0)}B</td>'
                f'<td class="muted sm clip">{pp.get("summary","")}</td>'
                f'</tr>'
            )
        extra_panels_html += (
            f'<div id="pp{pid}" class="ppanel" style="display:none;overflow-y:auto;max-height:350px">'
            f'<table><thead><tr><th>#</th><th>Source</th><th></th><th>Dest</th><th>Len</th><th>Info</th></tr></thead>'
            f'<tbody>{rows}</tbody></table></div>'
        )

    _anom_onclick = 'onclick="goView(\x27anomalies\x27,document.getElementById(\x27nb-anomalies\x27))" title="Click to investigate"'  if anom else ''

    # ── Protocol Flow Summary: new insight panels ─────────────────────────────
    _max_pb = max(proto_bytes.values(), default=1)
    _proto_bw_html = ''.join(
        f'<div class="ip-row">'
        f'<span class="ip-addr" style="color:{_proto_color(p)}">{p}</span>'
        f'<div class="ip-track"><div class="ip-fill" style="background:{_proto_color(p)};width:{int(b/_max_pb*100)}%"></div></div>'
        f'<span class="ip-cnt muted">{b:,}B</span>'
        f'</div>'
        for p, b in sorted(proto_bytes.items(), key=lambda x: x[1], reverse=True)[:8]
    ) or '<p class="muted sm" style="padding:4px 0">No byte data available</p>'

    _tcp_completion = round(tcp_synack / max(tcp_syn, 1) * 100) if tcp_syn else 0
    _tcp_half_open  = max(0, tcp_syn - tcp_synack)
    _tcp_rst_color  = '#ef4444' if tcp_rst > 5 else '#94a3b8'
    _tcp_comp_color = '#10b981' if _tcp_completion >= 80 else '#f59e0b' if _tcp_completion >= 50 else '#ef4444'
    _tcp_ho_color   = '#ef4444' if _tcp_half_open > 10 else '#94a3b8'
    def _kv_row(label, val, color):
        return (f'<div style="display:flex;justify-content:space-between;align-items:center;'
                f'padding:5px 0;border-bottom:1px solid var(--border)">'
                f'<span class="muted sm">{label}</span>'
                f'<span style="color:{color};font:700 12px var(--mono)">{val}</span></div>')
    _tcp_health_html = (
        _kv_row('Connections initiated (SYN)',   f'{tcp_syn:,}',           '#10b981') +
        _kv_row('Connections accepted (SYN-ACK)',f'{tcp_synack:,}',        '#3b82f6') +
        _kv_row('Handshake completion rate',     f'{_tcp_completion}%',    _tcp_comp_color) +
        _kv_row('Half-open (no reply)',          f'{_tcp_half_open:,}',    _tcp_ho_color) +
        _kv_row('Abrupt resets (RST)',           f'{tcp_rst:,}',           _tcp_rst_color) +
        _kv_row('Graceful closes (FIN)',         f'{tcp_fin:,}',           '#94a3b8')
    ) if tcp_syn or tcp_rst or tcp_fin else '<p class="muted sm" style="padding:4px 0">No TCP traffic</p>'

    def _ratio_bar(label, req, rep):
        pct = round(rep / max(req, 1) * 100)
        col = '#10b981' if pct >= 80 else '#f59e0b' if pct >= 50 else '#ef4444'
        return (f'<div style="margin-bottom:10px">'
                f'<div style="display:flex;justify-content:space-between;margin-bottom:4px">'
                f'<span class="muted sm">{label}</span>'
                f'<span style="color:{col};font:700 10px var(--mono)">{req:,}→{rep:,} ({pct}%)</span></div>'
                f'<div style="background:#1e2535;border-radius:3px;height:5px">'
                f'<div style="background:{col};height:5px;border-radius:3px;width:{min(pct,100)}%"></div></div></div>')
    _proto_completeness_html = (
        (_ratio_bar('ICMP Ping reply rate',  icmp_req, icmp_rep)   if icmp_req        else '') +
        (_ratio_bar('ARP reply rate',        arp_reqs_total, arp_reps_total) if arp_reqs_total else '') +
        (_ratio_bar('TCP handshake rate',    tcp_syn, tcp_synack)  if tcp_syn         else '')
    ) or '<p class="muted sm" style="padding:4px 0">No request-response protocols detected</p>'

    # ── AI Protocol Analyst: behavior tags ────────────────────────────────────
    _behavior_tags = []
    _proto_keys = set(pc.keys())
    _anom_titles = ' '.join(f.get('title','') for f in _anomaly_result.get('findings', []))
    _anom_sev_max = next((f['severity'] for f in _anomaly_result.get('findings', [])
                          if f['severity'] in ('critical','high')), None)
    # Traffic pattern heuristics
    if any(k in _proto_keys for k in ('ARP',)) and len(arp) > 100:
        _behavior_tags.append(('⚡', 'Broadcast Storm', '#ef4444'))
    if any(k in _proto_keys for k in ('DNS','mDNS','LLMNR')):
        _behavior_tags.append(('🔍', 'Discovery Traffic', '#06b6d4'))
    if any(k in _proto_keys for k in ('DHCP','DHCPv6')):
        _behavior_tags.append(('📡', 'DHCP Activity', '#f59e0b'))
    if any(k in _proto_keys for k in ('HTTP','HTTPS','TLS','SSL')):
        _behavior_tags.append(('🌐', 'Web Traffic', '#3b82f6'))
    if any(k in _proto_keys for k in ('QUIC','RTSP','RTP')):
        _behavior_tags.append(('📺', 'Streaming Traffic', '#8b5cf6'))
    if any(k in _proto_keys for k in ('SSH','Telnet','FTP')):
        _behavior_tags.append(('🔑', 'Remote Access', '#f97316'))
    if any(k in _proto_keys for k in ('BGP','OSPF','EIGRP','RIP','ISIS')):
        _behavior_tags.append(('🗺️', 'Routing Protocols', '#10b981'))
    if any(k in _proto_keys for k in ('SNMP','ICMP')) and len(icmp) > 50:
        _behavior_tags.append(('📊', 'Monitoring Traffic', '#4ade80'))
    if 'scan' in _anom_titles.lower() or 'port scan' in _anom_titles.lower():
        _behavior_tags.append(('🔎', 'Possible Scan', '#ef4444'))
    if tcp_rst > 20:
        _behavior_tags.append(('💥', 'RST Storm', '#ef4444'))
    if tcp_syn > 50 and tcp_synack < tcp_syn // 3:
        _behavior_tags.append(('⚠️', 'Half-Open Flood', '#f97316'))
    # Dominant protocol from pc
    _dom_proto = max(pc, key=pc.get) if pc else 'N/A'
    _dom_count  = pc.get(_dom_proto, 0)
    # Top 8 protocols for the UI
    _top_protos = sorted(pc.items(), key=lambda x: x[1], reverse=True)[:8]

    # Proto color helper (local mini-version)
    _PCMAP = {'ARP':'#f59e0b','ICMP':'#ef4444','TCP':'#3b82f6','UDP':'#10b981',
              'DNS':'#fbbf24','DHCP':'#4ade80','HTTP':'#38bdf8','HTTPS':'#818cf8',
              'TLS':'#a78bfa','SSH':'#60a5fa','OSPF':'#38bdf8','BGP':'#818cf8',
              'LLDP':'#8b5cf6','IPv6':'#06b6d4','NTP':'#a3e635','SNMP':'#e879f9',
              'mDNS':'#06b6d4','QUIC':'#f97316','STP':'#84cc16','IGMP':'#ec4899'}
    def _pc2(p):
        if p in _PCMAP: return _PCMAP[p]
        _fall = ['#00e5ff','#7c5cfc','#ff6b6b','#ffd93d','#6bcb77','#4d96ff','#ff9a3c','#c77dff']
        h = 0
        for c in p: h = (h + ord(c)) % len(_fall)
        return _fall[h]

    # Anomaly badge
    _sev_colors = {'critical':'#ef4444','high':'#f97316','medium':'#f59e0b',
                   'low':'#3b82f6','info':'#6b7280'}
    _anom_count = len(_anomaly_result.get('findings', []))
    if _anom_count:
        _badge_sev  = _anom_sev_max or 'low'
        _badge_col  = _sev_colors.get(_badge_sev, '#6b7280')
        _anom_badge = (f'<span style="background:{_badge_col}22;color:{_badge_col};'
                       f'border:1px solid {_badge_col}55;border-radius:10px;'
                       f'font:700 9px var(--mono);padding:2px 8px;white-space:nowrap">'
                       f'⚠ {_anom_count} anomal{"y" if _anom_count==1 else "ies"} '
                       f'· {_badge_sev.upper()}</span>')
    else:
        _anom_badge = ('<span style="background:#10b98122;color:#10b981;border:1px solid #10b98155;'
                       'border-radius:10px;font:700 9px var(--mono);padding:2px 8px">✓ Clean</span>')

    # AI narrative teaser (first 160 chars)
    _narrative_full = analysis.get('anomaly_result', {}).get('ai_narrative', '')
    _narrative_teaser = (_narrative_full[:160] + '…') if len(_narrative_full) > 160 else _narrative_full

    # Risk score bar
    _risk_score = analysis.get('anomaly_result', {}).get('ai_risk_score') or 0
    _risk_col = '#10b981' if _risk_score < 40 else '#f59e0b' if _risk_score < 70 else '#ef4444'

    # Protocol data for JS
    _proto_data_js = json.dumps([
        {'name': p, 'count': c, 'bytes': proto_bytes.get(p, 0)}
        for p, c in sorted(pc.items(), key=lambda x: x[1], reverse=True)[:30]
    ])

    # Pre-built HTML snippets for the sidebar
    _behavior_tags_html = ''.join(
        f'<span class="btag" style="border-color:{col}44;color:{col}">{ico} {lbl}</span>'
        for ico, lbl, col in (_behavior_tags or [('📦', 'Mixed Traffic', '#6b7280')])
    )
    _proto_chips_sidebar_html = ''.join(
        f'<span class="proto-chip" style="background:{_pc2(p)}22;color:{_pc2(p)};border-color:{_pc2(p)}55" '
        f'onclick="rfcAnalysis(\'{p}\')" title="{c} packets">{p}</span>'
        for p, c in _top_protos
    )
    _risk_bar_html = (
        f'<div class="risk-bar-wrap">'
        f'<div style="display:flex;justify-content:space-between;margin-bottom:3px">'
        f'<span style="font:600 9px var(--sans);color:var(--muted)">Risk Score</span>'
        f'<span style="font:700 9px var(--mono);color:{_risk_col}">{_risk_score}/100</span>'
        f'</div>'
        f'<div class="risk-bar-bg">'
        f'<div class="risk-bar-fill" style="width:{_risk_score}%;background:{_risk_col}"></div>'
        f'</div></div>'
    ) if _risk_score else ''

    anom_tab_js = '\n// ═══════════════════════════════════════════════════════════════\n//  ANOMALIES TAB\n// ═══════════════════════════════════════════════════════════════\nconst SEV_COLORS = {critical:\'#ef4444\',high:\'#f97316\',medium:\'#f59e0b\',low:\'#3b82f6\',info:\'#6b7280\'};\nconst SEV_ICONS  = {critical:\'\\ud83d\\udd34\',high:\'\\ud83d\\udfe0\',medium:\'\\ud83d\\udfe1\',low:\'\\ud83d\\udd35\',info:\'\\u2139\\ufe0f\'};\nlet _anomSevFilter=\'all\', _anomLayerFilter=\'all\', _anomCatFilter=\'all\', _anomSearch=\'\';\n\nfunction initAnomaliesTab() {\n  const s = ANOM_SUMMARY;\n  const cards = document.getElementById(\'anom-cards\');\n  if (!cards) return;\n  const defs = [\n    {key:\'critical\', label:\'Critical\', color:\'#ef4444\'},\n    {key:\'high\',     label:\'High\',     color:\'#f97316\'},\n    {key:\'medium\',   label:\'Medium\',   color:\'#f59e0b\'},\n    {key:\'low\',      label:\'Low\',      color:\'#3b82f6\'},\n    {key:\'info\',     label:\'Info\',     color:\'#6b7280\'},\n  ];\n  let html = \'\';\n  for (const d of defs) {\n    const cnt = s[d.key] || 0;\n    if (cnt === 0) continue;\n    html += \'<div onclick="anomFilter(\\\'sev\\\',\\\'\' + d.key + \'\\\',null)" style="cursor:pointer;background:var(--card-bg);border:1px solid \' + d.color + \'33;border-radius:8px;padding:10px 16px;min-width:90px;text-align:center">\'\n          + \'<div style="font:700 22px var(--mono);color:\' + d.color + \'">\' + cnt + \'</div>\'\n          + \'<div style="font:600 10px var(--sans);color:\' + d.color + \';text-transform:uppercase;margin-top:2px">\' + d.label + \'</div>\'\n          + \'</div>\';\n  }\n  if ((s.total || 0) === 0) {\n    html = \'<div style="background:var(--card-bg);border:1px solid #10b98133;border-radius:8px;padding:12px 20px;color:#10b981;font:600 13px var(--sans)">\\u2713 No anomalies detected \\u2014 traffic looks normal</div>\';\n  }\n  cards.innerHTML = html;\n\n  const cats = [...new Set(ANOM_FINDINGS.map(function(f){return f.category;}))].sort();\n  const catSel = document.getElementById(\'anom-cat-filter\');\n  catSel.innerHTML = \'<option value="all">All Categories</option>\' +\n    cats.map(function(c){return \'<option value="\'+c+\'">\'+c+\'</option>\';}).join(\'\');\n\n  const narrative = CTX.ai_narrative || \'\';\n  if (narrative) {\n    const nb = document.getElementById(\'anom-narrative\');\n    const nt = document.getElementById(\'anom-narrative-text\');\n    if (nb && nt) { nb.style.display=\'block\'; nt.textContent = narrative; }\n  }\n  renderAnomalies();\n}\n\nfunction anomFilter(type, val, btn) {\n  if (type === \'sev\') {\n    _anomSevFilter = val;\n    document.querySelectorAll(\'.anom-filter-btn\').forEach(function(b){b.classList.remove(\'active\');});\n    if (btn) btn.classList.add(\'active\');\n    else document.querySelectorAll(\'.anom-filter-btn\').forEach(function(b){if(b.dataset.sev===val)b.classList.add(\'active\');});\n  } else if (type === \'layer\') {\n    _anomLayerFilter = val;\n  } else if (type === \'cat\') {\n    _anomCatFilter = val;\n  } else if (type === \'search\') {\n    _anomSearch = val.toLowerCase();\n  }\n  renderAnomalies();\n}\n\nfunction renderAnomalies() {\n  const list  = document.getElementById(\'anom-list\');\n  const empty = document.getElementById(\'anom-empty\');\n  if (!list) return;\n  const LAYER_COLORS = {L2:\'#f59e0b\',L3:\'#10b981\',L4:\'#3b82f6\',L5:\'#8b5cf6\',L7:\'#ec4899\',\'L3-L7\':\'#06b6d4\',\'L2+L3\':\'#ef4444\',\'L4+L5\':\'#f97316\',\'L2+L7\':\'#f59e0b\',\'L3+L4\':\'#ef4444\'};\n  const filtered = ANOM_FINDINGS.filter(function(f) {\n    if (_anomSevFilter !== \'all\' && f.severity !== _anomSevFilter) return false;\n    if (_anomLayerFilter !== \'all\' && f.layer !== _anomLayerFilter) return false;\n    if (_anomCatFilter  !== \'all\' && f.category !== _anomCatFilter) return false;\n    if (_anomSearch && !f.title.toLowerCase().includes(_anomSearch) &&\n        !f.detail.toLowerCase().includes(_anomSearch) &&\n        !f.category.toLowerCase().includes(_anomSearch)) return false;\n    return true;\n  });\n  if (filtered.length === 0) { list.innerHTML = \'\'; empty.style.display=\'block\'; return; }\n  empty.style.display = \'none\';\n  list.innerHTML = filtered.map(function(f, i) {\n    const color = SEV_COLORS[f.severity] || \'#6b7280\';\n    const icon  = SEV_ICONS[f.severity]  || \'\\u26a0\';\n    const lc    = LAYER_COLORS[f.layer]  || \'#6b7280\';\n    return \'<div class="anom-row" style="border-left:3px solid \'+color+\';padding:8px 10px;margin-bottom:2px;display:flex;align-items:flex-start;gap:8px" id="anom-row-\'+i+\'">\'\n      + \'<span style="font-size:15px;flex-shrink:0;margin-top:1px">\'+icon+\'</span>\'\n      + \'<div style="flex:1;min-width:0">\'\n      +   \'<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">\'\n      +     \'<span style="background:\'+color+\'22;color:\'+color+\';border:1px solid \'+color+\'55;border-radius:3px;font:700 9px var(--mono);padding:1px 5px">\'+f.severity.toUpperCase()+\'</span>\'\n      +     \'<span style="background:\'+lc+\'22;color:\'+lc+\';border:1px solid \'+lc+\'55;border-radius:3px;font:700 9px var(--mono);padding:1px 5px">\'+f.layer+\'</span>\'\n      +     \'<span style="background:#ffffff0d;color:var(--muted);border-radius:3px;font:600 9px var(--mono);padding:1px 5px">\'+f.category+\'</span>\'\n      +     \'<strong style="font:600 12px var(--sans);color:var(--text)">\'+f.title+\'</strong>\'\n      +   \'</div>\'\n      +   \'<div style="font-size:11px;color:var(--muted);margin-top:3px;line-height:1.5">\'+f.detail+\'</div>\'\n      +   \'<div id="anom-explain-\'+i+\'" style="display:none;margin-top:6px;background:#0d1829;border-radius:4px;padding:8px;font-size:11px;color:#a78bfa"></div>\'\n      + \'</div>\'\n      + \'<button onclick="anomExplain(\'+i+\')" style="flex-shrink:0;background:none;border:1px solid var(--border);color:var(--muted);padding:2px 8px;border-radius:4px;font:600 9px var(--sans);cursor:pointer;white-space:nowrap" title="Ask AI to explain this finding">\\ud83e\\udd16 Explain</button>\'\n      + \'</div>\';\n  }).join(\'\');\n}\n\nfunction anomExplain(idx) {\n  const filtered = ANOM_FINDINGS.filter(function(f) {\n    if (_anomSevFilter !== \'all\' && f.severity !== f.severity) return false;\n    if (_anomLayerFilter !== \'all\' && f.layer !== _anomLayerFilter) return false;\n    if (_anomCatFilter !== \'all\' && f.category !== _anomCatFilter) return false;\n    if (_anomSearch && !f.title.toLowerCase().includes(_anomSearch) &&\n        !f.detail.toLowerCase().includes(_anomSearch)) return false;\n    return true;\n  });\n  const f   = filtered[idx];\n  if (!f) return;\n  const box = document.getElementById(\'anom-explain-\' + idx);\n  if (!box) return;\n  if (box.style.display !== \'none\') { box.style.display = \'none\'; return; }\n  box.style.display = \'block\';\n  box.innerHTML = \'<span style="color:#6b7280">\\u23f3 Asking AI\\u2026</span>\';\n  const prompt = \'Network anomaly detected:\\n\\nFinding: \' + f.title\n    + \'\\nLayer: \' + f.layer + \'\\nCategory: \' + f.category\n    + \'\\nSeverity: \' + f.severity + \'\\nDetail: \' + f.detail\n    + \'\\n\\nExplain in 3-4 sentences:\\n1. What is happening technically\\n2. Why it is concerning\\n3. How to investigate on an Extreme Networks Switch Engine switch — ONLY use commands from the official Switch Engine v33.6.1 Command References (https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20Command%20References/downloads/Switch_Engine_33_6_1_Command_References.pdf). Do NOT reference commands from other Extreme product lines (Fabric Engine, VOSS, EOS, SLX, etc.)\';\n  fetch(\'/api/chat\', {method:\'POST\', headers:{\'Content-Type\':\'application/json\'},\n    body: JSON.stringify({prompt: prompt})})\n    .then(function(r){return r.json();})\n    .then(function(d){ \n      box.innerHTML = \'<strong style="color:#8b5cf6">\\ud83e\\udd16 AI:</strong> \' + (d.response||\'No response\').replace(/\\n/g,\'<br>\');\n      box.innerHTML += \'<div class="msg-doclinks" style="margin-top:8px;padding-top:8px;border-top:1px solid var(--border)">\';\n      box.innerHTML += \'<span style="font:700 8px var(--sans);color:var(--muted);margin-right:4px">\\ud83d\\udcd6 References:</span>\';\n      box.innerHTML += \'<a class="msg-doclink" href="https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20Command%20References/downloads/Switch_Engine_33_6_1_Command_References.pdf" target="_blank" rel="noopener noreferrer">SW Engine Command References</a> \';\n      box.innerHTML += \'<a class="msg-doclink" href="https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20User%20Guide/downloads/Switch_Engine_33_6_1_User_Guide.pdf" target="_blank" rel="noopener noreferrer">SW Engine User Guide</a> \';\n      box.innerHTML += \'<a class="msg-doclink" href="https://documentation.extremenetworks.com/ExtremeXOS%20and%20Switch%20Engine%20v33.6.x%20EMS%20Messages%20Catalog/downloads/ExtremeXOS_and_Switch_Engine_33_6_x_EMS_Message_Catalog.pdf" target="_blank" rel="noopener noreferrer">EMS Messages Catalog</a>\';\n      box.innerHTML += \'</div>\';\n    })\n    .catch(function(){ box.innerHTML = \'<span style="color:#ef4444">AI unavailable</span>\'; });\n}\n'
    # ──────────────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Network Analyzer — {fname}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&family=Inter:wght@400;500;600;700;800&display=swap');
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#050a14;--panel:#0a1222;--card:#0e1a2e;--border:#1a2e4a;
  --acc:#00d4ff;--acc2:#7c5cfc;--ok:#34d399;--warn:#fbbf24;--err:#f87171;
  --text:#f1f5f9;--muted:#6b8ab0;
  --glow:0 0 20px rgba(0,212,255,.08);
  --mono:'IBM Plex Mono',monospace;--sans:'Inter',system-ui,sans-serif;
}}
/* Light theme overrides */
body.light{{
  --bg:#f0f4f8;--panel:#fff;--card:#f8fafc;--border:#d1d9e0;
  --text:#0f172a;--muted:#64748b;--glow:0 0 12px rgba(0,100,180,.06);
}}
html,body{{height:100%;overflow:hidden;background:var(--bg);color:var(--text);font-family:var(--sans);font-size:13px;-webkit-font-smoothing:antialiased}}
::-webkit-scrollbar{{width:5px;height:5px}}
::-webkit-scrollbar-track{{background:transparent}}
::-webkit-scrollbar-thumb{{background:#1e3050;border-radius:4px}}
::-webkit-scrollbar-thumb:hover{{background:#2a4060}}
::selection{{background:rgba(0,212,255,.25);color:#fff}}
.mono{{font-family:var(--mono)}}
.sm{{font-size:11px}}
.muted{{color:var(--muted)}}
.num{{font-family:var(--mono);font-weight:700;text-align:right}}
.c-acc{{color:var(--acc)}}
.clip{{max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.empty{{color:var(--muted);padding:16px;font-size:12px}}

/* ── BADGE ── */
.badge{{display:inline-block;padding:2px 9px;border-radius:5px;font:700 10px var(--mono);color:#fff;white-space:nowrap;letter-spacing:.03em}}

/* ── HEADER ── */
#hdr{{
  height:54px;background:linear-gradient(180deg,#0c1628 0%,var(--panel) 100%);
  border-bottom:1px solid var(--border);box-shadow:0 1px 12px rgba(0,0,0,.35);
  display:flex;align-items:center;gap:12px;padding:0 20px;flex-shrink:0;position:relative;z-index:10
}}
.logo{{
  width:32px;height:32px;border-radius:10px;
  background:linear-gradient(135deg,var(--acc),var(--acc2));
  display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0;
  box-shadow:0 2px 12px rgba(0,212,255,.3)
}}
.brand{{font-size:15px;font-weight:800;letter-spacing:-.4px}}
.brand em{{color:var(--acc);font-style:normal}}
.brand sup{{font-size:8px;background:linear-gradient(135deg,var(--ok),#059669);color:#000;padding:1px 5px;border-radius:4px;
  font-weight:700;vertical-align:top;margin-top:2px}}
.nav{{display:flex;gap:2px;background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:3px;margin-left:10px}}
.nav-btn{{
  background:none;border:none;color:var(--muted);font:600 12px var(--sans);
  cursor:pointer;padding:7px 18px;border-radius:8px;transition:all .2s ease
}}
.nav-btn:hover{{color:var(--text);background:rgba(255,255,255,.04)}}
.nav-btn.on{{background:linear-gradient(135deg,var(--acc),#0099cc);color:#000;font-weight:700;box-shadow:0 2px 10px rgba(0,212,255,.25)}}
.hchips{{display:flex;gap:6px;margin-left:auto;align-items:center;flex-wrap:nowrap}}
.chip{{
  background:rgba(14,26,46,.8);border:1px solid var(--border);backdrop-filter:blur(4px);
  padding:4px 11px;border-radius:14px;font:500 10px var(--mono);color:var(--muted);transition:all .2s
}}
.chip:hover{{border-color:var(--acc);color:var(--text)}}
.chip.ok{{color:var(--ok);border-color:rgba(52,211,153,.25)}}
.chip.warn{{color:var(--warn);border-color:rgba(251,191,36,.25)}}

/* ── SHELL ── */
#app{{display:flex;height:calc(100vh - 54px);overflow:hidden}}
#main{{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}}
.view{{display:none;flex:1;flex-direction:column;min-height:0;overflow:hidden}}
.view.on{{display:flex;overflow:hidden}}
.scroll{{overflow-y:auto;overflow-x:hidden;flex:1;min-height:0;padding:14px 16px;display:flex;flex-direction:column;gap:12px}}

/* ── SIDEBAR ── */
#sb{{
  width:340px;flex-shrink:0;border-left:1px solid var(--border);
  background:linear-gradient(180deg,var(--panel) 0%,#080f1c 100%);display:flex;flex-direction:column;overflow:hidden;
  position:relative;transition:width .2s ease;
}}
#sb.sb-collapsed{{width:36px!important;overflow:hidden}}
#sb.sb-collapsed .sb-hide-when-collapsed{{display:none!important}}
#sb.sb-collapsed .sb-mode-panel{{display:none!important}}
#sb-resize-handle{{
  position:absolute;left:0;top:0;bottom:0;width:5px;cursor:col-resize;
  background:transparent;z-index:10;transition:background .15s
}}
#sb-resize-handle:hover,#sb-resize-handle.dragging{{background:rgba(0,212,255,.35)}}
.sb-size-btn{{
  background:none;border:1px solid var(--border);color:var(--muted);
  border-radius:4px;padding:2px 6px;font-size:10px;cursor:pointer;line-height:1;
  transition:all .15s;flex-shrink:0
}}
.sb-size-btn:hover{{color:var(--acc);border-color:var(--acc);background:rgba(0,212,255,.07)}}
#sb.sb-collapsed .sb-collapsed-tab{{
  display:flex!important
}}
.sb-collapsed-tab{{
  display:none;flex-direction:column;align-items:center;justify-content:center;
  gap:6px;padding:10px 0;cursor:pointer;flex:1
}}
.sb-collapsed-tab span{{
  writing-mode:vertical-rl;font:700 9px var(--sans);color:var(--muted);
  letter-spacing:.1em;text-transform:uppercase
}}
.sb-hdr{{
  padding:12px 16px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:8px;flex-shrink:0;background:rgba(10,18,34,.6)
}}
.sb-hdr h3{{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em}}
.ai-chip{{
  font-size:9px;font-family:var(--mono);color:var(--muted);padding:2px 8px;
  background:var(--bg);border:1px solid var(--border);border-radius:10px;margin-left:auto
}}
.pulse{{width:7px;height:7px;border-radius:50%;background:var(--ok);animation:pulse 2s infinite;box-shadow:0 0 6px rgba(52,211,153,.4)}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.3}}}}
#msgs{{flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:8px;min-height:0}}
#sbp-chat{{flex:1;min-height:0;flex-direction:column;overflow:hidden}}
#sbp-insights{{flex:1;min-height:0;overflow-y:auto}}
.msg{{padding:10px 14px;border-radius:10px;font-size:11.5px;line-height:1.75;transition:all .15s;word-break:break-word;overflow-wrap:break-word}}
.mu{{background:linear-gradient(135deg,#0f1e3a,#142240);border:1px solid #1a3252;color:#a5c4fd;align-self:flex-end;max-width:88%;border-radius:10px 10px 2px 10px}}
.mb{{background:rgba(8,15,30,.7);border:1px solid var(--border);align-self:flex-start;max-width:100%;width:100%;border-radius:10px 10px 10px 2px;box-sizing:border-box}}
.mb strong{{color:var(--acc)}}
.mb code{{background:#0d1829;padding:2px 6px;border-radius:4px;font-family:var(--mono);font-size:10px;border:1px solid var(--border);white-space:pre-wrap;word-break:break-all}}
.msg-doclinks{{margin-top:10px;padding-top:8px;border-top:1px solid var(--border);display:flex;flex-wrap:wrap;gap:5px;align-items:center}}
.msg-doclink{{font:600 9px var(--mono);color:var(--acc);border:1px solid rgba(0,212,255,.25);border-radius:5px;padding:3px 8px;text-decoration:none;background:rgba(0,212,255,.06);white-space:nowrap;transition:all .15s}}
.msg-doclink:hover{{background:rgba(0,212,255,.15);border-color:var(--acc)}}
.think{{
  background:rgba(8,15,30,.6);border:1px solid var(--border);padding:10px 14px;
  border-radius:10px;font-size:11px;color:var(--muted);display:flex;gap:8px;align-items:center
}}
.dots span{{
  display:inline-block;width:3px;height:3px;background:var(--acc);
  border-radius:50%;animation:bop .7s infinite
}}
.dots span:nth-child(2){{animation-delay:.15s}}.dots span:nth-child(3){{animation-delay:.3s}}
@keyframes bop{{0%,100%{{transform:translateY(0)}}50%{{transform:translateY(-4px)}}}}
.qbtns{{padding:0 12px 8px;display:flex;flex-wrap:wrap;gap:5px;flex-shrink:0}}
.qb{{
  background:rgba(12,23,41,.7);border:1px solid var(--border);color:#7eb4f0;
  padding:5px 11px;border-radius:8px;font:600 10px var(--sans);cursor:pointer;transition:all .2s
}}
.qb:hover{{background:#0f1e3a;border-color:var(--acc);color:var(--acc);transform:translateY(-1px);box-shadow:0 2px 8px rgba(0,212,255,.15)}}
.qb-mcp{{background:rgba(30,10,50,.7);border-color:#7c3aed55;color:#c4b5fd}}
.qb-mcp:hover{{background:#1e0a32;border-color:#7c3aed;color:#a78bfa;box-shadow:0 2px 8px rgba(124,58,237,.2)}}
.inp-row{{padding:10px 12px;border-top:1px solid var(--border);display:flex;gap:8px;flex-shrink:0;background:rgba(10,18,34,.4)}}
.inp{{
  flex:1;background:rgba(12,23,41,.7);border:1px solid var(--border);border-radius:8px;
  padding:8px 12px;color:var(--text);font:500 11.5px var(--sans);outline:none;resize:none;height:38px;
  transition:border-color .2s
}}
.inp:focus{{border-color:var(--acc);box-shadow:0 0 0 2px rgba(0,212,255,.12)}}
.sbtn{{
  background:linear-gradient(135deg,var(--acc),var(--acc2));border:none;
  border-radius:8px;padding:8px 15px;color:#000;font-weight:700;cursor:pointer;font-size:14px;
  transition:all .2s;box-shadow:0 2px 8px rgba(0,212,255,.2)
}}
.sbtn:hover{{transform:translateY(-1px);box-shadow:0 4px 14px rgba(0,212,255,.3)}}

/* ── AI Protocol Analyst sidebar ── */
.sb-mode-bar{{display:flex;gap:2px;padding:8px 10px 0;flex-shrink:0;background:rgba(10,18,34,.6);border-bottom:1px solid var(--border)}}
.sb-mode-btn{{flex:1;background:none;border:none;color:var(--muted);font:600 9px var(--sans);padding:5px 2px;border-radius:5px 5px 0 0;cursor:pointer;text-align:center;border-bottom:2px solid transparent;transition:all .2s}}
.sb-mode-btn:hover{{color:var(--text)}}
.sb-mode-btn.on{{color:var(--acc);border-bottom-color:var(--acc);background:rgba(0,212,255,.05)}}
#sbm-mcp.on{{color:#a78bfa;border-bottom-color:#7c3aed;background:rgba(124,58,237,.08)}}
.sb-mode-panel{{display:none;flex:1;flex-direction:column;overflow-y:auto;min-height:0}}
.sb-mode-panel.on{{display:flex}}
/* Insights panel */
.insight-section{{padding:10px 12px;border-bottom:1px solid var(--border);flex-shrink:0}}
.insight-label{{font:700 8px var(--sans);text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:6px}}
.proto-chips{{display:flex;flex-wrap:wrap;gap:4px}}
.proto-chip{{
  font:700 9px var(--mono);padding:3px 8px;border-radius:10px;cursor:pointer;
  border:1px solid transparent;transition:all .15s;white-space:nowrap
}}
.proto-chip:hover{{filter:brightness(1.3);transform:translateY(-1px)}}
.behavior-tags{{display:flex;flex-wrap:wrap;gap:4px}}
.btag{{
  font:600 9px var(--sans);padding:2px 8px;border-radius:8px;
  background:rgba(255,255,255,.05);border:1px solid var(--border);color:var(--text);
  white-space:nowrap
}}
.risk-bar-wrap{{margin-top:4px}}
.risk-bar-bg{{background:#1e2535;border-radius:3px;height:6px}}
.risk-bar-fill{{height:6px;border-radius:3px;transition:width .4s ease}}
/* Action panel */
.action-grid{{display:grid;grid-template-columns:1fr 1fr;gap:6px;padding:10px 12px;flex-shrink:0}}
.action-card{{
  background:rgba(12,23,41,.8);border:1px solid var(--border);border-radius:8px;
  padding:10px 8px;cursor:pointer;transition:all .2s;text-align:center
}}
.action-card:hover{{border-color:var(--acc);background:rgba(0,212,255,.05);transform:translateY(-1px);box-shadow:0 3px 10px rgba(0,212,255,.12)}}
.action-card .ac-icon{{font-size:18px;margin-bottom:4px}}
.action-card .ac-label{{font:700 9px var(--sans);color:var(--text);text-transform:uppercase;letter-spacing:.05em}}
.action-card .ac-sub{{font:400 8px var(--sans);color:var(--muted);margin-top:2px}}
/* Proto picker */
.proto-pick-wrap{{padding:10px 12px;flex-shrink:0}}
.proto-pick-title{{font:700 9px var(--sans);text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-bottom:8px;display:flex;align-items:center;gap:8px}}
.proto-pick-back{{background:none;border:1px solid var(--border);color:var(--muted);padding:1px 7px;border-radius:4px;font:600 8px var(--sans);cursor:pointer}}
.proto-pick-back:hover{{color:var(--text);border-color:var(--acc)}}
.proto-pick-grid{{display:flex;flex-wrap:wrap;gap:5px;margin-top:6px}}
.rfc-manual-row{{display:flex;gap:6px;padding:10px 12px;border-top:1px solid var(--border);flex-shrink:0;align-items:center}}
.rfc-num-inp{{flex:1;background:#0d1829;border:1px solid var(--border);color:var(--text);padding:4px 8px;border-radius:5px;font:500 10px var(--mono);outline:none}}
.rfc-num-inp:focus{{border-color:var(--acc)}}
/* Suggested actions */
.sugg-list{{padding:0 12px 8px;flex-shrink:0}}
.sugg-item{{
  display:flex;align-items:center;gap:8px;padding:6px 8px;margin-bottom:4px;
  background:rgba(12,23,41,.8);border:1px solid var(--border);border-radius:6px;
  cursor:pointer;transition:all .15s;font:500 10px var(--sans);color:var(--text)
}}
.sugg-item:hover{{border-color:var(--acc);background:rgba(0,212,255,.06)}}
.sugg-arrow{{color:var(--acc);font-size:12px;margin-left:auto}}

/* ── CARDS ── */
.card{{background:var(--card);border:1px solid var(--border);border-radius:12px;overflow:hidden;transition:border-color .2s,box-shadow .2s}}
.card:hover{{border-color:#243a5c;box-shadow:var(--glow)}}
.ch{{
  padding:10px 16px;background:linear-gradient(180deg,#0a1422 0%,#0c1628 100%);border-bottom:1px solid var(--border);
  font:700 11px var(--sans);text-transform:uppercase;letter-spacing:.08em;color:var(--acc);
  display:flex;align-items:center;gap:7px
}}
.ch .cnt{{
  background:var(--panel);border:1px solid var(--border);color:var(--muted);
  font:400 9px var(--mono);padding:2px 8px;border-radius:10px;margin-left:auto
}}
.cb{{padding:14px 15px}}
.row2{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
.row3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}}

/* ── TABLES ── */
table{{width:100%;border-collapse:collapse;font-size:11px}}
th{{
  background:linear-gradient(180deg,#07101a 0%,#091420 100%);padding:8px 10px;text-align:left;font-size:10px;
  text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:700;
  position:sticky;top:0;z-index:2;border-bottom:2px solid var(--border)
}}
td{{padding:7px 10px;border-bottom:1px solid rgba(18,30,48,.6);vertical-align:middle}}
tr:hover td{{background:rgba(19,38,64,.5);cursor:pointer}}
tr:last-child td{{border-bottom:none}}

/* ── STAT CARDS ── */
.stats-row{{display:grid;grid-template-columns:repeat(auto-fill,minmax(135px,1fr));gap:10px}}
.sc{{
  background:linear-gradient(160deg,var(--card) 0%,#0b1525 100%);border:1px solid var(--border);border-radius:12px;
  padding:14px 14px 12px;position:relative;overflow:hidden;cursor:pointer;transition:all .25s ease
}}
.sc:hover{{border-color:var(--c,var(--acc));transform:translateY(-2px);box-shadow:0 4px 20px rgba(0,0,0,.3)}}
.sc::after{{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--c,var(--acc)),transparent);border-radius:3px 3px 0 0}}
.sc-n{{font-size:28px;font-weight:800;font-family:var(--mono);color:var(--c,var(--acc));line-height:1}}
.sc-l{{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-top:5px;font-weight:600}}
.sc-sub{{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;font-size:10px;color:var(--muted);font-family:var(--mono)}}
.sc-sub b{{color:var(--text)}}

/* ── IP BARS ── */
.ip-row{{display:flex;align-items:center;gap:8px;margin-bottom:7px}}
.ip-addr{{font-family:var(--mono);min-width:115px;font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.ip-track{{flex:1;height:7px;background:#0d1829;border-radius:4px;overflow:hidden}}
.ip-fill{{height:100%;border-radius:4px;transition:width .4s ease}}
.ip-cnt{{font-family:var(--mono);color:var(--muted);font-size:9px;min-width:24px;text-align:right}}

/* ── ANOMALIES ── */
.anom-row{{
  background:linear-gradient(135deg,#1f0a0a,#1a0808);border:1px solid rgba(239,68,68,.3);border-radius:8px;
  padding:11px 15px;display:flex;align-items:center;gap:10px;font-size:12px;
  color:#fca5a5;margin-bottom:7px;transition:all .2s
}}
.anom-row:hover{{border-color:rgba(239,68,68,.5);background:#220c0c}}
.anom-icon{{color:#ef4444;font-size:16px;flex-shrink:0}}
.ok-row{{
  background:linear-gradient(135deg,#0a1d12,#081a10);border:1px solid rgba(52,211,153,.2);border-radius:8px;
  padding:10px 14px;display:flex;align-items:center;gap:9px;font-size:12px;color:#6ee7b7
}}
.anom-filter-btn{{
  background:none;border:1px solid var(--border);color:var(--muted);padding:3px 10px;
  border-radius:4px;font:600 10px var(--sans);cursor:pointer;transition:all .15s
}}
.anom-filter-btn:hover{{border-color:var(--acc);color:var(--acc)}}
.anom-filter-btn.active{{background:var(--acc);border-color:var(--acc);color:#000}}

/* ── FLOWS+PROTOCOLS MERGED TAB ── */
.fp-tab{{
  background:none;border:none;border-bottom:2px solid transparent;
  color:var(--muted);padding:10px 20px;cursor:pointer;
  font:600 11px var(--sans);transition:all .15s;white-space:nowrap
}}
.fp-tab:hover{{color:var(--text)}}
.fp-tab.on{{color:var(--acc);border-bottom-color:var(--acc)}}
.fp-panel{{display:none;flex:1;flex-direction:column;min-height:0}}
.fp-panel.active{{display:flex}}
#fp-panel-proto.active{{overflow-y:auto}}


/* ── SERVICE CARDS ── */
.svc-card{{
  background:rgba(8,15,30,.6);border:1px solid var(--border);padding:8px 13px;
  border-radius:8px;min-width:85px;transition:all .2s
}}
.svc-card:hover{{border-color:var(--acc);transform:translateY(-1px)}}
.svc-name{{color:var(--acc);font-size:12px;font-weight:700}}
.svc-cnt{{color:var(--muted);font-size:10px;margin-top:2px}}

/* ── PACKETS VIEW ── */
.ws-bar{{
  padding:8px 14px;background:linear-gradient(180deg,#07101a 0%,#091320 100%);border-bottom:1px solid var(--border);
  display:flex;gap:8px;align-items:center;flex-shrink:0;flex-wrap:wrap
}}
.ws-filter{{
  flex:1;min-width:200px;background:rgba(12,23,41,.7);border:1px solid var(--border);
  border-radius:8px;padding:6px 12px;color:var(--text);font:400 11px var(--mono);outline:none;
  transition:all .2s
}}
.ws-filter:focus{{border-color:var(--acc);box-shadow:0 0 0 2px rgba(0,212,255,.1)}}
.ws-fbtn{{
  background:#0d1829;border:1px solid var(--border);color:#94a3b8;
  padding:5px 12px;border-radius:7px;font:600 10px var(--sans);cursor:pointer;transition:all .2s
}}
.ws-fbtn:hover{{border-color:var(--acc);color:var(--acc);background:#0f1e3a}}
#ptw{{flex:1;overflow-y:auto;min-height:0;position:relative}}
#pt{{width:100%;border-collapse:collapse;font-size:11px;font-family:var(--mono);table-layout:fixed}}
#pt th{{
  background:linear-gradient(180deg,#06101d 0%,#081422 100%);padding:6px 9px;text-align:left;font-size:9px;text-transform:uppercase;
  letter-spacing:.07em;color:var(--muted);position:sticky;top:0;z-index:5;
  border-bottom:2px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap;transition:color .15s
}}
#pt th:hover{{color:var(--acc)}}
/* Virtual scroll: uniform row height keeps position arithmetic exact */
#pt td{{padding:4px 9px;border-bottom:1px solid rgba(16,28,46,.5);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:220px;height:26px;line-height:18px;box-sizing:border-box}}
/* Spacer row inside tbody that gives the scroll container its full height */
#pt-spc td{{border:none;padding:0;height:0}}
/* Row-count status bar above the filter bar */
#pt-row-count{{font:600 10px var(--mono);color:#4a7090;padding:3px 14px;flex-shrink:0;
  background:linear-gradient(180deg,#050e1a,#07101a);border-bottom:1px solid var(--border);user-select:none}}
#pt tr{{cursor:pointer;transition:background .12s}}
#pt tr:hover td{{background:rgba(14,30,53,.6)}}
#pt tr.sel td{{background:rgba(16,42,64,.7)!important;outline-left:3px solid var(--acc)}}

/* ── DETAIL PANE ── */
#dpane{{flex-shrink:0;border-top:1px solid var(--border);display:flex;flex-direction:column;background:rgba(8,14,24,.5)}}
#dresz{{height:5px;background:var(--border);cursor:row-resize;transition:background .15s}}
#dresz:hover{{background:var(--acc);box-shadow:0 0 8px rgba(0,212,255,.3)}}
#dtabs{{
  display:flex;background:linear-gradient(180deg,#06101d 0%,#081420 100%);border-bottom:1px solid var(--border);
  flex-shrink:0;padding:0 14px;gap:2px
}}
.dtab{{
  padding:7px 15px;background:none;border:none;color:var(--muted);
  font:700 10px var(--sans);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;transition:all .15s
}}
.dtab:hover{{color:var(--text);background:rgba(255,255,255,.02)}}
.dtab.on{{color:var(--acc);border-bottom-color:var(--acc)}}
#dbody{{overflow-y:auto;flex:1;min-height:0}}
.ws-tree{{padding:8px 12px;font-family:var(--mono);font-size:11px;line-height:1.8}}
.wl{{margin-bottom:4px}}
.wl-hdr{{cursor:pointer;display:flex;align-items:center;gap:6px;padding:2px 4px;border-radius:4px}}
.wl-hdr:hover{{background:#0e1e35}}
.wl-hdr .arr{{color:var(--muted);font-size:10px;width:10px;flex-shrink:0}}
.wl-title{{font-weight:700}}
.wl-fields{{padding-left:22px}}
.wf{{display:flex;gap:0;padding:1px 4px;border-radius:3px}}
.wf:hover{{background:#0e1e35}}
.wfn{{color:#475569;min-width:160px;flex-shrink:0}}
.wfv{{color:var(--text)}}
.wfnote{{color:#2d3f55;font-size:10px;margin-left:8px;font-style:italic}}
.hex-wrap{{padding:8px 12px;font-family:var(--mono);font-size:10px;line-height:1.7;color:#64748b}}
.hrow{{display:flex;gap:16px}}
.hoff{{color:#2d3f55;min-width:40px}}
.hbytes{{color:#94a3b8;flex:1}}
.hascii{{color:#475569}}

/* ── TIMELINE ── */
.tl-bar{{display:flex;gap:4px;flex-wrap:wrap;flex:1;justify-content:flex-end}}
.tl-btn{{
  background:rgba(13,24,41,.7);border:1px solid var(--border);color:#64748b;
  padding:3px 9px;border-radius:7px;font:700 9px var(--sans);cursor:pointer;transition:all .2s
}}
.tl-btn:hover,.tl-btn.on{{color:#fff;border-color:var(--c,var(--acc));background:rgba(15,30,53,.8);box-shadow:0 0 6px rgba(0,212,255,.1)}}
#tl-sel{{display:none;margin-top:6px;background:#0d1829;border:1px solid var(--border);border-radius:6px;padding:7px 11px;font:400 10px var(--mono);color:var(--text)}}

/* ── PROTOCOLS EXTRA TABS ── */
.ptab-bar{{
  display:flex;gap:5px;flex-wrap:wrap;padding:8px 14px;background:linear-gradient(180deg,#07101a 0%,#091320 100%);
  border-bottom:1px solid var(--border);flex-shrink:0
}}
.ptab{{
  background:rgba(12,23,41,.7);border:1px solid var(--border);color:#94a3b8;
  padding:5px 12px;border-radius:7px;font:700 10px var(--sans);cursor:pointer;transition:all .2s
}}
.ptab:hover{{border-color:var(--c,var(--acc));color:var(--c,var(--acc));background:rgba(15,30,53,.5)}}
.ptab.on{{background:var(--c,var(--acc));color:#000;border-color:var(--c,var(--acc));box-shadow:0 2px 8px rgba(0,0,0,.2)}}
.pcnt{{
  display:inline-block;background:rgba(30,45,69,.7);color:#94a3b8;
  font-family:var(--mono);font-size:9px;padding:1px 6px;border-radius:10px;margin-left:4px
}}
/* ── EXPORT BUTTONS ── */
.exp-btn{{
  background:rgba(13,24,41,.7);border:1px solid var(--border);color:#94a3b8;
  padding:4px 10px;border-radius:7px;font:600 9px var(--sans);cursor:pointer;
  text-decoration:none;display:inline-flex;align-items:center;gap:3px;transition:all .2s
}}
.exp-btn:hover{{border-color:var(--acc);color:var(--acc);background:rgba(15,30,53,.5)}}
/* ── UPLOAD ── */
.upload-btn{{
  background:rgba(13,24,41,.7);border:1px solid rgba(52,211,153,.4);color:#34d399;
  padding:4px 10px;border-radius:7px;font:600 9px var(--sans);cursor:pointer;
  display:inline-flex;align-items:center;gap:3px;transition:all .2s
}}
.upload-btn:hover{{background:#34d399;color:#070d1a;box-shadow:0 2px 8px rgba(52,211,153,.25)}}
#drop-overlay{{
  display:none;position:fixed;inset:0;z-index:9999;
  background:rgba(5,10,20,0.88);backdrop-filter:blur(10px);
  flex-direction:column;align-items:center;justify-content:center;gap:14px
}}
#drop-overlay.active{{display:flex}}
#drop-overlay .drop-box{{
  border:2px dashed rgba(52,211,153,.6);border-radius:20px;padding:48px 70px;
  text-align:center;color:#e2e8f0;font:600 17px var(--sans);
  background:rgba(14,26,46,.4);backdrop-filter:blur(4px);transition:all .3s
}}
#drop-overlay .drop-box:hover{{border-color:#34d399;background:rgba(14,26,46,.6)}}
#drop-overlay .drop-sub{{color:var(--muted);font-size:12px;margin-top:8px}}
/* ── PCAP SOURCE TABS ── */
.pcap-tab{{
  background:rgba(13,24,41,.7);border:1px solid var(--border);color:#64748b;
  padding:4px 11px;border-radius:7px;font:600 9px var(--sans);cursor:pointer;
  transition:all .2s;white-space:nowrap
}}
.pcap-tab.active{{border-color:#3b82f6;color:#60a5fa;background:rgba(59,130,246,.1)}}
.pcap-tab:hover{{border-color:#3b82f6;color:#93c5fd;background:rgba(59,130,246,.05)}}
/* ── FLOW DIAGRAM ── */
#flow-cv{{cursor:default}}
#flow-scroll{{scrollbar-width:thin;scrollbar-color:#1e3a5f #070d1a}}

/* ── TERMINAL ── */
#term-out .t-err{{color:#f87171}}
#term-out .t-sys{{color:#4a6080}}
.ppanel{{display:none;overflow-y:auto;max-height:350px}}

/* ── GLOBAL ENHANCEMENTS ── */
.scroll{{scroll-behavior:smooth}}
.wl-hdr:hover{{background:rgba(14,30,53,.5)}}
.wf:hover{{background:rgba(14,30,53,.4)}}
.card,.sc{{will-change:transform}}

/* ── Bookmark star on rows ── */
tr.bookmarked td:first-child::before{{content:'★ ';color:var(--warn)}}

/* ── Command Palette ── */
#cmd-palette{{
  display:none;position:fixed;top:0;left:0;width:100%;height:100%;z-index:9999;
  background:rgba(0,0,0,.55);backdrop-filter:blur(3px);justify-content:center;padding-top:14vh;
}}
#cmd-palette.open{{display:flex}}
#cmd-box{{
  width:500px;max-width:90vw;background:var(--panel);border:1px solid var(--border);border-radius:12px;
  box-shadow:0 20px 60px rgba(0,0,0,.5);overflow:hidden
}}
#cmd-input{{
  width:100%;padding:14px 18px;background:transparent;border:none;border-bottom:1px solid var(--border);
  color:var(--text);font:500 14px var(--sans);outline:none
}}
#cmd-results{{max-height:300px;overflow-y:auto;padding:6px 0}}
.cmd-item{{padding:8px 18px;cursor:pointer;display:flex;align-items:center;gap:10px;font:500 12px var(--sans);color:var(--text)}}
.cmd-item:hover,.cmd-item.sel{{background:rgba(0,212,255,.08)}}
.cmd-item .cmd-key{{margin-left:auto;font:500 10px var(--mono);color:var(--muted);background:var(--card);padding:2px 6px;border-radius:3px;border:1px solid var(--border)}}

/* ── Shortcut Modal ── */
#shortcut-modal{{
  display:none;position:fixed;top:0;left:0;width:100%;height:100%;z-index:9998;
  background:rgba(0,0,0,.55);backdrop-filter:blur(3px);justify-content:center;align-items:center
}}
#shortcut-modal.open{{display:flex}}
.shortcut-card{{
  background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:24px 32px;
  max-width:450px;width:90vw;box-shadow:0 20px 60px rgba(0,0,0,.5)
}}
.shortcut-card h3{{color:var(--acc);font:700 14px var(--sans);margin-bottom:14px}}
.shortcut-row{{display:flex;justify-content:space-between;padding:5px 0;font:400 12px var(--sans);color:var(--text);border-bottom:1px solid var(--border)}}
.shortcut-row:last-child{{border-bottom:none}}
.shortcut-row kbd{{background:var(--card);padding:2px 8px;border-radius:4px;font:600 10px var(--mono);color:var(--acc);border:1px solid var(--border)}}

/* ── Light theme overrides ── */
body.light #hdr{{background:linear-gradient(180deg,#e8eef5 0%,#dce4ed 100%)}}
body.light .card{{background:#fff;border-color:#d1d9e0;box-shadow:0 1px 3px rgba(0,0,0,.08)}}
body.light .sc{{background:#fff;border-color:#d1d9e0}}
body.light .nav-btn{{color:#334155}}
body.light .nav-btn.on{{background:rgba(0,150,220,.12);color:#0077b6}}
body.light .badge{{filter:brightness(1.1)}}
body.light #sb{{background:linear-gradient(180deg,#f0f4f8 0%,#e8eef5 100%)}}
body.light .msg.mb{{background:#f4f7fa;border-color:#d1d9e0}}
body.light #cmd-box{{background:#fff}}
body.light .shortcut-card{{background:#fff}}
</style>
</head>
<body>

<!-- ═══ DRAG & DROP OVERLAY ═══ -->
<div id="drop-overlay">
  <div class="drop-box">
    📂 Drop PCAP file here
    <div class="drop-sub">Supports .pcap files (libpcap format)</div>
  </div>
</div>

<!-- ═══ COMMAND PALETTE (Ctrl+K) ═══ -->
<div id="cmd-palette" onclick="if(event.target===this)closePalette()">
  <div id="cmd-box">
    <input id="cmd-input" type="text" placeholder="Type a command or search… (Esc to close)" oninput="filterCmds()" onkeydown="cmdKey(event)">
    <div id="cmd-results"></div>
  </div>
</div>

<!-- ═══ KEYBOARD SHORTCUTS MODAL ═══ -->
<div id="shortcut-modal" onclick="if(event.target===this)this.classList.remove('open')">
  <div class="shortcut-card">
    <h3>⌨ Keyboard Shortcuts</h3>
    <div class="shortcut-row"><span>Command Palette</span><kbd>⌘K</kbd></div>
    <div class="shortcut-row"><span>Dashboard</span><kbd>1</kbd></div>
    <div class="shortcut-row"><span>Packet Summary</span><kbd>2</kbd></div>
    <div class="shortcut-row"><span>Protocol Flow Summary</span><kbd>3</kbd></div>
    <div class="shortcut-row"><span>Anomaly Detection</span><kbd>4</kbd></div>
    <div class="shortcut-row"><span>Trap Analysis</span><kbd>5</kbd></div>
    <div class="shortcut-row"><span>Terminal</span><kbd>6</kbd></div>
    <div class="shortcut-row"><span>Next Packet</span><kbd>↓ / J</kbd></div>
    <div class="shortcut-row"><span>Prev Packet</span><kbd>↑ / K</kbd></div>
    <div class="shortcut-row"><span>Bookmark Packet</span><kbd>B</kbd></div>
    <div class="shortcut-row"><span>Focus Filter</span><kbd>/</kbd></div>
    <div class="shortcut-row"><span>Toggle Theme</span><kbd>T</kbd></div>
    <div class="shortcut-row"><span>Close Overlay</span><kbd>Esc</kbd></div>
    <div style="margin-top:12px;text-align:center"><button onclick="document.getElementById('shortcut-modal').classList.remove('open')" style="background:var(--acc);border:none;color:#000;padding:6px 20px;border-radius:6px;font:700 11px var(--sans);cursor:pointer">Got it</button></div>
  </div>
</div>

<!-- ═══ HEADER ═══ -->
<div id="hdr">
  <div class="logo">🔬</div>
  <div class="brand">AI <em>Network</em> <sup>Analyzer</sup></div>
  <nav class="nav">
    <button class="nav-btn" onclick="window.location='/reset'" title="Return to home page" style="font-size:14px;padding:7px 10px">🏠</button>
    <button class="nav-btn on"  id="nb-overview"  onclick="goView('overview',this)">Dashboard</button>
    <button class="nav-btn"     id="nb-packets"   onclick="goView('packets',this)">Packet Summary</button>
    <button class="nav-btn"     id="nb-flowproto" onclick="goView('flowproto',this)">Protocol Flow Summary</button>
    <button class="nav-btn"     id="nb-anomalies" onclick="goView('anomalies',this)">Anomaly Detection</button>
    <button class="nav-btn"     id="nb-traps"     onclick="goView('traps',this)">Trap Analysis</button>
    <button class="nav-btn"     id="nb-terminal"  onclick="goView('terminal',this)">Terminal</button>
  </nav>
  <div style="display:flex;gap:4px;align-items:center;margin-left:4px">
    <button onclick="toggleTheme()" id="theme-btn" style="background:none;border:1px solid var(--border);color:var(--muted);padding:3px 8px;border-radius:5px;cursor:pointer;font-size:12px" title="Toggle light/dark theme">🌙</button>
    <button onclick="showShortcuts()" style="background:none;border:1px solid var(--border);color:var(--muted);padding:3px 8px;border-radius:5px;cursor:pointer;font:600 10px var(--sans)" title="Keyboard shortcuts">⌨ ?</button>
  </div>
  <div class="hchips">
    <span class="chip">📁 {fname}</span>
    <span class="chip">📦 {total:,} pkts</span>
    <span class="chip ok">✓ {switch_info}</span>
    {f'<span class="chip warn" style="cursor:pointer" onclick="goView(\'anomalies\',document.getElementById(\'nb-anomalies\'))">⚠ {len(anom)} anomal{"y" if len(anom)==1 else "ies"}</span>' if anom else ''}
    <div style="display:flex;gap:4px;margin-left:4px;align-items:center">
      <div id="pcap-tabs" style="display:flex;gap:2px;margin-right:4px">
        <button class="pcap-tab {'active' if ACTIVE_SLOT=='original' else ''}" id="pt-original" onclick="switchPcap('original',this)" title="Switch to captured/original PCAP" style="{'display:none' if 'original' not in PCAP_SLOTS else ''}">📡 Captured</button>
        <button class="pcap-tab {'active' if ACTIVE_SLOT=='uploaded' else ''}" id="pt-uploaded" onclick="switchPcap('uploaded',this)" title="Switch to uploaded PCAP" style="{'' if _up_visible else 'display:none'}">📂 {_up_fname}</button>
      </div>
      <button class="upload-btn" onclick="document.getElementById('pcap-file').click()" title="Upload a PCAP file">⬆ Upload PCAP</button>
      <input type="file" id="pcap-file" accept=".pcap,.pcapng" style="display:none" onchange="uploadPcap(this.files[0])">
      <button class="upload-btn" onclick="document.getElementById('trap-csv-file').click()" title="Upload a trap CSV file" style="background:linear-gradient(135deg,#7c5cfc,#5a3ec8);color:#fff">⚡ Trap CSV</button>
      <input type="file" id="trap-csv-file" accept=".csv,.CSV,.json,.JSON,.txt" style="display:none" onchange="uploadTrapCsvHeader(this.files[0])">
      <a href="/export/json" class="exp-btn" title="Export JSON">⬇ JSON</a>
      <a href="/export/csv"  class="exp-btn" title="Export CSV">⬇ CSV</a>
      <a href="/export/pcap" class="exp-btn" title="Download PCAP">⬇ PCAP</a>
    </div>
  </div>
</div>

<!-- ═══ APP SHELL ═══ -->
<div id="app">
<div id="main">

<!-- ═══ OVERVIEW ═══ -->
<div id="view-overview" class="view on">
<div class="scroll">

  <div class="stats-row">
    <div class="sc" style="--c:var(--acc)" onclick="goView('packets',document.getElementById('nb-packets'))">
      <div class="sc-n">{total:,}</div>
      <div class="sc-l">Total Packets</div>
      <div class="sc-sub"><span>Bytes: <b>{total_bytes:,}</b></span></div>
    </div>
    {dyn_cards}
    <div class="sc" style="--c:{'#ef4444' if anom else '#10b981'}" {_anom_onclick}>
      <div class="sc-n" style="font-size:18px">{"⚠ "+str(len(anom)) if anom else "✓"}</div>
      <div class="sc-l">Anomalies</div>
      <div class="sc-sub"><span>{"Click to investigate →" if anom else "None found"}</span></div>
    </div>
  </div>

  <div class="row3">
    <div class="card">
      <div class="ch">Protocol Distribution</div>
      <div class="cb" style="height:190px;position:relative;overflow:hidden"><canvas id="donut"></canvas></div>
    </div>
    <div class="card">
      <div class="ch">Top Source IPs</div>
      <div class="cb">{src_bars}</div>
    </div>
    <div class="card">
      <div class="ch">Top Dest IPs</div>
      <div class="cb">{dst_bars}</div>
    </div>
  </div>

  <div class="row2">
    <div class="card">
      <div class="ch">Anomaly Detection <span class="cnt">{len(anom)} found</span></div>
      <div class="cb">{anom_html}</div>
    </div>
    <div class="card">
      <div class="ch">Services Detected <span class="cnt">{len(svcs)}</span></div>
      <div class="cb"><div style="display:flex;flex-wrap:wrap;gap:6px">{svc_html}</div></div>
    </div>
  </div>

  <div class="card">
    <div class="ch">Top Conversations <span class="cnt">{len(_convos_stats)} pairs</span></div>
    <div class="cb" style="max-height:240px;overflow-y:auto;overflow-x:hidden;padding-right:8px">{convo_html}</div>
  </div>

  <div class="card">
    <div class="ch">
      Packet Timeline
      <div class="tl-bar">
        <button class="tl-btn on" data-proto="ALL" style="--c:#e2e8f0" onclick="tlFilter(this)">ALL</button>
        {tl_btns}
        <button class="tl-btn" onclick="if(tlChart)tlChart.resetZoom()" style="margin-left:2px;--c:#94a3b8">Reset</button>
      </div>
    </div>
    <div style="padding:10px 13px">
      <div style="height:220px;position:relative;overflow:hidden"><canvas id="tl-cv"></canvas></div>
      <div class="sm muted" style="margin-top:4px;text-align:right">scroll=zoom · drag=pan · click dot to inspect packet</div>
      <div id="tl-sel"></div>
    </div>
  </div>

</div><!-- /scroll -->
</div><!-- /view-overview -->

<!-- ═══ FLOWS + PROTOCOLS ═══ -->
<div id="view-flowproto" class="view" style="flex-direction:column">

  <!-- Sub-tab bar -->
  <div style="padding:0 14px;background:#07101a;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:0;flex-shrink:0">
    <button class="fp-tab on" id="fp-tab-proto"   onclick="fpTab('proto')">Protocol Stats</button>
    <button class="fp-tab"    id="fp-tab-flows"   onclick="fpTab('flows')">⇄ Flow Diagram</button>
  </div>

  <!-- ── Protocol Stats ── -->
  <div id="fp-panel-proto" class="fp-panel active">
    <div class="row3" style="padding:14px 16px 0;flex-shrink:0">
      <div class="card">
        <div class="ch">Bandwidth by Protocol</div>
        <div class="cb">{_proto_bw_html}</div>
      </div>
      <div class="card">
        <div class="ch">TCP Session Health</div>
        <div class="cb">{_tcp_health_html}</div>
      </div>
      <div class="card">
        <div class="ch">Request / Response Ratios</div>
        <div class="cb">{_proto_completeness_html}</div>
      </div>
    </div>
    <div style="padding:8px 16px 4px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;flex-shrink:0">
      <button class="collapsible-btn" onclick="toggleCollapsible('tcp-flags')" style="background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:10px 14px;cursor:pointer;font:600 11px var(--sans);color:var(--acc);white-space:nowrap">▶ TCP Flags ({len(tcp)} pkts)</button>
      <button class="collapsible-btn" onclick="toggleCollapsible('icmp-types')" style="background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:10px 14px;cursor:pointer;font:600 11px var(--sans);color:var(--acc);white-space:nowrap">▶ ICMP Types ({len(icmp)} pkts)</button>
      <button class="collapsible-btn" onclick="toggleCollapsible('arp-analysis')" style="background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:10px 14px;cursor:pointer;font:600 11px var(--sans);color:var(--acc);white-space:nowrap">▶ ARP Analysis</button>
      <button class="collapsible-btn" onclick="toggleCollapsible('services')" style="background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:10px 14px;cursor:pointer;font:600 11px var(--sans);color:var(--acc);white-space:nowrap">▶ Services ({len(svcs)})</button>
    </div>

    <div style="padding:0 16px 14px;display:flex;flex-direction:column;gap:12px">
      <div id="tcp-flags" class="collapsible-section" style="display:none">
        <div class="card">
          <div class="ch">TCP Flags <span class="cnt">{len(tcp)} pkts</span></div>
          <div class="cb"><table><thead><tr><th>Flag</th><th>Count</th><th>Meaning</th></tr></thead>
          <tbody>{tcp_flag_rows}</tbody></table></div>
        </div>
      </div>
      <div id="icmp-types" class="collapsible-section" style="display:none">
        <div class="card">
          <div class="ch">ICMP Types <span class="cnt">{len(icmp)} pkts</span></div>
          <div class="cb"><table><thead><tr><th>Type</th><th>Count</th><th>Dir</th></tr></thead>
          <tbody>{icmp_rows}</tbody></table></div>
        </div>
      </div>
      <div id="arp-analysis" class="collapsible-section" style="display:none">
        <div class="card">
          <div class="ch">ARP Analysis</div>
          <div class="cb"><table><thead><tr><th>Metric</th><th>Value</th><th>Notes</th></tr></thead>
          <tbody>{arp_analysis_rows}</tbody></table></div>
        </div>
      </div>
      <div id="services" class="collapsible-section" style="display:none">
        <div class="card">
          <div class="ch">Services <span class="cnt">{len(svcs)}</span></div>
          <div class="cb"><table><thead><tr><th>Service</th><th>Packets</th><th>Share</th></tr></thead>
          <tbody>{svc_rows}</tbody></table></div>
        </div>
      </div>
      <div class="card">
        <div class="ch">RFC-Compliant Request-Response Analysis</div>
        <div style="display:flex;gap:8px;margin-bottom:12px;padding:8px 0;flex-wrap:wrap">
          <button onclick="toggleCompleteAnalysis()" style="background:linear-gradient(135deg,var(--acc),var(--acc2));border:none;border-radius:6px;padding:6px 14px;color:#000;font:700 11px var(--sans);cursor:pointer">🤖 Ask AI for complete analysis</button>
        </div>
        <div id="complete-analysis-ai" style="display:none;background:var(--bg2);border-radius:6px;padding:12px;margin-bottom:12px;max-height:500px;overflow-y:auto">
          <div id="complete-analysis-resp" class="sm" style="color:var(--text);line-height:1.7"></div>
        </div>
      </div>
      {(f'<div class="ptab-bar" id="ptab-bar">' + extra_tabs_html + '</div>' + extra_panels_html) if extra_tabs_html else ''}
    </div>
  </div><!-- /fp-panel-proto -->

  <!-- ── Flow Diagram ── -->
  <div id="fp-panel-flows" class="fp-panel">
    <div style="padding:8px 14px;background:#07101a;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;flex-shrink:0">
      <span style="font:700 11px var(--sans);text-transform:uppercase;letter-spacing:.08em;color:var(--acc)">⇄ Flow Sequence Diagram</span>
      <span class="muted sm" id="flow-count"></span>
      <div style="margin-left:auto;display:flex;gap:6px;align-items:center">
        <label class="muted sm">Filter:</label>
        <select id="flow-proto-filter" onchange="buildFlowDiagram()" style="background:#0d1829;border:1px solid var(--border);color:var(--text);padding:3px 8px;border-radius:4px;font:600 10px var(--mono)">
          <option value="ALL">All Protocols</option>
        </select>
        <label class="muted sm">Hosts:</label>
        <select id="flow-host-filter" onchange="buildFlowDiagram()" style="background:#0d1829;border:1px solid var(--border);color:var(--text);padding:3px 8px;border-radius:4px;font:600 10px var(--mono)">
          <option value="ALL">All Hosts</option>
        </select>
        <button onclick="flowZoomIn()" style="background:#0d1829;border:1px solid var(--border);color:var(--text);padding:3px 8px;border-radius:4px;cursor:pointer;font:14px monospace" title="Zoom In">+</button>
        <button onclick="flowZoomOut()" style="background:#0d1829;border:1px solid var(--border);color:var(--text);padding:3px 8px;border-radius:4px;cursor:pointer;font:14px monospace" title="Zoom Out">-</button>
        <button onclick="flowResetZoom()" style="background:#0d1829;border:1px solid var(--border);color:#64748b;padding:3px 10px;border-radius:4px;font:600 10px var(--sans);cursor:pointer" title="Reset">Reset</button>
      </div>
    </div>
    <div style="flex:1;overflow:auto;position:relative" id="flow-scroll">
      <canvas id="flow-cv"></canvas>
    </div>
  </div><!-- /fp-panel-flows -->

</div><!-- /view-flowproto -->

<!-- ═══ PACKETS ═══ -->
<div id="view-packets" class="view" style="flex-direction:column">

  <div class="ws-bar">
    <input class="ws-filter" id="pf" type="text" placeholder="Filter: tcp  ip 10.x  port 443  flags RST  vlan 10  mac aa:bb  bookmarked" oninput="_debouncedFilter()">
    <button class="ws-fbtn" onclick="clearFilter()">Clear</button>
    <button class="ws-fbtn" onclick="qFilter('bookmarked')" style="color:var(--warn)" title="Show bookmarked packets">★</button>
    {proto_qbtns}
  </div>

  <div id="pt-row-count">&nbsp;</div>

  <div id="igmp-packet-ai-response" style="display:none;padding:12px 16px;background:#1a0f2e;border-bottom:1px solid #3d2a5f;border-left:3px solid #8b5cf6;max-height:200px;overflow-y:auto">
    <div id="igmp-packet-ai-resp" class="sm" style="color:var(--text);line-height:1.7;font-size:10px"></div>
  </div>

  <div id="ptw">
    <table id="pt">
      <colgroup>
        <col style="width:46px">
        <col style="width:72px">
        <col style="width:90px">
        <col style="width:160px">
        <col style="width:22px">
        <col style="width:160px">
        <col style="width:52px">
        <col style="width:80px">
        <col>
      </colgroup>
      <thead>
        <tr>
          <th onclick="sortBy('id')">#</th>
          <th onclick="sortBy('ts')">Time</th>
          <th onclick="sortBy('proto')">Protocol</th>
          <th onclick="sortBy('src')">Source</th>
          <th></th>
          <th onclick="sortBy('dst')">Destination</th>
          <th onclick="sortBy('len')">Len</th>
          <th>Flags</th>
          <th>Info</th>
        </tr>
      </thead>
      <tbody id="ptb">
        <tr id="pt-spc"><td colspan="9"></td></tr>
      </tbody>
    </table>
  </div>

  <div id="dpane" style="height:270px;display:flex;flex-direction:column;flex-shrink:0">
    <div id="dresz"></div>
    <div id="dtabs">
      <button class="dtab on" onclick="dtab(this,'dtree')">▶ Packet Tree</button>
      <button class="dtab"    onclick="dtab(this,'dhex')">⬡ Hex Dump</button>
      <button class="dtab"    onclick="dtab(this,'dai')">🤖 Ask AI</button>
      <span id="dsum" class="muted" style="font:400 10px var(--mono);margin-left:auto;align-self:center;padding-right:8px"></span>
    </div>
    <div id="dbody">
      <div id="dtree" class="ws-tree"><span class="muted">← Click a packet row to inspect</span></div>
      <div id="dhex"  class="hex-wrap" style="display:none"><span class="muted">← Click a packet to see hex</span></div>
      <div id="dai"   style="display:none;padding:10px">
        <div id="ai-resp" class="sm" style="color:var(--text);line-height:1.7"></div>
      </div>
    </div>
  </div>

</div><!-- /view-packets -->



<!-- ═══ TERMINAL ═══ -->
<div id="view-terminal" class="view" style="flex-direction:column;background:#020b14">

  <!-- Top bar: title + utility buttons -->
  <div style="padding:6px 14px;background:#07101a;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;flex-shrink:0">
    <span style="font:700 10px var(--sans);text-transform:uppercase;letter-spacing:.08em;color:var(--acc)">⚡ Terminal</span>
    <span id="term-status" style="font:400 10px var(--mono);color:#64748b">connected</span>
    <div style="margin-left:auto;display:flex;gap:6px">
      <button onclick="termClear()" style="background:#0d1829;border:1px solid var(--border);color:#64748b;padding:3px 10px;border-radius:4px;font:600 10px var(--sans);cursor:pointer">Clear</button>
      <button onclick="termKill()"  style="background:#1a0808;border:1px solid #ef444433;color:#ef4444;padding:3px 10px;border-radius:4px;font:600 10px var(--sans);cursor:pointer">Kill</button>
    </div>
  </div>

  <!-- ── ESCAPE / DISCONNECT button strip ── -->
  <div style="padding:7px 14px;background:#060f1a;border-bottom:1px solid #1e3a5f;display:flex;align-items:center;gap:6px;flex-shrink:0;flex-wrap:wrap">
    <span style="font:700 9px var(--sans);text-transform:uppercase;letter-spacing:.1em;color:#475569;white-space:nowrap;margin-right:4px">
      🔌 Escape / Disconnect
    </span>

    <!-- Telnet escape — biggest, most prominent -->
    <button onclick="termSendRaw(String.fromCharCode(29))"
      title="Telnet escape character — works on ALL systems including Mac"
      style="background:#1e3a5f;border:2px solid #3b82f6;color:#93c5fd;padding:5px 14px;border-radius:6px;font:700 11px var(--mono);cursor:pointer;letter-spacing:.04em">
      ⎋ Telnet Escape (Ctrl+])
    </button>

    <!-- Ctrl+X — Extreme / Cisco logout -->
    <button onclick="termSendRaw(String.fromCharCode(24))"
      title="Ctrl+X — exits Extreme EXOS, some Cisco CLIs"
      style="background:#1a2a1a;border:1px solid #22c55e55;color:#86efac;padding:5px 12px;border-radius:6px;font:700 11px var(--mono);cursor:pointer">
      ^X  Exit CLI
    </button>

    <!-- quit text command -->
    <button onclick="termSendLine('quit')"
      title="Sends: quit + Enter"
      style="background:#1a2a1a;border:1px solid #22c55e55;color:#86efac;padding:5px 12px;border-radius:6px;font:700 11px var(--mono);cursor:pointer">
      quit
    </button>

    <!-- exit text command -->
    <button onclick="termSendLine('exit')"
      title="Sends: exit + Enter"
      style="background:#1a2a1a;border:1px solid #22c55e55;color:#86efac;padding:5px 12px;border-radius:6px;font:700 11px var(--mono);cursor:pointer">
      exit
    </button>

    <!-- Ctrl+D EOF -->
    <button onclick="termSendRaw(String.fromCharCode(4))"
      title="Ctrl+D — EOF / force logout on Unix shells"
      style="background:#2a1a1a;border:1px solid #f59e0b44;color:#fcd34d;padding:5px 12px;border-radius:6px;font:700 11px var(--mono);cursor:pointer">
      ^D  EOF
    </button>

    <!-- Ctrl+C interrupt -->
    <button onclick="termSendRaw(String.fromCharCode(3))"
      title="Ctrl+C — interrupt / cancel current command"
      style="background:#2a1a1a;border:1px solid #f59e0b44;color:#fcd34d;padding:5px 12px;border-radius:6px;font:700 11px var(--mono);cursor:pointer">
      ^C  Break
    </button>

    <!-- Mac tip badge -->
    <span style="margin-left:auto;font:400 9px var(--sans);color:#334155;white-space:nowrap">
      🍎 Mac: use buttons above — Ctrl+] blocked by browser
    </span>
  </div>

  <!-- ── CONNECT BAR — SSH or Telnet ── -->
  <div style="padding:7px 14px;background:#080f1c;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:6px;flex-shrink:0;flex-wrap:wrap">
    <span style="font:700 9px var(--sans);text-transform:uppercase;letter-spacing:.1em;color:#475569;white-space:nowrap;margin-right:4px">
      🔗 Quick Connect
    </span>
    <select id="term-proto" style="background:#0d1829;border:1px solid var(--border);color:var(--acc);padding:4px 8px;border-radius:5px;font:600 10px var(--mono);cursor:pointer">
      <option value="ssh">SSH</option>
      <option value="telnet">Telnet</option>
    </select>
    <input id="term-host" type="text" placeholder="IP Address" value="{switch_ip or ''}" style="background:#0d1829;border:1px solid var(--border);color:var(--text);padding:4px 10px;border-radius:5px;font:500 11px var(--mono);width:130px;outline:none">
    <input id="term-user" type="text" placeholder="User" value="admin" style="background:#0d1829;border:1px solid var(--border);color:var(--text);padding:4px 10px;border-radius:5px;font:500 11px var(--mono);width:80px;outline:none">
    <input id="term-pass" type="password" placeholder="Password" style="background:#0d1829;border:1px solid var(--border);color:var(--text);padding:4px 10px;border-radius:5px;font:500 11px var(--mono);width:90px;outline:none">
    <button onclick="quickConnect()" style="background:linear-gradient(135deg,var(--acc),#0099cc);border:none;color:#000;padding:4px 14px;border-radius:5px;font:700 10px var(--sans);cursor:pointer;transition:all .2s" title="Connect via selected protocol">
      ▶ Connect
    </button>
    <span class="muted" style="font-size:9px;margin-left:4px">or type: <code style="color:var(--acc);font-size:9px">connect &lt;IP&gt;</code> (SSH) &nbsp;|&nbsp; <code style="color:#10b981;font-size:9px">tconnect &lt;IP&gt;</code> (Telnet)</span>
  </div>

  <!-- Terminal output -->
  <div id="term-out" style="flex:1;overflow-y:auto;padding:12px 16px;font:13px/1.5 'IBM Plex Mono',monospace;color:#c8d8e8;white-space:pre-wrap;word-break:break-all;min-height:0"></div>

  <!-- Input bar -->
  <div style="padding:8px 12px;border-top:1px solid var(--border);display:flex;gap:8px;align-items:center;flex-shrink:0;background:#07101a">
    <span style="color:var(--ok);font-family:var(--mono);font-size:12px;white-space:nowrap">$ </span>
    <input id="term-inp" type="text" autocomplete="off" autocorrect="off" spellcheck="false"
      style="flex:1;background:transparent;border:none;outline:none;color:#e2e8f0;font:13px 'IBM Plex Mono',monospace"
      placeholder="Type command and press Enter…"
      onkeydown="termKey(event)">
  </div>
</div>

<!-- ═══ ANOMALIES ═══ -->
<div id="view-anomalies" class="view" style="flex-direction:column">
  <div class="scroll">
    <div style="padding:8px 4px 12px">

      <!-- Summary cards -->
      <div id="anom-cards" style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px"></div>

      <!-- Filter bar -->
      <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:10px">
        <span style="font:600 11px var(--mono);color:var(--muted)">Filter:</span>
        <button class="anom-filter-btn active" data-sev="all"   onclick="anomFilter('sev','all',this)">All</button>
        <button class="anom-filter-btn" data-sev="critical" onclick="anomFilter('sev','critical',this)" style="border-color:#ef4444;color:#ef4444">🔴 Critical</button>
        <button class="anom-filter-btn" data-sev="high"     onclick="anomFilter('sev','high',this)"     style="border-color:#f97316;color:#f97316">🟠 High</button>
        <button class="anom-filter-btn" data-sev="medium"   onclick="anomFilter('sev','medium',this)"   style="border-color:#f59e0b;color:#f59e0b">🟡 Medium</button>
        <button class="anom-filter-btn" data-sev="low"      onclick="anomFilter('sev','low',this)"      style="border-color:#3b82f6;color:#3b82f6">🔵 Low</button>
        <span style="font:600 11px var(--mono);color:var(--muted);margin-left:8px">Layer:</span>
        <select id="anom-layer-filter" onchange="anomFilter('layer',this.value,null)" style="background:var(--card-bg);border:1px solid var(--border);color:var(--text);padding:3px 8px;border-radius:4px;font-size:11px">
          <option value="all">All Layers</option>
          <option value="L2">L2</option>
          <option value="L3">L3</option>
          <option value="L4">L4</option>
          <option value="L5">L5</option>
          <option value="L7">L7</option>
          <option value="Cross-Layer">Cross-Layer</option>
          <option value="L3-L7">L3-L7 (No-Response)</option>
        </select>
        <select id="anom-cat-filter" onchange="anomFilter('cat',this.value,null)" style="background:var(--card-bg);border:1px solid var(--border);color:var(--text);padding:3px 8px;border-radius:4px;font-size:11px">
          <option value="all">All Categories</option>
        </select>
        <input id="anom-search" type="text" placeholder="Search findings…" oninput="anomFilter('search',this.value,null)"
               style="background:var(--card-bg);border:1px solid var(--border);color:var(--text);padding:3px 8px;border-radius:4px;font-size:11px;width:160px;outline:none;margin-left:auto">
      </div>

      <!-- Findings table -->
      <div id="anom-list" style="display:flex;flex-direction:column;gap:4px"></div>
      <div id="anom-empty" style="display:none;padding:24px;text-align:center;color:var(--muted);font-size:13px">No findings match current filter</div>

      <!-- AI Narrative -->
      <div id="anom-narrative" style="margin-top:16px;display:none">
        <div style="font:700 11px var(--mono);color:#8b5cf6;margin-bottom:6px">🤖 AI ANALYSIS NARRATIVE</div>
        <div id="anom-narrative-text" style="background:var(--card-bg);border-left:3px solid #8b5cf6;padding:10px 14px;border-radius:4px;font-size:12px;color:var(--muted);line-height:1.6"></div>
      </div>

    </div>
  </div>
</div>

<!-- ═══ TRAPS ═══ -->
<div id="view-traps" class="view" style="flex-direction:column">
  {f'<div style="padding:8px 16px;background:#1a0a2e;border-bottom:1px solid #4c1d9533;font-size:11px;color:#a78bfa;flex-shrink:0">🔗 <strong>{len(anom)} anomal{"y" if len(anom)==1 else "ies"}</strong> detected in packet capture — <a href="#" onclick="goView(\'anomalies\',document.getElementById(\'nb-anomalies\'));return false" style="color:var(--acc)">correlate with anomaly analysis →</a></div>' if anom else ''}
  <div class="scroll">
    {traps_html}
  </div>
</div>

</div><!-- #main -->

<!-- ═══ SIDEBAR ═══ -->
<div id="sb">
  <div id="sb-resize-handle" title="Drag to resize"></div>
  <div class="sb-collapsed-tab" onclick="_sbExpand()" title="Expand panel">
    <span style="font-size:14px">&#x276F;</span>
    <span>AI Panel</span>
  </div>
  <div class="sb-hdr sb-hide-when-collapsed">
    <div class="pulse"></div>
    <h3>AI Protocol Analyst</h3>
    <span class="ai-chip" id="ai-chip-label">{ai_model}</span>
    <div style="display:flex;gap:3px;margin-left:6px">
      <button class="sb-size-btn" onclick="_sbCycleSize()" title="Cycle panel width (Normal / Wide / Narrow)">&#x2194;</button>
      <button class="sb-size-btn" onclick="_sbCollapse()" title="Collapse panel">&#x276C;</button>
    </div>
  </div>

  <!-- ── AI Settings ── -->
  <div class="sb-hide-when-collapsed" style="padding:6px 12px;background:#080f1c;border-bottom:1px solid var(--border);display:flex;flex-wrap:wrap;gap:4px;align-items:center">
    <select id="ai-backend" onchange="applyAIConfig()" style="background:#0d1829;border:1px solid var(--border);color:var(--acc);padding:3px 6px;border-radius:4px;font:600 10px var(--mono);cursor:pointer;flex:0 0 auto">
      <option value="ollama" {'selected' if AI_BACKEND=='ollama' else ''}>Ollama</option>
      <option value="claude" {'selected' if AI_BACKEND=='claude' else ''}>Claude</option>
      <option value="openai" {'selected' if AI_BACKEND=='openai' else ''}>OpenAI</option>
    </select>
    <input id="ai-model" type="text" value="{ai_model}" placeholder="Model name" style="background:#0d1829;border:1px solid var(--border);color:var(--text);padding:3px 6px;border-radius:4px;font:500 10px var(--mono);width:90px;outline:none;flex:1 1 70px">
    <input id="ai-key" type="password" placeholder="API key (if needed)" value="" style="background:#0d1829;border:1px solid var(--border);color:var(--text);padding:3px 6px;border-radius:4px;font:500 10px var(--mono);width:80px;outline:none;flex:1 1 70px">
    <button onclick="applyAIConfig()" style="background:linear-gradient(135deg,var(--acc),#0099cc);border:none;color:#000;padding:3px 10px;border-radius:4px;font:700 9px var(--sans);cursor:pointer;flex:0 0 auto" title="Apply AI settings">Apply</button>
  </div>
  <!-- ── AI Protocol Analyst mode bar ── -->
  <div class="sb-mode-bar sb-hide-when-collapsed">
    <button id="sbm-insights" class="sb-mode-btn on" onclick="showSbMode('insights')">💡 Insights</button>
    <button id="sbm-explain"  class="sb-mode-btn" onclick="showSbMode('explain')">⚡ Explain</button>
    <button id="sbm-rfc"      class="sb-mode-btn" onclick="showSbMode('rfc')">📖 RFC</button>
    <button id="sbm-exos"     class="sb-mode-btn" onclick="showSbMode('exos')">🔧 EXOS</button>
    <button id="sbm-mcp"      class="sb-mode-btn" onclick="showSbMode('mcp')">🔌 MCP</button>
    <button id="sbm-chat"     class="sb-mode-btn" onclick="showSbMode('chat')">💬 Chat</button>
  </div>

  <!-- ── Insights panel ── -->
  <div id="sbp-insights" class="sb-mode-panel on">
    <div class="insight-section">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:6px;flex-wrap:wrap;margin-bottom:8px">
        <span style="font:700 11px var(--sans);color:var(--text)">{fname}</span>
        {_anom_badge}
      </div>
      {_risk_bar_html}
    </div>
    <div class="insight-section">
      <div class="insight-label">Traffic Behaviour</div>
      <div class="behavior-tags">{_behavior_tags_html}</div>
    </div>
    <div class="insight-section">
      <div class="insight-label">Top Protocols · click for RFC</div>
      <div class="proto-chips">{_proto_chips_sidebar_html}</div>
    </div>
    {f'<div class="insight-section"><div class="insight-label">AI Summary</div><div style="font:400 10px var(--sans);color:var(--muted);line-height:1.5">{_narrative_teaser}<br><button onclick="showSbMode(\'chat\');ask(\'Explain the full AI narrative and risk assessment\')" style="margin-top:6px;background:none;border:1px solid var(--border);color:var(--acc);padding:2px 10px;border-radius:4px;font:600 9px var(--sans);cursor:pointer">Read full analysis →</button></div></div>' if _narrative_teaser else ''}
    <div class="insight-section">
      <div class="insight-label">Suggested Actions</div>
      <div style="padding:0">
        <div class="sugg-item" onclick="showSbMode('chat');ask('Give a complete stats summary table of all protocols: count, bytes, requests vs replies')">📊 Protocol stats breakdown<span class="sugg-arrow">›</span></div>
        {('<div class="sugg-item" onclick="showSbMode(\'chat\');diagnoseAnomalies()">🔍 Diagnose all anomalies<span class="sugg-arrow">›</span></div>') if anom else ''}
        <div class="sugg-item" onclick="showSbMode('chat');ask('Any security threats? Port scans, floods, RST storms, gratuitous ARP?')">🔒 Security threat check<span class="sugg-arrow">›</span></div>
        <div class="sugg-item" onclick="showSbMode('chat');ask('Give a complete network engineering report with recommendations')">📄 Full engineering report<span class="sugg-arrow">›</span></div>
      </div>
    </div>
  </div>

  <!-- ── Explain panel ── -->
  <div id="sbp-explain" class="sb-mode-panel">
    <div class="action-grid">
      <div class="action-card" onclick="showSbMode('chat');ask('Give a complete stats summary table of all protocols: count, bytes, requests vs replies')">
        <div class="ac-icon">📊</div><div class="ac-label">Stats</div><div class="ac-sub">Counts &amp; bytes</div>
      </div>
      <div class="action-card" onclick="showSbMode('chat');ask('Explain ARP exchanges: RFC 826 detail, request/reply analysis, gratuitous ARP')">
        <div class="ac-icon">🔗</div><div class="ac-label">ARP</div><div class="ac-sub">RFC 826 deep-dive</div>
      </div>
      <div class="action-card" onclick="showSbMode('chat');ask('Explain all ICMP traffic: RFC 792 type/code meanings, echo analysis')">
        <div class="ac-icon">📡</div><div class="ac-label">ICMP</div><div class="ac-sub">RFC 792 analysis</div>
      </div>
      <div class="action-card" onclick="showSbMode('chat');ask('Analyse TCP sessions: SYN/ACK/RST/FIN states, connection health, RFC 793')">
        <div class="ac-icon">🌐</div><div class="ac-label">TCP</div><div class="ac-sub">Session health</div>
      </div>
      <div class="action-card" onclick="showSbMode('chat');ask('What services and open ports are visible? Risk assessment and exposure analysis')">
        <div class="ac-icon">🔌</div><div class="ac-label">Services</div><div class="ac-sub">Port exposure</div>
      </div>
      <div class="action-card" onclick="showSbMode('chat');ask('Any security threats? Port scans, floods, RST storms, gratuitous ARP poisoning?')">
        <div class="ac-icon">🔒</div><div class="ac-label">Security</div><div class="ac-sub">Threat detection</div>
      </div>
      <div class="action-card" onclick="showSbMode('chat');ask('What troubleshooting steps would you recommend based on this capture?')">
        <div class="ac-icon">🔧</div><div class="ac-label">Troubleshoot</div><div class="ac-sub">Diagnose issues</div>
      </div>
      <div class="action-card" onclick="showSbMode('chat');ask('Give a complete network engineering report with recommendations')">
        <div class="ac-icon">📄</div><div class="ac-label">Full Report</div><div class="ac-sub">Engineering summary</div>
      </div>
    </div>
  </div>

  <!-- ── RFC panel ── -->
  <div id="sbp-rfc" class="sb-mode-panel">
    <div class="proto-pick-wrap" style="flex-shrink:0">
      <div class="proto-pick-title">RFC Analysis — pick a protocol</div>
      <div id="rfc-proto-btns" class="proto-pick-grid"></div>
    </div>
    <div class="rfc-manual-row" style="flex-shrink:0">
      <input id="rfc-manual-inp" class="rfc-num-inp" type="number" min="1" max="9999" placeholder="RFC # e.g. 793">
      <button onclick="submitCustomRFC()" style="background:linear-gradient(135deg,var(--acc),#0099cc);border:none;color:#000;padding:4px 12px;border-radius:5px;font:700 9px var(--sans);cursor:pointer">Look Up</button>
    </div>
    <div id="rfc-msgs" style="flex:1;overflow-y:auto;padding:8px 12px;display:flex;flex-direction:column;gap:6px">
      <div class="msg mb" style="border-left:2px solid #60a5fa44">Select a protocol above or enter an RFC number to look up the standard, packet structure, and relevant details.</div>
    </div>
  </div>

  <!-- ── EXOS panel ── -->
  <div id="sbp-exos" class="sb-mode-panel">
    <div class="proto-pick-wrap" style="flex-shrink:0">
      <div class="proto-pick-title">Switch Engine Commands — pick a protocol</div>
      <div id="exos-proto-btns" class="proto-pick-grid"></div>
    </div>
    <div style="padding:0 12px 6px;flex-shrink:0">
      <div class="sugg-item" onclick="askExos('Generate a complete Switch Engine CLI troubleshooting runbook for this network capture. ONLY use commands from the official Extreme Networks Switch Engine documentation: Switch Engine v33.6.1 User Guide (https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20User%20Guide/downloads/Switch_Engine_33_6_1_User_Guide.pdf), Switch Engine v33.6.1 Command References (https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20Command%20References/downloads/Switch_Engine_33_6_1_Command_References.pdf), and EMS Messages Catalog (https://documentation.extremenetworks.com/ExtremeXOS%20and%20Switch%20Engine%20v33.6.x%20EMS%20Messages%20Catalog/downloads/ExtremeXOS_and_Switch_Engine_33_6_x_EMS_Message_Catalog.pdf). Do NOT use commands from other Extreme products.')">📋 Full Switch Engine Runbook<span class="sugg-arrow">›</span></div>
    </div>
    <div id="exos-msgs" style="flex:1;overflow-y:auto;padding:8px 12px;display:flex;flex-direction:column;gap:8px">
      <div class="msg mb" style="border-left:2px solid #22d3ee44">
        <strong style="color:#67e8f9">EXOS Mode</strong> — pick a protocol above for Switch Engine CLI commands, debug steps, and EMS log references.<br><br>
        <span style="font:400 9px var(--sans);color:#475569">Responses use RAG-enriched Switch Engine documentation — no live switch required.</span>
      </div>
    </div>
  </div>

  <!-- ── MCP panel ── -->
  <div id="sbp-mcp" class="sb-mode-panel">
    <div style="padding:10px 12px 6px;flex-shrink:0">
      <div style="font:700 10px var(--sans);text-transform:uppercase;letter-spacing:.08em;color:#7c3aed;margin-bottom:6px">🔌 Live Switch — exos-mcp-server</div>
      <div style="display:flex;gap:6px;align-items:center;margin-bottom:8px">
        <input id="mcp-switch-ip" type="text" placeholder="Switch IP (e.g. 10.127.32.224)" style="flex:1;background:#0d1829;border:1px solid #7c3aed55;color:var(--text);padding:4px 8px;border-radius:4px;font:500 10px var(--mono);outline:none"/>
        <button onclick="_mcpSetIp()" style="background:#7c3aed22;border:1px solid #7c3aed55;color:#a78bfa;padding:3px 10px;border-radius:4px;font:700 9px var(--sans);cursor:pointer">Set</button>
      </div>
      <div style="font:400 9px var(--sans);color:#475569;margin-bottom:8px">Queries in this tab are sent directly to the MCP server — not to the AI. Include an IP or set it above.</div>
    </div>
    <div style="padding:0 10px 8px;display:flex;flex-wrap:wrap;gap:4px;flex-shrink:0">
      <span style="width:100%;font:700 8px var(--sans);text-transform:uppercase;letter-spacing:.1em;color:#7c3aed;padding:2px 0">Switching &amp; VLANs</span>
      <button class="qb qb-mcp" onclick="askMcp('Show me all VLANs')">VLANs</button>
      <button class="qb qb-mcp" onclick="askMcp('Show all down ports')">Down Ports</button>
      <button class="qb qb-mcp" onclick="askMcp('Get traffic stats for port 1:1')">Port Stats</button>
      <button class="qb qb-mcp" onclick="askMcp('Show me all LAGs')">LAGs</button>
      <button class="qb qb-mcp" onclick="askMcp('Show MLAG peer status')">MLAG</button>
      <span style="width:100%;font:700 8px var(--sans);text-transform:uppercase;letter-spacing:.1em;color:#7c3aed;padding:4px 0 2px">Routing &amp; Protocols</span>
      <button class="qb qb-mcp" onclick="askMcp('Show OSPF configuration')">OSPF</button>
      <button class="qb qb-mcp" onclick="askMcp('Show BGP summary')">BGP</button>
      <button class="qb qb-mcp" onclick="askMcp('Show all IP routes on VR-Default')">Routes</button>
      <button class="qb qb-mcp" onclick="askMcp('Show ACL policy counters')">ACL</button>
      <span style="width:100%;font:700 8px var(--sans);text-transform:uppercase;letter-spacing:.1em;color:#7c3aed;padding:4px 0 2px">System</span>
      <button class="qb qb-mcp" onclick="askMcp('What firmware is running?')">Firmware</button>
      <button class="qb qb-mcp" onclick="askMcp('Show system health')">Health</button>
      <button class="qb qb-mcp" onclick="askMcp('List all available tools')">Tools</button>
    </div>
    <div id="mcp-msgs" style="flex:1;overflow-y:auto;padding:8px 12px;display:flex;flex-direction:column;gap:8px">
      <div class="msg mb" style="border-left:2px solid #7c3aed44">
        <strong style="color:#a78bfa">MCP Mode</strong> — queries here go directly to the <strong>exos-mcp-server</strong>.<br><br>
        Set a switch IP above or include it in your query (e.g. <em>show vlans on 10.127.32.224</em>).<br><br>
        <span style="font:400 9px var(--sans);color:#475569">Make sure the MCP server is running:<br><code style="color:#7c3aed">python3.10 main.py --transport sse --host 0.0.0.0 --port 8000</code></span>
      </div>
    </div>
  </div>

  <!-- ── Chat panel ── -->
  <div id="sbp-chat" class="sb-mode-panel">
    <div id="msgs">
      <div class="msg mb">
        Analysed <strong>{total:,} packets</strong> from <strong>{fname}</strong>.<br><br>
        Switch to <strong>💡 Insights</strong> for an overview, or ask me anything about the capture.
        {('<br><br><span style="color:#fca5a5">⚠ '+str(len(anom))+' anomal'+('y' if len(anom)==1 else 'ies')+' detected — check <em>Insights</em> for suggested actions.</span>') if anom else ''}
        <br><br>
        <span style="font:400 9px var(--sans);color:#475569">Responses are concise by default — ask for <em>more detail</em> anytime. Memory lasts for <strong style="color:var(--acc)">20 turns</strong>. Use <strong>✕</strong> to clear.</span>
      </div>
    </div>
    <div style="padding:4px 10px 6px;display:flex;flex-wrap:wrap;gap:4px;border-top:1px solid #1e3a5f22;flex-shrink:0">
      <span style="width:100%;font:700 8px var(--sans);text-transform:uppercase;letter-spacing:.1em;color:#475569;padding:2px 0">📦 PCAP Analysis</span>
      <button class="qb" onclick="ask('Give a complete stats summary table of all protocols: count, bytes, requests vs replies')">Stats</button>
      <button class="qb" onclick="ask('Any security threats? Port scans, floods, RST storms, gratuitous ARP?')">Security</button>
      <button class="qb" onclick="ask('Analyse TCP sessions: SYN/ACK/RST/FIN states, connection health, RFC 793')">TCP Sessions</button>
      <button class="qb" onclick="ask('Give a complete network engineering report with recommendations')">Full Report</button>
    </div>
  </div>

  <div class="inp-row">
    <textarea class="inp" id="inp" placeholder="Ask about protocols, RFCs, analysis..."
      onkeydown="if(event.key==='Enter'&&!event.shiftKey){{event.preventDefault();send();}}"></textarea>
    <div style="display:flex;flex-direction:column;gap:3px">
      <button class="sbtn" onclick="send()" title="Send (Enter)">&#x25B6;</button>
      <button class="sbtn" onclick="_chatClear()" title="Clear chat history"
        style="background:rgba(100,116,139,.15);border-color:#334155;color:#64748b;font-size:10px" >&#x2715;</button>
    </div>
  </div>
</div>

</div><!-- #app -->

<script>
// ═══════════════════════════════════════════════════════════════
//  DATA
// ═══════════════════════════════════════════════════════════════
const LABELS={labels_js}, VALS={values_js};
const ALL_PKTS={pkt_js};
const TL_DATA={tl_js};
const FLOW_DATA={flow_js};
const STREAM_DATA={stream_js};
const CTX={ctx_js};
const ANOMALIES={anom_js};
const ANOM_FINDINGS={anom_findings_js};
const ANOM_SUMMARY={anom_summary_js};
const _TS0={ts0_js};  // Unix epoch of first packet — used for relative time display

// ═══════════════════════════════════════════════════════════════
//  COLOR MAP
// ═══════════════════════════════════════════════════════════════
const CMAP={{ARP:'#f59e0b',ICMP:'#ef4444',TCP:'#3b82f6',UDP:'#10b981',
  LLDP:'#8b5cf6',IPv6:'#06b6d4',EAPoL:'#f97316',IGMP:'#ec4899',
  RARP:'#fb923c',STP:'#84cc16',OSPF:'#38bdf8',BGP:'#818cf8',
  DNS:'#fbbf24',DHCP:'#4ade80',NTP:'#a3e635',SSH:'#60a5fa'}};
const FALL=['#00e5ff','#7c5cfc','#ff6b6b','#ffd93d','#6bcb77','#4d96ff','#ff9a3c','#c77dff'];

{anom_tab_js}
function pc(p){{if(CMAP[p])return CMAP[p];let h=0;for(let c of p)h=(h+c.charCodeAt(0))%FALL.length;return FALL[h];}}
const LCOLORS=LABELS.map(l=>pc(l));

// ═══════════════════════════════════════════════════════════════
//  INLINE DONUT CHART ENGINE
// ═══════════════════════════════════════════════════════════════
let donutChart=null;
function buildDonut(){{
  const canvas=document.getElementById('donut');
  if(!canvas)return;
  const ctx=canvas.getContext('2d');
  function resize(){{canvas.width=canvas.parentElement.clientWidth||300;canvas.height=canvas.parentElement.clientHeight||190;}}
  resize();
  const total=VALS.reduce((a,b)=>a+b,0)||1;
  let slices=[],hov=-1;
  function mkSlices(){{slices=[];let a=-Math.PI/2;VALS.forEach((v,i)=>{{const sw=v/total*Math.PI*2;slices.push({{s:a,sw,lbl:LABELS[i],v,col:LCOLORS[i]}});a+=sw;}});}}
  function draw(){{
    const W=canvas.width,H=canvas.height;ctx.clearRect(0,0,W,H);
    const cx=W*.40,cy=H/2,or=Math.min(cx,cy)*.82,ir=or*.60;
    slices.forEach((s,i)=>{{
      const r=i===hov?or+5:or;
      ctx.beginPath();ctx.moveTo(cx,cy);ctx.arc(cx,cy,r,s.s,s.s+s.sw);ctx.closePath();
      ctx.fillStyle=s.col;ctx.fill();ctx.strokeStyle='#070d1a';ctx.lineWidth=2;ctx.stroke();
    }});
    ctx.beginPath();ctx.arc(cx,cy,ir,0,Math.PI*2);ctx.fillStyle='#070d1a';ctx.fill();
    const hs=hov>=0?slices[hov]:(slices.reduce((a,b)=>a.v>b.v?a:b,slices[0]||{{lbl:'',v:0}}));
    ctx.fillStyle='#e2e8f0';ctx.font='bold 13px IBM Plex Mono,monospace';ctx.textAlign='center';ctx.textBaseline='middle';
    ctx.fillText(hs.v,cx,cy-7);
    ctx.font='9px DM Sans,sans-serif';ctx.fillStyle='#4a6080';ctx.fillText(hs.lbl,cx,cy+8);
    const lgX=cx+or+14,lgY=cy-slices.length*9;
    slices.forEach((s,i)=>{{
      const y=lgY+i*18;ctx.fillStyle=s.col;ctx.fillRect(lgX,y,7,7);
      ctx.fillStyle=i===hov?'#e2e8f0':'#94a3b8';ctx.font='9px DM Sans,sans-serif';ctx.textAlign='left';ctx.textBaseline='top';
      ctx.fillText(s.lbl+' ('+s.v+')',lgX+11,y-.5);
    }});
  }}
  mkSlices();draw();
  canvas.addEventListener('mousemove',e=>{{
    const r=canvas.getBoundingClientRect(),W=canvas.width,H=canvas.height,cx=W*.40,cy=H/2;
    const or=Math.min(cx,cy)*.82,ir=or*.60;
    const mx=(e.clientX-r.left)*(W/r.width)-cx,my=(e.clientY-r.top)*(H/r.height)-cy;
    const d=Math.sqrt(mx*mx+my*my);let f=-1;
    if(d>=ir&&d<=or+5){{let a=Math.atan2(my,mx);if(a<-Math.PI/2)a+=Math.PI*2;slices.forEach((s,i)=>{{let st=s.s,en=s.s+s.sw;if(st<-Math.PI/2){{st+=Math.PI*2;en+=Math.PI*2;}}if(a>=st&&a<=en)f=i;}});}}
    if(f!==hov){{hov=f;draw();}}
  }});
  canvas.addEventListener('mouseleave',()=>{{hov=-1;draw();}});
  if(window.ResizeObserver)new ResizeObserver(()=>{{resize();mkSlices();draw();}}).observe(canvas.parentElement);
  donutChart={{destroy:()=>ctx.clearRect(0,0,canvas.width,canvas.height)}};
}}

// ═══════════════════════════════════════════════════════════════
//  INLINE SCATTER/TIMELINE ENGINE
// ═══════════════════════════════════════════════════════════════
let tlChart=null;
function fmtTime(secs){{
  // Format elapsed seconds as hh:mm:ss, mm:ss.t or +s.mmm
  const h=Math.floor(secs/3600);
  const m=Math.floor((secs%3600)/60);
  const s=secs%60;
  if(secs>=3600) return String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+s.toFixed(0).padStart(2,'0');
  if(secs>=60)   return String(m).padStart(2,'0')+':'+s.toFixed(1).padStart(4,'0');
  return '+'+s.toFixed(3)+'s';
}}
function buildTimeline(filter){{
  if(tlChart){{tlChart.destroy();tlChart=null;}}
  const canvas=document.getElementById('tl-cv');
  if(!canvas)return;
  const ctx=canvas.getContext('2d');
  const PAD={{l:52,r:16,t:14,b:44}};
  const byProto={{}};
  TL_DATA.forEach(p=>{{
    const pr=filter==='ALL'?p.proto:(p.proto===filter?p.proto:null);
    if(!pr)return;
    if(!byProto[pr])byProto[pr]=[];
    byProto[pr].push({{x:p.x,y:p.y,id:p.id,src:p.src,dst:p.dst}});
  }});
  const datasets=Object.entries(byProto).map(([proto,pts])=>{{return{{label:proto,data:pts,col:pc(proto)}};}});
  const allPts=datasets.flatMap(d=>d.data);
  let minX=allPts.length?Math.min(...allPts.map(p=>p.x)):0;
  let maxX=allPts.length?Math.max(...allPts.map(p=>p.x)):1;
  let maxY=allPts.length?Math.max(...allPts.map(p=>p.y)):1;
  if(maxX===minX)maxX=minX+1;if(maxY===0)maxY=1;
  let vx=[minX,maxX],drag=false,ds=null,dvx=null,tip=null;
  function resize(){{canvas.width=canvas.parentElement.clientWidth||600;canvas.height=canvas.parentElement.clientHeight||220;}}
  function px(x){{return PAD.l+(x-vx[0])/(vx[1]-vx[0])*(canvas.width-PAD.l-PAD.r);}}
  function py(y){{return PAD.t+(canvas.height-PAD.t-PAD.b)*(1-y/(maxY*1.1));}}
  function niceXTicks(lo,hi,count){{
    const span=hi-lo;
    const raw=span/count;
    const mag=Math.pow(10,Math.floor(Math.log10(raw)));
    let step=mag;
    for(const m of [1,2,5,10,15,30,60,300,600,3600]){{
      if(mag*m>=raw){{step=mag*m;break;}}
    }}
    const first=Math.ceil(lo/step)*step;
    const ticks=[];
    for(let t=first;t<=hi+step*0.01;t=parseFloat((t+step).toPrecision(12)))ticks.push(parseFloat(t.toPrecision(12)));
    return ticks;
  }}
  function draw(){{
    const W=canvas.width,H=canvas.height;ctx.clearRect(0,0,W,H);
    // Y grid
    ctx.strokeStyle='#1a2840';ctx.lineWidth=1;
    for(let i=0;i<=4;i++){{
      const y=PAD.t+(H-PAD.t-PAD.b)*i/4;
      ctx.beginPath();ctx.moveTo(PAD.l,y);ctx.lineTo(W-PAD.r,y);ctx.stroke();
      const v=Math.round(maxY*1.1*(1-i/4));
      const lbl=v>=1000?(v/1000).toFixed(1)+'K':v.toString();
      ctx.fillStyle='#4a6080';ctx.font='8px IBM Plex Mono,monospace';
      ctx.textAlign='right';ctx.textBaseline='middle';ctx.fillText(lbl,PAD.l-4,y);
    }}
    // X grid with hh:mm:ss labels
    const ticks=niceXTicks(vx[0],vx[1],6);
    ticks.forEach(v=>{{
      const x=PAD.l+(v-vx[0])/(vx[1]-vx[0])*(W-PAD.l-PAD.r);
      if(x<PAD.l-1||x>W-PAD.r+1)return;
      ctx.strokeStyle='#1a2840';ctx.lineWidth=1;
      ctx.beginPath();ctx.moveTo(x,PAD.t);ctx.lineTo(x,H-PAD.b);ctx.stroke();
      // Tick mark
      ctx.strokeStyle='#2a4060';ctx.lineWidth=1;
      ctx.beginPath();ctx.moveTo(x,H-PAD.b);ctx.lineTo(x,H-PAD.b+4);ctx.stroke();
      const label=fmtTime(v);
      ctx.fillStyle='#5a7090';ctx.font='8px IBM Plex Mono,monospace';
      ctx.textAlign='center';ctx.textBaseline='top';ctx.fillText(label,x,H-PAD.b+6);
    }});
    // Axis labels
    ctx.fillStyle='#3a5070';ctx.font='9px DM Sans,sans-serif';
    ctx.textAlign='center';ctx.textBaseline='bottom';
    ctx.fillText('Time from first packet',W/2,H-1);
    ctx.save();ctx.translate(11,H/2);ctx.rotate(-Math.PI/2);
    ctx.fillText('Bytes/pkt',0,0);ctx.restore();
    // Dots
    datasets.forEach(d=>{{
      ctx.fillStyle=d.col+'cc';
      d.data.forEach(p=>{{
        const x2=px(p.x),y2=py(p.y);
        if(x2<PAD.l||x2>W-PAD.r||y2<PAD.t||y2>H-PAD.b)return;
        ctx.beginPath();ctx.arc(x2,y2,3,0,Math.PI*2);ctx.fill();
      }});
    }});
    // Tooltip
    if(tip){{
      const{{x:tx,y:ty,text}}=tip;
      const lines=text.split('\\n'),lh=14,tw=210,th=lines.length*lh+10;
      let ox=tx+8,oy=ty-th-4;
      if(ox+tw>W-PAD.r)ox=tx-tw-8;if(oy<PAD.t)oy=ty+4;
      ctx.fillStyle='#0b1628';ctx.strokeStyle='#2a4060';ctx.lineWidth=1;
      ctx.beginPath();if(ctx.roundRect)ctx.roundRect(ox,oy,tw,th,4);else ctx.rect(ox,oy,tw,th);
      ctx.fill();ctx.stroke();
      ctx.fillStyle='#e2e8f0';ctx.font='9px IBM Plex Mono,monospace';
      ctx.textAlign='left';ctx.textBaseline='top';
      lines.forEach((l,i)=>ctx.fillText(l,ox+6,oy+5+i*lh));
    }}
    // Legend
    let lgX=PAD.l+4,lgY=PAD.t+2;
    datasets.forEach(d=>{{
      ctx.fillStyle=d.col;ctx.fillRect(lgX,lgY,7,7);
      ctx.fillStyle='#64748b';ctx.font='8px DM Sans,sans-serif';
      ctx.textAlign='left';ctx.textBaseline='top';
      const lbl=d.label+' ('+d.data.length+')';
      ctx.fillText(lbl,lgX+10,lgY);
      lgX+=ctx.measureText(lbl).width+22;
      if(lgX>W-80){{lgX=PAD.l+4;lgY+=12;}}
    }});
  }}
  canvas.style.cursor='crosshair';
  canvas.addEventListener('mousemove',e=>{{
    const rect=canvas.getBoundingClientRect();const mx=(e.clientX-rect.left)*(canvas.width/rect.width),my=(e.clientY-rect.top)*(canvas.height/rect.height);
    if(drag&&ds){{const dx=(mx-ds.x)/(canvas.width-PAD.l-PAD.r)*(dvx[1]-dvx[0]);vx=[dvx[0]-dx,dvx[1]-dx];tip=null;draw();return;}}
    let best=null,bestD=15;
    datasets.forEach(d=>d.data.forEach(p=>{{const dx=px(p.x)-mx,dy=py(p.y)-my,dd=Math.sqrt(dx*dx+dy*dy);if(dd<bestD){{bestD=dd;best={{p,d,x:px(p.x),y:py(p.y)}};}}}}));
    if(best){{
      const t=fmtTime(best.p.x);
      tip={{x:best.x,y:best.y,text:'#'+best.p.id+' '+best.d.label+'\\n'+best.p.src+' \u2192 '+best.p.dst+'\\n'+best.p.y+'B   t='+t}};
      canvas.style.cursor='pointer';canvas.onclick=()=>selPkt(best.p.id);
    }}else{{tip=null;canvas.style.cursor='crosshair';canvas.onclick=null;}}
    draw();
  }});
  canvas.addEventListener('mousedown',e=>{{const r=canvas.getBoundingClientRect();drag=true;ds={{x:(e.clientX-r.left)*(canvas.width/r.width)}};dvx=[...vx];canvas.style.cursor='grabbing';}});
  canvas.addEventListener('mouseup',()=>{{drag=false;ds=null;canvas.style.cursor='crosshair';}});
  canvas.addEventListener('mouseleave',()=>{{drag=false;tip=null;draw();}});
  canvas.addEventListener('wheel',e=>{{e.preventDefault();const r=canvas.getBoundingClientRect();const mx=(e.clientX-r.left)*(canvas.width/r.width);const frac=(mx-PAD.l)/(canvas.width-PAD.l-PAD.r);const span=vx[1]-vx[0];const zoom=e.deltaY>0?1.25:0.8;const ns=Math.max(.0005,Math.min(maxX-minX+.1,span*zoom));const anchor=vx[0]+frac*span;vx=[anchor-frac*ns,anchor+(1-frac)*ns];draw();}},{{passive:false}});
  resize();draw();
  if(window.ResizeObserver)new ResizeObserver(()=>{{resize();draw();}}).observe(canvas.parentElement);
  tlChart={{destroy:()=>ctx.clearRect(0,0,canvas.width,canvas.height),resetZoom:()=>{{vx=[minX,maxX];draw();}}}};
}}
function tlFilter(btn){{
  document.querySelectorAll('.tl-btn').forEach(b=>{{b.classList.remove('on');b.style.color='';}});
  btn.classList.add('on');
  const p=btn.dataset.proto;
  btn.style.color=p==='ALL'?'#e2e8f0':pc(p);
  buildTimeline(p);
}}

// ═══════════════════════════════════════════════════════════════
//  VIEW SWITCHER
// ═══════════════════════════════════════════════════════════════
function fpTab(name){{
  document.querySelectorAll('.fp-tab').forEach(function(t){{t.classList.remove('on');}});
  const btn=document.getElementById('fp-tab-'+name);
  if(btn)btn.classList.add('on');
  document.querySelectorAll('.fp-panel').forEach(function(p){{p.classList.remove('active');p.style.display='';}});
  const panel=document.getElementById('fp-panel-'+name);
  if(panel){{panel.classList.add('active');panel.style.display='';}}
  if(name==='proto'){{
    requestAnimationFrame(function(){{if(donutChart)donutChart.destroy();buildDonut();}});
    // re-open active ptab if any
    const bar=document.getElementById('ptab-bar');
    if(bar){{
      const first=bar.querySelector('.ptab');
      const anyVis=[...document.querySelectorAll('.ppanel')].some(p=>p.style.display==='block');
      if(first&&!anyVis){{const pid=first.getAttribute('data-panel');if(pid)ptab(first,pid);}}
    }}
  }}
  if(name==='flows'){{requestAnimationFrame(function(){{requestAnimationFrame(function(){{buildFlowDiagram();}});}});}}
}}

function goView(name,btn){{
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('on'));
  if(btn)btn.classList.add('on');
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('on'));
  const el=document.getElementById('view-'+name);
  if(el)el.classList.add('on');
  if(name==='overview'){{
    requestAnimationFrame(()=>requestAnimationFrame(()=>{{
      if(donutChart)donutChart.destroy();
      buildDonut();
      if(!tlChart)buildTimeline('ALL');
    }}));
  }}
  if(name==='flowproto'){{
    const anyActive=document.querySelector('.fp-panel.active');
    if(!anyActive){{fpTab('proto');}}
    else{{
      if(document.getElementById('fp-panel-proto').classList.contains('active'))
        requestAnimationFrame(()=>{{if(donutChart)donutChart.destroy();buildDonut();}});
      if(document.getElementById('fp-panel-flows').classList.contains('active'))
        requestAnimationFrame(()=>requestAnimationFrame(()=>buildFlowDiagram()));
    }}
  }}
  if(name==='packets'){{renderTable();}}
  if(name==='terminal'){{
    termConnect();
    setTimeout(()=>{{const inp=document.getElementById('term-inp');if(inp)inp.focus();}},100);
  }}
  if(name==='anomalies'){{
    requestAnimationFrame(()=>initAnomaliesTab());
  }}
}}

// ═══════════════════════════════════════════════════════════════
//  FLOW SEQUENCE DIAGRAM (Canvas2D ladder diagram)
// ═══════════════════════════════════════════════════════════════
let _flowZoom=1;
function flowZoomIn(){{ _flowZoom=Math.min(3,_flowZoom*1.25); buildFlowDiagram(); }}
function flowZoomOut(){{ _flowZoom=Math.max(0.4,_flowZoom*0.8); buildFlowDiagram(); }}
function flowResetZoom(){{ _flowZoom=1; buildFlowDiagram(); }}

function buildFlowDiagram(){{
  const canvas=document.getElementById('flow-cv');
  if(!canvas)return;
  const ctx=canvas.getContext('2d');
  const scr=document.getElementById('flow-scroll');
  const hosts=FLOW_DATA.hosts||[];
  let arrows=FLOW_DATA.arrows||[];
  const flowProtos=FLOW_DATA.protos||[];

  // Populate protocol filter dropdown (once)
  const pf=document.getElementById('flow-proto-filter');
  if(pf && pf.options.length<=1 && flowProtos.length){{
    flowProtos.forEach(pr=>{{const o=document.createElement('option');o.value=pr;o.textContent=pr;pf.appendChild(o);}});
  }}
  const protoF=pf?pf.value:'ALL';
  if(protoF!=='ALL') arrows=arrows.filter(a=>a.proto===protoF);

  // Apply host filter
  const hf=document.getElementById('flow-host-filter');
  const hostF=hf?hf.value:'ALL';
  if(hostF!=='ALL') arrows=arrows.filter(a=>a.src===hostF||a.dst===hostF);

  // Populate host filter dropdown (once)
  if(hf && hf.options.length<=1){{
    hosts.forEach(h=>{{const o=document.createElement('option');o.value=h;o.textContent=h;hf.appendChild(o);}});
  }}

  // Determine visible hosts (only those in filtered arrows)
  let visHosts;
  if(protoF==='ALL' && hostF==='ALL') visHosts=hosts;
  else {{
    const hs=new Set(); arrows.forEach(a=>{{hs.add(a.src);hs.add(a.dst);}});
    visHosts=hosts.filter(h=>hs.has(h));
  }}

  const cnt=document.getElementById('flow-count');
  if(cnt) cnt.textContent=arrows.length+' arrows, '+visHosts.length+' hosts';

  if(visHosts.length<1||arrows.length<1){{
    canvas.width=scr.clientWidth||800; canvas.height=200;
    ctx.clearRect(0,0,canvas.width,canvas.height);
    ctx.fillStyle='#4a6080';ctx.font='14px DM Sans,sans-serif';ctx.textAlign='center';
    ctx.fillText('No flows to display'+(protoF!=='ALL'?' for '+protoF:''),canvas.width/2,100);
    return;
  }}

  // Layout constants (zoom-affected)
  const COL_W=Math.max(120,160*_flowZoom);  // column width
  const ROW_H=Math.max(22,30*_flowZoom);    // row height per arrow
  const HDR_H=60;                           // header height
  const PAD_L=100;                          // left padding (timestamps + role badge)
  const PAD_B=30;                           // bottom padding
  const FONT_SZ=Math.max(8,10*_flowZoom);

  const W=PAD_L+visHosts.length*COL_W+40;   // extra right margin for pkt IDs
  const H=HDR_H+arrows.length*ROW_H+PAD_B;
  canvas.width=W; canvas.height=H;

  // Host index map
  const hi={{}};
  visHosts.forEach((h,i)=>hi[h]=i);

  // Host X positions (centre of each column)
  function hx(host){{ return PAD_L+hi[host]*COL_W+COL_W/2; }}

  ctx.clearRect(0,0,W,H);

  // ── Draw host columns (lifelines) ───────────────────────────
  ctx.textAlign='center'; ctx.textBaseline='top';
  visHosts.forEach((h,i)=>{{
    const x=hx(h);
    // Header box
    ctx.fillStyle='#0d1829'; ctx.strokeStyle='#1e3a5f';
    const bw=COL_W-16, bh=36;
    const bx=x-bw/2, by=6;
    ctx.beginPath();
    if(ctx.roundRect) ctx.roundRect(bx,by,bw,bh,6);
    else ctx.rect(bx,by,bw,bh);
    ctx.fill(); ctx.lineWidth=1; ctx.strokeStyle='#1e3a5f'; ctx.stroke();
    ctx.fillStyle='#e2e8f0'; ctx.font='bold '+Math.max(9,11*_flowZoom)+'px IBM Plex Mono,monospace';
    // Truncate long hostnames
    let label=h; if(label.length>18) label=label.substring(0,16)+'..';
    ctx.fillText(label,x,by+6);
    // Port label (if applicable)
    ctx.fillStyle='#4a6080'; ctx.font=Math.max(7,9*_flowZoom)+'px DM Sans,sans-serif';
    ctx.fillText(i===0?'\u25C6 Host '+(i+1):'\u25C7 Host '+(i+1),x,by+22);

    // Lifeline (dashed vertical line)
    ctx.strokeStyle='#1e3a5f'; ctx.lineWidth=1;
    ctx.setLineDash([4,3]);
    ctx.beginPath(); ctx.moveTo(x,HDR_H); ctx.lineTo(x,H-PAD_B); ctx.stroke();
    ctx.setLineDash([]);
  }});

  // ── Draw arrows ─────────────────────────────────────────────
  arrows.forEach((a,i)=>{{
    const y=HDR_H+i*ROW_H+ROW_H/2;
    const si=hi[a.src], di=hi[a.dst];
    if(si===undefined||di===undefined)return;
    const x1=hx(a.src), x2=hx(a.dst);
    const col=pc(a.proto);
    const self=(a.src===a.dst);
    const role=a.role||'data';  // 'request','response','data'
    const isResp=(role==='response');

    // Alternating row background for readability
    if(i%2===0){{ ctx.fillStyle='#0a1020'; ctx.fillRect(0,y-ROW_H/2,W,ROW_H); }}

    // Timestamp label (left margin)
    ctx.fillStyle='#4a6080'; ctx.font=Math.max(7,8*_flowZoom)+'px IBM Plex Mono,monospace';
    ctx.textAlign='left'; ctx.textBaseline='middle';
    ctx.fillText(a.t.toFixed(4)+'s',4,y);

    // Role badge (before arrow)
    const badgeW=Math.max(24,30*_flowZoom);
    const bx=PAD_L-badgeW-4, by2=y-6;
    if(role==='request'){{
      ctx.fillStyle='#10b98133'; ctx.strokeStyle='#10b981';
      ctx.beginPath(); if(ctx.roundRect) ctx.roundRect(bx,by2,badgeW,12,3); else ctx.rect(bx,by2,badgeW,12); ctx.fill(); ctx.lineWidth=0.5; ctx.stroke();
      ctx.fillStyle='#10b981'; ctx.font='bold '+Math.max(6,7*_flowZoom)+'px IBM Plex Mono,monospace';
      ctx.textAlign='center'; ctx.textBaseline='middle'; ctx.fillText('REQ',bx+badgeW/2,y);
    }}else if(role==='response'){{
      ctx.fillStyle='#3b82f633'; ctx.strokeStyle='#3b82f6';
      ctx.beginPath(); if(ctx.roundRect) ctx.roundRect(bx,by2,badgeW,12,3); else ctx.rect(bx,by2,badgeW,12); ctx.fill(); ctx.lineWidth=0.5; ctx.stroke();
      ctx.fillStyle='#3b82f6'; ctx.font='bold '+Math.max(6,7*_flowZoom)+'px IBM Plex Mono,monospace';
      ctx.textAlign='center'; ctx.textBaseline='middle'; ctx.fillText('RSP',bx+badgeW/2,y);
    }}else{{
      ctx.fillStyle='#64748b33'; ctx.strokeStyle='#64748b';
      ctx.beginPath(); if(ctx.roundRect) ctx.roundRect(bx,by2,badgeW,12,3); else ctx.rect(bx,by2,badgeW,12); ctx.fill(); ctx.lineWidth=0.5; ctx.stroke();
      ctx.fillStyle='#64748b'; ctx.font='bold '+Math.max(6,7*_flowZoom)+'px IBM Plex Mono,monospace';
      ctx.textAlign='center'; ctx.textBaseline='middle'; ctx.fillText('DAT',bx+badgeW/2,y);
    }}

    if(self){{
      // Self-loop: curved arrow to self
      ctx.strokeStyle=col; ctx.lineWidth=1.5;
      if(isResp) ctx.setLineDash([4,3]);
      ctx.beginPath();
      ctx.moveTo(x1+2,y-4); ctx.bezierCurveTo(x1+40,y-18,x1+40,y+18,x1+2,y+4);
      ctx.stroke(); ctx.setLineDash([]);
      ctx.fillStyle=col; ctx.beginPath();
      ctx.moveTo(x1+2,y+4); ctx.lineTo(x1+8,y+1); ctx.lineTo(x1+6,y+8); ctx.fill();
    }} else {{
      const dir=x2>x1?1:-1;
      // Arrow line: solid for request, dashed for response
      ctx.strokeStyle=col; ctx.lineWidth=isResp?1.2:1.8;
      if(isResp) ctx.setLineDash([6,3]);
      ctx.beginPath(); ctx.moveTo(x1,y); ctx.lineTo(x2-dir*8,y); ctx.stroke();
      ctx.setLineDash([]);
      // Arrowhead (filled for request, outline for response)
      if(isResp){{
        ctx.strokeStyle=col; ctx.lineWidth=1.2;
        ctx.beginPath(); ctx.moveTo(x2,y); ctx.lineTo(x2-dir*10,y-5); ctx.moveTo(x2,y); ctx.lineTo(x2-dir*10,y+5); ctx.stroke();
      }}else{{
        ctx.fillStyle=col; ctx.beginPath();
        ctx.moveTo(x2,y); ctx.lineTo(x2-dir*8,y-4); ctx.lineTo(x2-dir*8,y+4); ctx.fill();
      }}
    }}

    // Label on arrow
    const mx=self?x1+44:(x1+x2)/2;
    ctx.fillStyle=col; ctx.font='bold '+FONT_SZ+'px IBM Plex Mono,monospace';
    ctx.textAlign='center'; ctx.textBaseline='bottom';
    let lbl=a.label; if(lbl.length>28) lbl=lbl.substring(0,26)+'..';
    ctx.fillText(lbl,mx,y-3);

    // Bytes label + direction indicator
    if(a.bytes){{
      ctx.fillStyle='#4a6080'; ctx.font=(FONT_SZ-2)+'px DM Sans,sans-serif';
      ctx.textBaseline='top';
      const dirIcon=self?'↺':(x2>x1?'→':'←');
      ctx.fillText(a.bytes+'B '+dirIcon,mx,y+2);
    }}

    // Packet ID (far right)
    ctx.fillStyle='#334155'; ctx.font=(FONT_SZ-2)+'px IBM Plex Mono,monospace';
    ctx.textAlign='right'; ctx.textBaseline='middle';
    ctx.fillText('#'+a.id, W-6, y);
  }});

  // Click handler: click arrow to select packet
  canvas.onclick=function(e){{
    const rect=canvas.getBoundingClientRect();
    const my=(e.clientY-rect.top)*(canvas.height/rect.height);
    const idx=Math.floor((my-HDR_H)/ROW_H);
    if(idx>=0&&idx<arrows.length){{
      const pkt=arrows[idx];
      // Switch to packets view and select
      goView('packets',document.getElementById('nb-packets'));
      setTimeout(()=>selPkt(pkt.id),150);
    }}
  }};
  canvas.style.cursor='pointer';
}}


//  PACKET TABLE – virtual scroll + pre-indexed fast filter
// ═══════════════════════════════════════════════════════════════
const _PKT_TOTAL={pkt_total_count_js};  // real capture count (may exceed ALL_PKTS)
const _VS_ROW_H=26;   // must match #pt td height in CSS
const _VS_BUF=15;     // extra rows rendered above/below viewport

let sortKey='id',sortDir=1,filterStr='',curId=null;

// ── Search index (built once on first render) ──────────────────
let _vsReady=false,_vsFiltered=[];
let _srchIdx={{}};   // id -> pre-lowercased search string
let _idxProto={{}},_idxSrcIp={{}},_idxDstIp={{}};
let _idxPort={{}},_idxMac={{}},_idxVlan={{}},_idxFlags={{}};

function _buildPktIdx(){{
  if(_vsReady)return;
  _vsReady=true;
  function _ai(map,key,id){{key=String(key||'').toLowerCase();if(!key)return;if(!map[key])map[key]=new Set();map[key].add(id);}}
  Object.values(ALL_PKTS).forEach(p=>{{
    const proto=(p.proto||'').toLowerCase();
    const flags=(p.tcp_flags||p.arp_op||p.icmp_type_str||'');
    _srchIdx[p.id]=[proto,p.src_ip||'',p.dst_ip||'',
      String(p.src_port||''),String(p.dst_port||''),
      p.src_mac||'',p.dst_mac||'',String(p.vlan_id||''),
      flags.toLowerCase(),p.summary||'',p.service||'',
      p.tshark_info||'',p.dns_query||'',p.dhcp_msg_type||''
    ].join('\x00').toLowerCase();
    _ai(_idxProto,proto,p.id);
    if(p.src_ip)_ai(_idxSrcIp,p.src_ip,p.id);
    if(p.dst_ip)_ai(_idxDstIp,p.dst_ip,p.id);
    if(p.src_port)_ai(_idxPort,String(p.src_port),p.id);
    if(p.dst_port)_ai(_idxPort,String(p.dst_port),p.id);
    if(p.src_mac)_ai(_idxMac,p.src_mac.toLowerCase(),p.id);
    if(p.dst_mac)_ai(_idxMac,p.dst_mac.toLowerCase(),p.id);
    if(p.vlan_id)_ai(_idxVlan,String(p.vlan_id),p.id);
    if(flags)_ai(_idxFlags,flags.toUpperCase(),p.id);
  }});
}}

function _vsFilter(){{
  _buildPktIdx();
  const all=Object.values(ALL_PKTS);
  if(!filterStr)return all;
  const f=filterStr.toLowerCase().trim();
  if(f==='bookmarked')return all.filter(p=>_bookmarks.has(p.id));
  const parts=f.split(' ',2);
  if(parts.length>=2){{
    const[k,v]=parts;
    if(k==='ip'){{const S=_idxSrcIp[v]||new Set();const D=_idxDstIp[v]||new Set();return all.filter(p=>S.has(p.id)||D.has(p.id));}}
    if(k==='port'){{const ids=_idxPort[v]||new Set();return all.filter(p=>ids.has(p.id));}}
    if(k==='mac')return all.filter(p=>(_srchIdx[p.id]||'').includes(v));
    if(k==='vlan'){{const ids=_idxVlan[v]||new Set();return all.filter(p=>ids.has(p.id));}}
    if(k==='flags')return all.filter(p=>(p.tcp_flags||'').toUpperCase().includes(v.toUpperCase()));
    if(k==='proto'){{const ids=_idxProto[v]||new Set();return all.filter(p=>ids.has(p.id));}}
  }}
  if(_idxProto[f]&&(_idxProto[f].size||0)>0){{const ids=_idxProto[f];return all.filter(p=>ids.has(p.id));}}
  return all.filter(p=>(_srchIdx[p.id]||'').includes(f));
}}

function _vsSort(arr){{
  arr.sort((a,b)=>{{
    let av,bv;
    if(sortKey==='id'){{av=a.id;bv=b.id;}}
    else if(sortKey==='ts'){{av=a.ts;bv=b.ts;}}
    else if(sortKey==='proto'){{av=a.proto||'';bv=b.proto||'';}}
    else if(sortKey==='src'){{av=a.src_ip||'';bv=b.src_ip||'';}}
    else if(sortKey==='dst'){{av=a.dst_ip||'';bv=b.dst_ip||'';}}
    else if(sortKey==='len'){{av=a.frame_len;bv=b.frame_len;}}
    else{{av=a.id;bv=b.id;}}
    return av<bv?-sortDir:av>bv?sortDir:0;
  }});
}}

function _vsRender(){{
  const wrap=document.getElementById('ptw');
  const spc=document.getElementById('pt-spc');
  const tbody=document.getElementById('ptb');
  if(!wrap||!tbody)return;
  const total=_vsFiltered.length;
  const viewH=wrap.clientHeight;
  const scrollTop=wrap.scrollTop;
  const firstIdx=Math.max(0,Math.floor(scrollTop/_VS_ROW_H)-_VS_BUF);
  const lastIdx=Math.min(total-1,Math.ceil((scrollTop+viewH)/_VS_ROW_H)+_VS_BUF);
  const topPad=firstIdx*_VS_ROW_H;
  const botPad=Math.max(0,(total-1-lastIdx)*_VS_ROW_H);
  // Update top spacer height
  if(spc&&spc.firstElementChild)spc.firstElementChild.style.height=topPad+'px';
  // Build visible rows
  const frag=document.createDocumentFragment();
  for(let i=firstIdx;i<=lastIdx&&i<total;i++){{
    const p=_vsFiltered[i];
    const col=pc(p.proto);
    const src=(p.src_ip||p.src_mac||'?')+(p.src_port?':'+p.src_port:'');
    const dst=(p.dst_ip||p.dst_mac||'?')+(p.dst_port?':'+p.dst_port:'');
    const flags=p.tcp_flags||p.arp_op||p.icmp_type_str||'';
    const fc=flags.includes('SYN')&&!flags.includes('ACK')?'#10b981':flags.includes('RST')?'#ef4444':flags.includes('FIN')?'#f59e0b':'#94a3b8';
    const tr=document.createElement('tr');
    tr.dataset.id=p.id;
    tr.style.borderLeft='3px solid '+col;
    if(_bookmarks.has(p.id))tr.classList.add('bookmarked');
    if(p.id===curId)tr.classList.add('sel');
    tr.innerHTML=
      '<td class="muted">'+p.id+'</td>'+
      '<td class="muted" style="font-size:10px;cursor:default" title="'+_absTime(p.ts)+'">'+_relTime(p.ts)+'</td>'+
      '<td><span class="badge" style="background:'+col+'">'+p.proto+'</span></td>'+
      '<td style="color:#93c5fd;font-family:var(--mono);font-size:11px">'+src+'</td>'+
      '<td class="muted" style="font-size:10px">→</td>'+
      '<td style="color:#86efac;font-family:var(--mono);font-size:11px">'+dst+'</td>'+
      '<td class="muted" style="font-size:10px">'+p.frame_len+'B</td>'+
      '<td style="color:'+fc+';font-size:10px;font-family:monospace">'+flags+'</td>'+
      '<td class="muted" style="font-size:10px" title="'+(p.summary||'').replace(/"/g,"'")+'">'+(p.summary||'')+'</td>';
    tr.onclick=()=>selPkt(p.id);
    frag.appendChild(tr);
  }}
  // Bottom padding row
  const btm=document.createElement('tr');
  btm.innerHTML='<td colspan="9" style="padding:0;height:'+botPad+'px;border:none"></td>';
  frag.appendChild(btm);
  // Replace rows (keep #pt-spc as first child)
  while(tbody.children.length>1)tbody.removeChild(tbody.lastChild);
  tbody.appendChild(frag);
}}

function renderTable(){{
  _buildPktIdx();
  _vsFiltered=_vsFilter();
  _vsSort(_vsFiltered);
  // Update row-count bar
  const bar=document.getElementById('pt-row-count');
  if(bar){{
    const shown=_vsFiltered.length;
    const loaded=Object.keys(ALL_PKTS).length;
    let txt='';
    if(!filterStr){{
      txt=loaded+' packets loaded';
      if(_PKT_TOTAL>loaded)txt+=' · '+(_PKT_TOTAL-loaded)+' not loaded (capture has '+_PKT_TOTAL+' total)';
    }}else{{
      txt=shown+' matching of '+loaded+' loaded';
      if(_PKT_TOTAL>loaded)txt+=' · '+_PKT_TOTAL+' total in capture';
    }}
    bar.textContent=txt;
    bar.style.color=(_PKT_TOTAL>loaded)?'#f59e0b':'#4a7090';
  }}
  _vsRender();
}}

// Attach virtual scroll listener once DOM is ready
(function _initVsScroll(){{
  const wrap=document.getElementById('ptw');
  if(wrap)wrap.addEventListener('scroll',()=>_vsRender(),{{passive:true}});
  else requestAnimationFrame(_initVsScroll);
}})();

// Debounce helper for filter input
let _filterTimer=null;
function _debouncedFilter(){{
  clearTimeout(_filterTimer);
  _filterTimer=setTimeout(()=>{{filterStr=document.getElementById('pf').value.trim();renderTable();}},150);
}}

function sortBy(k){{if(sortKey===k)sortDir*=-1;else{{sortKey=k;sortDir=1;}}renderTable();}}
function applyFilter(){{filterStr=document.getElementById('pf').value.trim();renderTable();}}
function clearFilter(){{document.getElementById('pf').value='';filterStr='';renderTable();}}
function qFilter(p){{document.getElementById('pf').value=p;filterStr=p;renderTable();}}

// ═══════════════════════════════════════════════════════════════
//  PACKET DETAIL
// ═══════════════════════════════════════════════════════════════
function selPkt(id){{
  curId=id;const p=ALL_PKTS[String(id)];if(!p)return;
  // Scroll virtual container so the row is visible, then re-render with sel highlight
  const idx=_vsFiltered.findIndex(x=>x.id===id);
  if(idx>=0){{
    const wrap=document.getElementById('ptw');
    if(wrap){{
      const tgt=idx*_VS_ROW_H;
      const vh=wrap.clientHeight;
      if(tgt<wrap.scrollTop+_VS_ROW_H||tgt+_VS_ROW_H>wrap.scrollTop+vh-_VS_ROW_H)
        wrap.scrollTop=Math.max(0,tgt-Math.floor(vh/2));
      _vsRender();
    }}
  }}
  const sum=['Pkt #'+p.id,' · ',p.proto,' · ',p.frame_len+'B',' · ',_relTime(p.ts)];
  if(p.src_ip)sum.push('  '+p.src_ip+' → '+(p.dst_ip||'?'));
  if(p.service)sum.push('  ['+p.service+']');
  const summary=sum.join('');
  document.getElementById('dsum').textContent=summary;
  buildTree(p);buildHex(p);
  document.getElementById('ai-resp').textContent='';
  const tabs=document.querySelectorAll('.dtab');
  if(tabs.length)dtab(tabs[0],'dtree');
}}

// ── Timestamp helpers ─────────────────────────────────────────────────────
function _absTime(epochSec){{
  const d=new Date(epochSec*1000);
  const pad=n=>String(n).padStart(2,'0');
  const ms=String(Math.round((epochSec%1)*1e6)).padStart(6,'0');
  const mon=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][d.getMonth()];
  return d.getDate()+' '+mon+' '+d.getFullYear()+' '+pad(d.getHours())+':'+pad(d.getMinutes())+':'+pad(d.getSeconds())+'.'+ms+' local';
}}
function _relTime(epochSec){{
  const rel=epochSec-_TS0;
  if(rel<0)return epochSec.toFixed(6)+'s';
  const h=Math.floor(rel/3600),m=Math.floor((rel%3600)/60),s=rel%60;
  if(h>0)return String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+s.toFixed(4).padStart(7,'0');
  if(m>0)return String(m).padStart(2,'0')+':'+s.toFixed(6).padStart(9,'0');
  return s.toFixed(6)+'s';
}}

function buildTree(p){{
  const wrap=document.getElementById('dtree');wrap.innerHTML='';
  // Synthetic Frame layer (like Wireshark's 'Frame N: X bytes' header)
  const _frameLayer={{
    title:'Frame '+p.id+': '+p.frame_len+' bytes on wire ('+p.frame_len*8+' bits)',
    color:'#64748b',
    fields:[
      {{n:'Arrival Time',       v:_absTime(p.ts)}},
      {{n:'Epoch Arrival Time', v:p.ts.toFixed(9)+' seconds'}},
      {{n:'Time from first',    v:_relTime(p.ts)}},
      {{n:'Frame Number',       v:String(p.id)}},
      {{n:'Frame Length',       v:p.frame_len+' bytes ('+p.frame_len*8+' bits)'}},
      {{n:'Capture Length',     v:p.frame_len+' bytes ('+p.frame_len*8+' bits)'}},
      {{n:'Protocols in frame', v:[p.proto,p.service].filter(Boolean).join(':')||'unknown'}},
    ]
  }};
  [_frameLayer].concat(p.layers||[]).forEach(layer=>{{  // prepend frame layer
    const div=document.createElement('div');div.className='wl';
    const open={{v:true}};
    const hdr=document.createElement('div');hdr.className='wl-hdr';hdr.style.color=layer.color||'#94a3b8';
    hdr.innerHTML=`<span class="arr">▾</span><span class="wl-title" style="color:${{layer.color||'#94a3b8'}}">${{layer.title}}</span>`;
    const fields=document.createElement('div');fields.className='wl-fields';
    (layer.fields||[]).forEach(f=>{{
      const row=document.createElement('div');row.className='wf';
      row.innerHTML=`<span class="wfn">${{f.n}}</span><span class="wfv">${{f.v}}</span>`+(f.note?`<span class="wfnote">// ${{f.note}}</span>`:'');
      fields.appendChild(row);
    }});
    hdr.onclick=()=>{{open.v=!open.v;fields.style.display=open.v?'':'none';hdr.querySelector('.arr').textContent=open.v?'▾':'▸';}};
    div.appendChild(hdr);div.appendChild(fields);wrap.appendChild(div);
  }});
}}

function buildHex(p){{
  const wrap=document.getElementById('dhex');
  const bytes=p.hex_data;
  if(!bytes||!bytes.length){{wrap.innerHTML='<span class="muted">No hex data</span>';return;}}
  let html='<div style="padding:2px 12px 4px;font-size:9px;color:#2d3f55">Showing '+bytes.length+' of '+p.frame_len+' bytes</div><div class="hex-wrap">';
  for(let i=0;i<bytes.length;i+=16){{
    const row=bytes.slice(i,i+16);
    const off=i.toString(16).padStart(4,'0');
    const hex=row.map(b=>b.toString(16).padStart(2,'0')).join(' ');
    const asc=row.map(b=>(b>=32&&b<127)?String.fromCharCode(b):'.').join('');
    html+=`<div class="hrow"><span class="hoff">${{off}}</span><span class="hbytes">${{hex.padEnd(47)}}</span><span class="hascii">${{asc}}</span></div>`;
  }}
  html+='</div>';wrap.innerHTML=html;
}}

function dtab(btn,pane){{
  document.querySelectorAll('.dtab').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  ['dtree','dhex','dai'].forEach(id=>{{const el=document.getElementById(id);if(el)el.style.display=id===pane?'':'none';}});
  if(pane==='dai'&&curId)askPkt();
}}

// Detail pane resizer
(function(){{
  const rz=document.getElementById('dresz'),wp=document.getElementById('dpane');
  if(!rz||!wp)return;
  let drag=false,sy=0,sh=0;
  rz.addEventListener('mousedown',e=>{{drag=true;sy=e.clientY;sh=wp.offsetHeight;document.body.style.cursor='row-resize';e.preventDefault();}});
  document.addEventListener('mousemove',e=>{{if(!drag)return;const d=sy-e.clientY;wp.style.height=Math.max(80,Math.min(600,sh+d))+'px';}});
  document.addEventListener('mouseup',()=>{{drag=false;document.body.style.cursor='';}});
}})();

async function askPkt(){{
  if(!curId)return;
  const p=ALL_PKTS[String(curId)];if(!p)return;
  const layers=(p.layers||[]).map(l=>l.title+':\\n'+(l.fields||[]).map(f=>f.n+': '+f.v+(f.note?' ('+f.note+')':'')).join('\\n')).join('\\n\\n');
  const q='Analyse Packet #'+p.id+':\\nProto: '+p.proto+'  Len: '+p.frame_len+'B\\nSummary: '+p.summary+'\\n\\n'+layers+'\\n\\nExplain: 1)RFC 2)each field 3)src→dst 4)purpose 5)security notes';
  const el=document.getElementById('ai-resp');el.textContent='Analysing…';
  try{{
    const r=await fetch('/api/chat',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{prompt:'Context:\\n'+JSON.stringify(CTX)+'\\n\\n'+q}})}});
    const d=await r.json();el.innerHTML=fmt(d.response||d.error||'No response');
  }}catch(e){{el.textContent='Error: '+e.message;}}
}}

function toggleCollapsible(id){{
  const el=document.getElementById(id);
  const btn=event.target;
  if(el.style.display==='none'){{
    el.style.display='block';
    btn.textContent=btn.textContent.replace('▶','▼');
  }}else{{
    el.style.display='none';
    btn.textContent=btn.textContent.replace('▼','▶');
  }}
}}

function toggleCompleteAnalysis(){{
  const el=document.getElementById('complete-analysis-ai');
  if(el.style.display==='none'){{ el.style.display='block'; askCompleteAnalysis(); }}
  else{{ el.style.display='none'; }}
}}

async function askCompleteAnalysis(){{
  const el=document.getElementById('complete-analysis-resp');
  el.innerHTML='<div style="color:var(--acc)">🔄 Analysing protocols in this capture…</div>';

  // Protocol counts
  const protoCounts={{}};
  Object.values(ALL_PKTS).forEach(p=>{{ protoCounts[p.proto||'?']=(protoCounts[p.proto||'?']||0)+1; }});
  const protoSummary=Object.entries(protoCounts).sort((a,b)=>b[1]-a[1]).map(([p,c])=>p+': '+c).join(', ');

  // Layer stack summary
  const layerStacks={{}};
  Object.values(ALL_PKTS).forEach(p=>{{const s=(p.layers||[]).map(l=>l.title.split('(')[0].trim()).join(' > ');if(s) layerStacks[s]=(layerStacks[s]||0)+1;}});
  const stackSummary=Object.entries(layerStacks).sort((a,b)=>b[1]-a[1]).map(([s,c])=>s+': '+c+' pkts').join('\\n');

  // Hosts
  const hosts=(FLOW_DATA.hosts||[]).slice(0,10).join(', ');

  const q='This pcap contains: '+protoSummary+'.\\n'+
    'Layer stacks:\\n'+stackSummary+'\\n'+
    'Hosts: '+hosts+'\\n\\n'+
    'Explain the PURPOSE of each protocol seen in this capture and what ROLE it plays. '+
    'Why is each protocol here? How do they work together? What is the overall network activity story? '+
    'Reference the RFC for each protocol. Be concise.';

  try{{
    const r=await fetch('/api/chat',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{prompt:q,skip_rag:true}})}});
    const d=await r.json();
    el.innerHTML=fmt(d.response||d.error||'No response');
  }}catch(e){{
    el.textContent='Error: '+e.message;
  }}
}}

async function askIgmpPacketAnalysis(){{
  if(!curId){{alert('⚠️  Select a packet first by clicking on a row in Packets tab');return;}}
  const p=ALL_PKTS[String(curId)];
  if(!p){{alert('❌ Packet not found');return;}}
  
  // Determine which response area to use (Packets tab or Protocols tab)
  const responseEl=document.getElementById('igmp-packet-ai-response');
  const protResponseEl=document.getElementById('protocol-packet-ai-response');
  
  // Show appropriate response area based on which is visible
  const isProtocolsView=document.getElementById('view-protocols').style.display!=='none';
  const targetResponseEl=isProtocolsView?protResponseEl:responseEl;
  const targetRespDiv=isProtocolsView?document.getElementById('protocol-packet-ai-resp'):document.getElementById('igmp-packet-ai-resp');
  
  if(targetResponseEl) targetResponseEl.style.display='block';
  targetRespDiv.textContent='🔄 Analyzing packet with RFC standards…';
  
  const layers=(p.layers||[]).map(l=>l.title+':\\n'+(l.fields||[]).map(f=>f.n+': '+f.v+(f.note?' ('+f.note+')':'')).join('\\n')).join('\\n\\n');
  const q='This is a network packet. Analyze it according to RFC standards:\\n\\n**Packet #'+p.id+'**\\nProtocol: '+p.proto+'\\nLength: '+p.frame_len+'B\\nTimestamp: '+p.ts+'s\\nSummary: '+p.summary+'\\n\\n**Packet Layers:**\\n'+layers+'\\n\\n**Analysis Required:**\\n1) What RFC standards apply to this packet?\\n2) Explain each important field and its value\\n3) What is the purpose of this packet in the protocol flow?\\n4) Source → Destination communication summary\\n5) Are there any RFC compliance issues or anomalies?';
  
  try{{
    const r=await fetch('/api/chat',{{
      method:'POST',
      headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{prompt:'Context:\\n'+JSON.stringify(CTX)+'\\n\\n'+q}})
    }});
    const d=await r.json();
    targetRespDiv.innerHTML=fmt(d.response||d.error||'No response received');
  }}catch(e){{
    targetRespDiv.innerHTML='<span style=\"color:#ef4444\">Error: '+e.message+'</span>';
  }}
}}

function toggleIgmpPacketAi(){{
  const el=document.getElementById('igmp-packet-ai');
  if(el.style.display==='none'){{
    el.style.display='block';
    askIgmpPacketAnalysis();
  }}else{{
    el.style.display='none';
  }}
}}

// ═══════════════════════════════════════════════════════════════
//  PROTOCOL EXTRA TABS
// ═══════════════════════════════════════════════════════════════
function ptab(btn,pid){{
  document.querySelectorAll('.ptab').forEach(b=>b.classList.remove('on'));btn.classList.add('on');
  document.querySelectorAll('.ppanel').forEach(p=>p.style.display='none');
  const el=document.getElementById(pid);if(el)el.style.display='block';
}}

// Navigate to packet in Packets view from any other view
function selPktNav(id){{goView('packets',document.getElementById('nb-packets'));requestAnimationFrame(()=>setTimeout(()=>selPkt(id),30));}}

// ═══════════════════════════════════════════════════════════════
//  AI CHAT
// ═══════════════════════════════════════════════════════════════
function fmt(t){{
  t=t.replace(/[*][*](.*?)[*][*]/g,'<strong style="color:var(--acc)">$1</strong>');
  t=t.replace(/`([^`]+)`/g,'<code>$1</code>');
  return t.replace(/\\n/g,'<br>');
}}
function addMsg(txt,isUser){{
  const box=document.getElementById('msgs');
  const d=document.createElement('div');d.className='msg '+(isUser?'mu':'mb');
  d.innerHTML=isUser?txt:fmt(txt);box.appendChild(d);box.scrollTop=box.scrollHeight;return d;
}}
function _appendDocLinks(msgEl,links){{
  if(!links||!links.length)return;
  const box=document.getElementById('msgs');
  const footer=document.createElement('div');footer.className='msg-doclinks';
  footer.innerHTML='<span style="font:700 8px var(--sans);color:var(--muted);margin-right:4px">📖 References:</span>'
    +links.map(function(l){{
      return '<a class="msg-doclink" href="'+l.url+'" target="_blank" rel="noopener noreferrer">'+l.label+'</a>';
    }}).join('');
  msgEl.appendChild(footer);
  if(box)box.scrollTop=box.scrollHeight;
}}
function addThink(){{
  const box=document.getElementById('msgs');
  const d=document.createElement('div');d.className='think';
  d.innerHTML='Analysing<div class="dots"><span></span><span></span><span></span></div>';
  box.appendChild(d);box.scrollTop=box.scrollHeight;return d;
}}
function _getMcpSwitchIp() {{
  const ipEl = document.getElementById('mcp-switch-ip');
  return ipEl ? ipEl.value.trim() : '';
}}
function _mcpSetIp() {{
  const ip = _getMcpSwitchIp();
  if (ip) {{
    _addMcpMsg('\u2705 Switch IP set to **' + ip + '**. All queries will target this switch.', false);
  }} else {{
    _addMcpMsg('\u26a0\ufe0f Enter a switch IP first (e.g. 10.127.32.224).', false);
  }}
}}
function _addMcpMsg(text, isUser) {{
  const box = document.getElementById('mcp-msgs');
  if (!box) return null;
  const d = document.createElement('div');
  d.className = 'msg' + (isUser ? ' mu' : ' mb');
  if (!isUser) d.style.cssText = 'border-left:2px solid #7c3aed44';
  d.innerHTML = isUser ? text : fmt(text);
  box.appendChild(d);
  box.scrollTop = box.scrollHeight;
  return d;
}}
function _addMcpThink() {{
  const box = document.getElementById('mcp-msgs');
  if (!box) return {{remove:function(){{}}}};
  const d = document.createElement('div');
  d.className = 'msg mb think';
  d.style.cssText = 'border-left:2px solid #7c3aed44;color:#a78bfa';
  d.textContent = '⏳ Connecting to MCP server...';
  box.appendChild(d);
  box.scrollTop = box.scrollHeight;
  return d;
}}
async function sendMcp(q) {{
  if (!q) {{
    const el = document.getElementById('inp');
    q = el.value.trim();
    if (!q) return;
    el.value = '';
  }}
  _addMcpMsg(q, true);
  const th = _addMcpThink();
  const switchIp = _getMcpSwitchIp();
  // Inject switch IP into query if set and not already present
  let fullPrompt = q;
  if (switchIp && !q.includes(switchIp)) fullPrompt = q + ' on ' + switchIp;
  try {{
    const r = await fetch('/api/chat', {{method:'POST', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{prompt: fullPrompt, mode: 'mcp', switch_ip: switchIp}})}});
    const d = await r.json();
    th.remove();
    _addMcpMsg('🔌 **[Live \u2014 exos-mcp-server]**\\n\\n' + (d.response || d.error || 'No response'), false);
  }} catch(e) {{ th.remove(); _addMcpMsg('❌ MCP Error: ' + e.message, false); }}
}}
function askMcp(q) {{ showSbMode('mcp'); sendMcp(q); }}

// Chat tab conversation history (client-side, max 20 pairs)
let _chatHistory = [];
const _CHAT_HIST_MAX = 20;

function _chatClear() {{
  _chatHistory = [];
  const box = document.getElementById('msgs');
  if (box) {{ box.innerHTML = ''; addMsg('Chat history cleared. Starting fresh!', false); }}
}}

async function send(){{
  const el=document.getElementById('inp');const q=el.value.trim();if(!q)return;
  // If MCP tab active → sendMcp; if EXOS tab active → sendExos
  if (_activeSbMode === 'mcp')  {{ el.value=''; sendMcp(q); return; }}
  if (_activeSbMode === 'exos') {{ el.value=''; sendExos(q, null); return; }}
  if (_activeSbMode === 'rfc')  {{ el.value=''; sendRfc(q, null); return; }}
  el.value='';addMsg(q,true);const th=addThink();
  const docLinks=window._pendingDocLinks||null;window._pendingDocLinks=null;
  try{{
    const r=await fetch('/api/chat',{{method:'POST',headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{
        prompt: 'Context:\\n'+JSON.stringify(CTX)+'\\n\\nQuestion: '+q,
        history: _chatHistory
      }})}});
    const d=await r.json();th.remove();
    // Update local history from server response
    if (d.history) _chatHistory = d.history.slice(-(_CHAT_HIST_MAX * 2));
    const msgEl=addMsg(d.response||d.error||'No response',false);
    _appendDocLinks(msgEl,docLinks);
  }}catch(e){{th.remove();addMsg('Error: '+e.message,false);}}
}}
function ask(q){{document.getElementById('inp').value=q;send();}}
function askWithDocs(q,links){{window._pendingDocLinks=links;document.getElementById('inp').value=q;send();}}

// ═══════════════════════════════════════════════════════════════
//  EXOS TAB HELPERS  (own message area, RAG-backed, no MCP)
// ═══════════════════════════════════════════════════════════════
function _addExosMsg(text, isUser) {{
  const box = document.getElementById('exos-msgs');
  if (!box) return null;
  const d = document.createElement('div');
  d.className = 'msg' + (isUser ? ' mu' : ' mb');
  if (!isUser) d.style.cssText = 'border-left:2px solid #22d3ee44';
  d.innerHTML = isUser ? text : fmt(text);
  box.appendChild(d);
  box.scrollTop = box.scrollHeight;
  return d;
}}
function _addExosThink() {{
  const box = document.getElementById('exos-msgs');
  if (!box) return {{remove:function(){{}}}};
  const d = document.createElement('div');
  d.className = 'msg mb think';
  d.style.cssText = 'border-left:2px solid #22d3ee44;color:#67e8f9';
  d.innerHTML = 'Looking up Switch Engine docs<div class="dots"><span></span><span></span><span></span></div>';
  box.appendChild(d);
  box.scrollTop = box.scrollHeight;
  return d;
}}
async function sendExos(q, docLinks) {{
  if (!q) {{
    const el = document.getElementById('inp');
    q = el.value.trim();
    if (!q) return;
    el.value = '';
  }}
  _addExosMsg(q, true);
  const th = _addExosThink();
  try {{
    const r = await fetch('/api/chat', {{method:'POST', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{
        prompt: 'Context:\\n' + JSON.stringify(CTX) + '\\n\\nQuestion: ' + q,
        mode: 'exos'
      }})}});
    const d = await r.json();
    th.remove();
    const msgEl = _addExosMsg(d.response || d.error || 'No response', false);
    // Append doc reference links if provided
    if (docLinks && docLinks.length && msgEl) {{
      const footer = document.createElement('div');
      footer.className = 'msg-doclinks';
      footer.innerHTML = '<span style="font:700 8px var(--sans);color:var(--muted);margin-right:4px">\U0001f4d6 References:</span>'
        + docLinks.map(function(l){{
            return '<a class="msg-doclink" href="' + l.url + '" target="_blank" rel="noopener noreferrer">' + l.label + '</a>';
          }}).join('');
      msgEl.appendChild(footer);
      const box = document.getElementById('exos-msgs');
      if (box) box.scrollTop = box.scrollHeight;
    }}
  }} catch(e) {{ th.remove(); _addExosMsg('\u274c Error: ' + e.message, false); }}
}}
function askExos(q) {{ showSbMode('exos'); sendExos(q, null); }}
function sendExosWithDocs(q, links) {{ showSbMode('exos'); sendExos(q, links); }}

// ═══════════════════════════════════════════════════════════════
//  RFC TAB HELPERS  (own message area, RFC RAG-backed, no MCP)
// ═══════════════════════════════════════════════════════════════
function _addRfcMsg(text, isUser) {{
  const box = document.getElementById('rfc-msgs');
  if (!box) return null;
  const d = document.createElement('div');
  d.className = 'msg' + (isUser ? ' mu' : ' mb');
  if (!isUser) d.style.cssText = 'border-left:2px solid #60a5fa44';
  d.innerHTML = isUser ? text : fmt(text);
  box.appendChild(d);
  box.scrollTop = box.scrollHeight;
  return d;
}}
function _addRfcThink() {{
  const box = document.getElementById('rfc-msgs');
  if (!box) return {{remove:function(){{}}}};
  const d = document.createElement('div');
  d.className = 'msg mb think';
  d.style.cssText = 'border-left:2px solid #60a5fa44;color:#93c5fd';
  d.innerHTML = 'Looking up RFC references<div class="dots"><span></span><span></span><span></span></div>';
  box.appendChild(d);
  box.scrollTop = box.scrollHeight;
  return d;
}}
async function sendRfc(q, docLinks) {{
  if (!q) {{
    const el = document.getElementById('inp');
    q = el.value.trim();
    if (!q) return;
    el.value = '';
  }}
  _addRfcMsg(q, true);
  const th = _addRfcThink();
  try {{
    const r = await fetch('/api/chat', {{method:'POST', headers:{{'Content-Type':'application/json'}},
      body: JSON.stringify({{
        prompt: 'Context:\\n' + JSON.stringify(CTX) + '\\n\\nQuestion: ' + q,
        mode: 'rfc'
      }})}});
    const d = await r.json();
    th.remove();
    const msgEl = _addRfcMsg(d.response || d.error || 'No response', false);
    if (docLinks && docLinks.length && msgEl) {{
      const footer = document.createElement('div');
      footer.className = 'msg-doclinks';
      footer.innerHTML = '<span style="font:700 8px var(--sans);color:var(--muted);margin-right:4px">\U0001f4d6 References:</span>'
        + docLinks.map(function(l){{
            return '<a class="msg-doclink" href="' + l.url + '" target="_blank" rel="noopener noreferrer">' + l.label + '</a>';
          }}).join('');
      msgEl.appendChild(footer);
      const box = document.getElementById('rfc-msgs');
      if (box) box.scrollTop = box.scrollHeight;
    }}
  }} catch(e) {{ th.remove(); _addRfcMsg('\u274c Error: ' + e.message, false); }}
}}
function askRfc(q) {{ showSbMode('rfc'); sendRfc(q, null); }}
function sendRfcWithDocs(q, links) {{ showSbMode('rfc'); sendRfc(q, links); }}

// ═══════════════════════════════════════════════════════════════
//  SIDEBAR RESIZE / COLLAPSE
// ═══════════════════════════════════════════════════════════════
(function() {{
  const _SB_SIZES = [240, 340, 520];
  let _sbSizeIdx  = 1; // default = 340px

  function _sbSetWidth(w) {{
    const sb = document.getElementById('sb');
    if (sb) {{ sb.style.width = w + 'px'; sb.classList.remove('sb-collapsed'); }}
  }}

  window._sbCollapse = function() {{
    const sb = document.getElementById('sb');
    if (sb) sb.classList.add('sb-collapsed');
  }};

  window._sbExpand = function() {{
    const sb = document.getElementById('sb');
    if (sb) {{ sb.classList.remove('sb-collapsed'); sb.style.width = _SB_SIZES[_sbSizeIdx] + 'px'; }}
  }};

  window._sbCycleSize = function() {{
    _sbSizeIdx = (_sbSizeIdx + 1) % _SB_SIZES.length;
    _sbSetWidth(_SB_SIZES[_sbSizeIdx]);
  }};

  // Drag-to-resize from the left edge handle
  const handle = document.getElementById('sb-resize-handle');
  if (handle) {{
    let _dragging = false, _startX = 0, _startW = 0;
    handle.addEventListener('mousedown', function(e) {{
      const sb = document.getElementById('sb');
      if (!sb) return;
      _dragging = true;
      _startX = e.clientX;
      _startW = sb.offsetWidth;
      handle.classList.add('dragging');
      e.preventDefault();
    }});
    document.addEventListener('mousemove', function(e) {{
      if (!_dragging) return;
      const sb = document.getElementById('sb');
      if (!sb) return;
      const delta = _startX - e.clientX; // drag left = wider
      const newW  = Math.max(200, Math.min(800, _startW + delta));
      sb.style.width = newW + 'px';
      sb.classList.remove('sb-collapsed');
    }});
    document.addEventListener('mouseup', function() {{
      if (_dragging) {{ _dragging = false; handle.classList.remove('dragging'); }}
    }});
  }}
}})();

// ═══════════════════════════════════════════════════════════════
//  AI CONFIG (runtime model switching)
// ═══════════════════════════════════════════════════════════════
async function applyAIConfig(){{
  const backend=document.getElementById('ai-backend').value;
  const model=document.getElementById('ai-model').value.trim();
  const key=document.getElementById('ai-key').value;
  try{{
    const r=await fetch('/api/config',{{method:'POST',headers:{{'Content-Type':'application/json'}},
      body:JSON.stringify({{backend,model,key}})}});
    const d=await r.json();
    if(d.ok){{
      const lbl=document.getElementById('ai-chip-label');
      if(lbl) lbl.textContent=d.model||model||backend;
      addMsg('✅ AI backend switched to **'+backend+'** ('+( d.model||model)+')' ,false);
    }}
  }}catch(e){{ addMsg('❌ Failed to update AI config: '+e.message,false); }}
}}

// ═══════════════════════════════════════════════════════════════
//  ANOMALY AUTO-DIAGNOSIS
// ═══════════════════════════════════════════════════════════════
function diagnoseAnomalies(){{
  if(!ANOMALIES||!ANOMALIES.length){{ addMsg('No anomalies to diagnose.',false); return; }}
  const list=ANOMALIES.map((a,i)=>(i+1)+'. '+a).join('\\n');
  const prompt='I have detected the following anomalies in this PCAP capture:\\n\\n'+list
    +'\\n\\nFor each anomaly, provide:\\n'
    +'1. **Root Cause Analysis** — what is causing this on an Extreme Networks Switch Engine switch\\n'
    +'2. **Impact Assessment** — severity and which services or forwarding behaviour is affected\\n'
    +'3. **Switch Engine CLI Commands** — ONLY use commands from the official Extreme Networks Switch Engine documentation:\\n'
    +'   • Switch Engine v33.6.1 User Guide: https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20User%20Guide/downloads/Switch_Engine_33_6_1_User_Guide.pdf\\n'
    +'   • Switch Engine v33.6.1 Command References: https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20Command%20References/downloads/Switch_Engine_33_6_1_Command_References.pdf\\n'
    +'   • EMS Messages Catalog: https://documentation.extremenetworks.com/ExtremeXOS%20and%20Switch%20Engine%20v33.6.x%20EMS%20Messages%20Catalog/downloads/ExtremeXOS_and_Switch_Engine_33_6_x_EMS_Message_Catalog.pdf\\n'
    +'   • Doc index: https://supportdocs.extremenetworks.com/support/documentation/switch-engine-33-6-1/\\n'
    +'   Do NOT reference commands from other Extreme products (Fabric Engine, VOSS, EOS, SLX, NetIron, etc.)\\n'
    +'4. **Recommended Fix** — specific Switch Engine configuration steps with correct CLI syntax\\n'
    +'5. **RFC References** — relevant standards for each anomaly\\n'
    +'6. **Documentation Reference** — cite the exact Switch Engine doc section covering each command';
  ask(prompt);
}}

// ═══════════════════════════════════════════════════════════════
//  AI PROTOCOL ANALYST: MODE SWITCHER & PANEL FUNCTIONS
// ═══════════════════════════════════════════════════════════════
const _SB_MODES = ['insights','explain','rfc','exos','mcp','chat'];
let _activeSbMode = 'insights';
function showSbMode(mode) {{
  _activeSbMode = mode;
  _SB_MODES.forEach(function(m) {{
    const btn   = document.getElementById('sbm-' + m);
    const panel = document.getElementById('sbp-' + m);
    const on    = m === mode;
    if (btn)   {{ btn.classList.toggle('on', on); }}
    if (panel) {{ panel.classList.toggle('on', on); }}
  }});
  // Build dynamic proto buttons on first open
  if (mode === 'rfc')  _buildProtoButtons('rfc-proto-btns',  'rfc');
  if (mode === 'exos') _buildProtoButtons('exos-proto-btns', 'exos');
  // Scroll message panels to bottom
  if (mode === 'chat') {{
    const msgs = document.getElementById('msgs');
    if (msgs) msgs.scrollTop = msgs.scrollHeight;
  }}
  if (mode === 'rfc') {{
    const rmsg = document.getElementById('rfc-msgs');
    if (rmsg) rmsg.scrollTop = rmsg.scrollHeight;
    const inp = document.getElementById('inp');
    if (inp) inp.placeholder = 'Ask about RFC standards, protocol specs, packet formats...';
  }}
  if (mode === 'exos') {{
    const emsg = document.getElementById('exos-msgs');
    if (emsg) emsg.scrollTop = emsg.scrollHeight;
    const inp = document.getElementById('inp');
    if (inp) inp.placeholder = 'Ask about Switch Engine CLI, debug commands, EMS logs...';
  }}
  if (mode === 'mcp') {{
    const mmsg = document.getElementById('mcp-msgs');
    if (mmsg) mmsg.scrollTop = mmsg.scrollHeight;
    const inp = document.getElementById('inp');
    if (inp) inp.placeholder = 'Ask about your switch (e.g. show vlans on 10.127.0.1)...';
  }} else if (mode !== 'exos' && mode !== 'rfc') {{
    const inp = document.getElementById('inp');
    if (inp) inp.placeholder = 'Ask about protocols, RFCs, analysis...';
  }}
}}

function _buildProtoButtons(containerId, action) {{
  const el = document.getElementById(containerId);
  if (!el || el.dataset.built) return;
  el.dataset.built = '1';
  const protos = CTX.protocols || [];
  el.innerHTML = protos.map(function(p) {{
    const name = p.name;
    const col  = pc(name);
    const fn   = action === 'rfc' ? 'rfcAnalysis' : 'exosDebug';
    return '<span class="proto-chip" '
      + 'style="background:' + col + '22;color:' + col + ';border-color:' + col + '55" '
      + 'onclick="' + fn + '(\\'' + name + '\\')" '
      + 'title="' + p.count + ' packets">' + name + '</span>';
  }}).join('');
}}

function rfcAnalysis(proto) {{
  // Maps protocol → RFC reference + Switch Engine chapter so the AI searches the right section
  const rfcMap = {{
    ARP:   {{ rfc:'RFC 826 (ARP)',             swChapter:'ARP' }},
    ICMP:  {{ rfc:'RFC 792 (ICMPv4)',          swChapter:'IP Unicast Routing' }},
    TCP:   {{ rfc:'RFC 793 (TCP)',             swChapter:'Packet Capture' }},
    UDP:   {{ rfc:'RFC 768 (UDP)',             swChapter:'Packet Capture' }},
    DNS:   {{ rfc:'RFC 1035 (DNS)',            swChapter:'DNS Client' }},
    DHCP:  {{ rfc:'RFC 2131 (DHCP)',           swChapter:'DHCP Client and Server' }},
    DHCPv6:{{ rfc:'RFC 8415 (DHCPv6)',         swChapter:'DHCPv6' }},
    HTTP:  {{ rfc:'RFC 7230-7235 (HTTP/1.1)',  swChapter:'Web HTTP/HTTPS' }},
    HTTPS: {{ rfc:'RFC 7230 + TLS RFC 8446',   swChapter:'SSL/TLS and Web Access' }},
    TLS:   {{ rfc:'RFC 8446 (TLS 1.3)',        swChapter:'SSL/TLS' }},
    SSH:   {{ rfc:'RFC 4253 (SSH)',            swChapter:'SSH2' }},
    BGP:   {{ rfc:'RFC 4271 (BGP-4)',          swChapter:'BGP' }},
    OSPF:  {{ rfc:'RFC 2328 (OSPFv2)',         swChapter:'OSPF' }},
    LLDP:  {{ rfc:'IEEE 802.1AB (LLDP)',       swChapter:'LLDP' }},
    IPv6:  {{ rfc:'RFC 8200 (IPv6)',           swChapter:'IPv6 Unicast Routing' }},
    IGMP:  {{ rfc:'RFC 3376 (IGMPv3)',         swChapter:'IP Multicast / IGMP Snooping' }},
    NTP:   {{ rfc:'RFC 5905 (NTP v4)',         swChapter:'NTP' }},
    SNMP:  {{ rfc:'RFC 3411-3418 (SNMPv3)',    swChapter:'SNMP' }},
    STP:   {{ rfc:'IEEE 802.1D (STP)',         swChapter:'Spanning Tree Protocol' }},
    RSTP:  {{ rfc:'IEEE 802.1w (RSTP)',        swChapter:'Spanning Tree Protocol' }},
    FTP:   {{ rfc:'RFC 959 (FTP)',             swChapter:'File Management' }},
    SMTP:  {{ rfc:'RFC 5321 (SMTP)',           swChapter:'Packet Capture' }},
    mDNS:  {{ rfc:'RFC 6762 (mDNS)',           swChapter:'mDNS Proxy' }},
    QUIC:  {{ rfc:'RFC 9000 (QUIC)',           swChapter:'Packet Capture' }},
    RIP:   {{ rfc:'RFC 2453 (RIPv2)',          swChapter:'RIP' }},
    VRRP:  {{ rfc:'RFC 5798 (VRRPv3)',         swChapter:'VRRP' }},
    ISIS:  {{ rfc:'ISO/IEC 10589 (IS-IS)',     swChapter:'IS-IS' }},
    EAPoL: {{ rfc:'IEEE 802.1X (EAPoL)',       swChapter:'Network Login (802.1X)' }},
  }};
  const entry   = rfcMap[proto] || {{}};
  const refStr  = entry.rfc       || proto;
  const swChap  = entry.swChapter || proto + ' (search in Switch Engine User Guide)';
  const prompt = 'Explain the ' + proto + ' protocol in depth using ' + refStr + '.\\n\\n'
    + 'Include:\\n'
    + '1. **Protocol Overview** — purpose and design per ' + refStr + '\\n'
    + '2. **Packet Structure** — key header fields\\n'
    + '3. **Operation Flow** — how it works step by step\\n'
    + '4. **Observations in this capture** — what the ' + proto + ' traffic tells us\\n'
    + '5. **Common Issues** — error conditions and RFC-defined failure modes\\n'
    + '6. **Switch Engine CLI Commands** — look up "' + proto + '" in the "' + swChap + '" chapter of the Switch Engine docs to show commands for inspecting ' + proto + '.\\n'
    + '   ONLY use commands from these official Switch Engine documents:\\n'
    + '   • Command References (search "' + proto + '"): https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20Command%20References/downloads/Switch_Engine_33_6_1_Command_References.pdf\\n'
    + '   • User Guide chapter "' + swChap + '": https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20User%20Guide/downloads/Switch_Engine_33_6_1_User_Guide.pdf\\n'
    + '   Do NOT use commands from other Extreme products (Fabric Engine, VOSS, EOS, SLX, NetIron, etc.)';
  sendRfcWithDocs(prompt, [
    {{label:'SW Engine Command References (search: '+proto+')', url:'https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20Command%20References/downloads/Switch_Engine_33_6_1_Command_References.pdf'}},
    {{label:'SW Engine User Guide — '+swChap,                   url:'https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20User%20Guide/downloads/Switch_Engine_33_6_1_User_Guide.pdf'}},
  ]);
}}

function exosDebug(proto) {{
  const protoCtx = (CTX.protocols||[]).find(function(p){{return p.name===proto;}}) || null;

  // Maps each protocol to its Switch Engine doc search term, User Guide chapter, and known CLI commands.
  const _SW_PROTO_MAP = {{
    ARP:   {{ term:'ARP',           chapter:'ARP (Address Resolution Protocol)',         cmds:['show iparp','show iparp proxy','show iparp statistics','clear iparp'] }},
    DHCP:  {{ term:'DHCP',          chapter:'DHCP Client and Server',                   cmds:['show dhcp-client','show dhcpv4 server','show dhcpv4 server lease','show dhcpv4 server binding','show dhcpv4 server statistics'] }},
    DHCPv6:{{ term:'DHCPv6',        chapter:'DHCPv6',                                   cmds:['show dhcpv6 client','show dhcpv6 server','show dhcpv6 server binding','show dhcpv6 server statistics'] }},
    DNS:   {{ term:'DNS',           chapter:'DNS Client',                               cmds:['show dns-client','show dns-client configuration','ping <hostname>'] }},
    mDNS:  {{ term:'mDNS',          chapter:'mDNS Proxy',                               cmds:['show mdns-proxy','show mdns-proxy service-record','show mdns-proxy statistics'] }},
    ICMP:  {{ term:'ICMP',          chapter:'IP Unicast Routing',                       cmds:['ping','traceroute','show iproute statistics','show iproute','show ip-security'] }},
    TCP:   {{ term:'packet capture', chapter:'Packet Capture',                          cmds:['debug packet capture filter tcp on port <port>','show ports <port> statistics','show ports <port> packet-buffers'] }},
    UDP:   {{ term:'packet capture', chapter:'Packet Capture',                          cmds:['debug packet capture filter udp on port <port>','show ports <port> statistics'] }},
    OSPF:  {{ term:'OSPF',          chapter:'OSPF',                                     cmds:['show ospf','show ospf neighbor','show ospf lsdb','show ospf interface <vlan>','debug ospf'] }},
    BGP:   {{ term:'BGP',           chapter:'BGP',                                      cmds:['show bgp','show bgp neighbor','show bgp routes','show bgp neighbor statistics','show bgp summary','debug bgp'] }},
    STP:   {{ term:'STP',           chapter:'Spanning Tree Protocol',                   cmds:['show stpd','show stpd detail','show stpd ports','debug stpd'] }},
    RSTP:  {{ term:'STP',           chapter:'Spanning Tree Protocol',                   cmds:['show stpd','show stpd detail','show stpd ports'] }},
    LLDP:  {{ term:'LLDP',          chapter:'LLDP',                                     cmds:['show lldp','show lldp neighbors','show lldp port <port> neighbors detail','show lldp statistics'] }},
    IGMP:  {{ term:'IGMP',          chapter:'IP Multicast / IGMP Snooping',             cmds:['show igmp','show igmp snooping','show igmp snooping vlan <name>','show multicast cache','debug igmp'] }},
    NTP:   {{ term:'NTP',           chapter:'NTP',                                      cmds:['show ntp','show ntp associations','show ntp status','show ntp server'] }},
    SNMP:  {{ term:'SNMP',          chapter:'SNMP',                                     cmds:['show snmp','show snmp community','show snmp trap receiver','show snmp statistics','debug snmp'] }},
    SSH:   {{ term:'SSH',           chapter:'SSH2',                                     cmds:['show ssh2','show ssh2 session','show management'] }},
    TLS:   {{ term:'SSL',           chapter:'SSL/TLS',                                  cmds:['show ssl','show ssl detail','show management'] }},
    HTTPS: {{ term:'SSL',           chapter:'SSL/TLS and Web Access',                   cmds:['show management','show ssl','show web'] }},
    HTTP:  {{ term:'HTTP',          chapter:'Web HTTP/HTTPS',                           cmds:['show management','show web'] }},
    FTP:   {{ term:'FTP',           chapter:'File Management',                          cmds:['show management','show log'] }},
    IPv6:  {{ term:'IPv6',          chapter:'IPv6 Unicast Routing',                     cmds:['show ipv6','show ipv6 neighbor-discovery cache','show ipv6 route','show ipv6 ospf'] }},
    EAPoL: {{ term:'NetLogin',      chapter:'Network Login (802.1X / MAC-based)',       cmds:['show netlogin','show netlogin port','show netlogin session','debug netlogin'] }},
    RARP:  {{ term:'ARP',           chapter:'ARP',                                      cmds:['show iparp','show iparp statistics'] }},
    QUIC:  {{ term:'packet capture', chapter:'Packet Capture',                          cmds:['debug packet capture on port <port>','show ports <port> statistics detail'] }},
    RIP:   {{ term:'RIP',           chapter:'RIP',                                      cmds:['show rip','show rip interface','show rip routes','debug rip'] }},
    EIGRP: {{ term:'packet capture', chapter:'Packet Capture',                          cmds:['debug packet capture on port <port>','show log'] }},
    ISIS:  {{ term:'IS-IS',         chapter:'IS-IS',                                    cmds:['show isis','show isis adjacency','show isis lsdb'] }},
    VRRP:  {{ term:'VRRP',          chapter:'VRRP',                                     cmds:['show vrrp','show vrrp interface','show vrrp statistics'] }},
    MPLS:  {{ term:'MPLS',          chapter:'MPLS',                                     cmds:['show mpls','show mpls forwarding','show mpls lsp'] }},
  }};

  const info       = _SW_PROTO_MAP[proto] || null;
  const searchTerm = info ? info.term    : proto;
  const chapter    = info ? info.chapter : proto + ' (search in Switch Engine User Guide)';
  const knownCmds  = info ? info.cmds    : [];
  const cmdHint    = knownCmds.length
    ? 'The following Switch Engine CLI commands are relevant for ' + proto + ':\\n'
      + knownCmds.map(function(c){{return '  \u2022 ' + c;}}).join('\\n')
      + '\\n\\nFor each command above, explain its exact syntax, expected output, and what abnormal output looks like.\\n\\n'
    : '';

  const prompt = 'Troubleshoot ' + proto + ' issues found in this PCAP capture using Extreme Networks Switch Engine CLI.\\n\\n'
    + cmdHint
    + 'DOCUMENTATION: Look up "' + searchTerm + '" in the "' + chapter + '" section of these official Switch Engine v33.6.1 documents:\\n'
    + '\u2022 Command References: https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20Command%20References/downloads/Switch_Engine_33_6_1_Command_References.pdf\\n'
    + '\u2022 User Guide (chapter: "' + chapter + '"): https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20User%20Guide/downloads/Switch_Engine_33_6_1_User_Guide.pdf\\n'
    + '\u2022 EMS Messages Catalog: https://documentation.extremenetworks.com/ExtremeXOS%20and%20Switch%20Engine%20v33.6.x%20EMS%20Messages%20Catalog/downloads/ExtremeXOS_and_Switch_Engine_33_6_x_EMS_Message_Catalog.pdf\\n'
    + 'Do NOT use commands from Fabric Engine, VOSS, EOS, SLX, NetIron or any other Extreme product line.\\n\\n'
    + 'Provide:\\n'
    + '1. **show commands** \u2014 exact `show` commands for ' + proto + ' from the "' + chapter + '" chapter\\n'
    + '2. **debug / capture** \u2014 packet-level capture or debug commands for ' + proto + '\\n'
    + '3. **EMS log messages** \u2014 specific ' + proto + '-related EMS log events to monitor\\n'
    + '4. **config verification** \u2014 commands to check ' + proto + ' configuration is correct\\n'
    + '5. **healthy vs abnormal output** \u2014 what to look for in each command result\\n'
    + '6. **common misconfigurations** \u2014 ' + proto + '-specific mistakes on Switch Engine\\n'
    + '7. **chapter reference** \u2014 cite the exact "' + chapter + '" section from the Switch Engine documentation\\n\\n'
    + 'Capture context: ' + CTX.total + ' total packets'
    + (protoCtx ? ', ' + proto + '=' + protoCtx.count + ' pkts (' + protoCtx.bytes + ' bytes)' : '');
  showSbMode('exos');
  const _exosLinks = [
    {{label:'SW Engine Command References ('+proto+')', url:'https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20Command%20References/downloads/Switch_Engine_33_6_1_Command_References.pdf'}},
    {{label:'User Guide \u2014 '+chapter,                   url:'https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20User%20Guide/downloads/Switch_Engine_33_6_1_User_Guide.pdf'}},
    {{label:'EMS Messages Catalog',                    url:'https://documentation.extremenetworks.com/ExtremeXOS%20and%20Switch%20Engine%20v33.6.x%20EMS%20Messages%20Catalog/downloads/ExtremeXOS_and_Switch_Engine_33_6_x_EMS_Message_Catalog.pdf'}},
  ];
  sendExosWithDocs(prompt, _exosLinks);
}}

function submitCustomRFC() {{
  const inp = document.getElementById('rfc-manual-inp');
  if (!inp) return;
  const num = parseInt(inp.value, 10);
  if (!num || num < 1 || num > 9999) {{
    addMsg('Please enter a valid RFC number (1–9999).', false);
    showSbMode('chat');
    return;
  }}
  inp.value = '';
  const prompt = 'Summarise RFC ' + num + ' in detail.\\n\\n'
    + 'Include:\\n'
    + '1. **RFC title and purpose**\\n'
    + '2. **Protocol or standard it defines**\\n'
    + '3. **Key mechanisms and packet formats**\\n'
    + '4. **How it relates to the traffic in this capture** (if applicable)\\n'
    + '5. **Related RFCs and updates**';
  sendRfcWithDocs(prompt, [
    {{label:'RFC ' + num + ' (IETF RFC Editor)', url:'https://www.rfc-editor.org/rfc/rfc' + num + '.html'}},
    {{label:'SW Engine Command References',      url:'https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20Command%20References/downloads/Switch_Engine_33_6_1_Command_References.pdf'}},
    {{label:'SW Engine User Guide',              url:'https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20User%20Guide/downloads/Switch_Engine_33_6_1_User_Guide.pdf'}},
  ]);
}}


// ═══════════════════════════════════════════════════════════════
function renderStreams(){{
  const list=document.getElementById('stream-list');
  if(!list)return;
  const filt=document.getElementById('stream-filter');
  const fv=filt?filt.value:'ALL';
  let data=STREAM_DATA||[];
  if(fv!=='ALL') data=data.filter(s=>s.type===fv);
  const cnt=document.getElementById('stream-count');
  if(cnt) cnt.textContent=data.length+' streams';
  if(!data.length){{ list.innerHTML='<div class="muted" style="padding:40px;text-align:center">No streams found'+(fv!=='ALL'?' for '+fv:'')+'</div>'; return; }}
  let html='';
  data.forEach((stream,si)=>{{
    const isTCP=(stream.type==='TCP');
    const col=isTCP?'#3b82f6':'#f59e0b';
    const flagBadges=stream.flags.map(f=>{{
      const fc={{'SYN':'#10b981','ACK':'#3b82f6','FIN':'#f59e0b','RST':'#ef4444','PSH':'#8b5cf6','URG':'#f97316'}};
      return '<span style=\"display:inline-block;padding:1px 5px;border-radius:3px;font:600 8px var(--mono);background:'+(fc[f]||'#475569')+'22;color:'+(fc[f]||'#94a3b8')+';border:1px solid '+(fc[f]||'#475569')+'44\">'+f+'</span>';
    }}).join(' ');
    // Detect handshake completeness for TCP
    let hsLabel='';
    if(isTCP){{
      const fl=stream.flags;
      const hasSyn=fl.includes('SYN'), hasAck=fl.includes('ACK'), hasFin=fl.includes('FIN'), hasRst=fl.includes('RST');
      if(hasSyn&&hasAck&&hasFin) hsLabel='<span style=\"color:#10b981;font:600 9px var(--sans)\">✓ Complete (SYN→SYN+ACK→ACK→FIN)</span>';
      else if(hasSyn&&hasAck&&hasRst) hsLabel='<span style=\"color:#ef4444;font:600 9px var(--sans)\">✗ Reset (SYN→SYN+ACK→RST)</span>';
      else if(hasSyn&&hasAck) hsLabel='<span style=\"color:#3b82f6;font:600 9px var(--sans)\">◐ Established (SYN→SYN+ACK→ACK)</span>';
      else if(hasSyn&&!hasAck) hsLabel='<span style=\"color:#f59e0b;font:600 9px var(--sans)\">⚠ Half-open (SYN only)</span>';
      else hsLabel='<span style=\"color:#64748b;font:600 9px var(--sans)\">— Data Only</span>';
    }}
    // Collapsible stream card
    html+='<div style=\"margin-bottom:8px;background:#0a1628;border:1px solid #1e3a5f;border-radius:8px;overflow:hidden\">';
    html+='<div onclick=\"this.nextElementSibling.style.display=this.nextElementSibling.style.display===\\'none\\'?\\'\\':\\'none\\'\" style=\"padding:8px 14px;cursor:pointer;display:flex;align-items:center;gap:8px;flex-wrap:wrap\">';
    html+='<span style=\"font:700 10px var(--mono);color:'+col+';padding:2px 8px;background:'+col+'15;border-radius:4px;border:1px solid '+col+'33\">'+stream.type+'</span>';
    html+='<span style=\"font:600 11px var(--mono);color:var(--text)\">'+stream.key+'</span>';
    html+='<span class=\"muted sm\">'+stream.count+' pkts</span>';
    if(flagBadges) html+='<span style=\"display:flex;gap:3px\">'+flagBadges+'</span>';
    if(hsLabel) html+='<span style=\"margin-left:auto\">'+hsLabel+'</span>';
    html+='</div>';
    // Steps (sequence diagram)
    html+='<div style=\"display:none;padding:4px 14px 10px;border-top:1px solid #1e3a5f22\">';
    html+='<div style=\"display:flex;flex-direction:column;gap:1px;font:11px var(--mono)\">';
    stream.steps.forEach((st,idx)=>{{
      if(isTCP){{
        const flagCol={{'SYN':'#10b981','SYN, ACK':'#3b82f6','ACK':'#64748b','FIN':'#f59e0b','FIN, ACK':'#f59e0b','RST':'#ef4444','RST, ACK':'#ef4444','PSH, ACK':'#8b5cf6'}};
        const fc=flagCol[st.flags]||'#475569';
        html+='<div style=\"display:flex;align-items:center;gap:8px;padding:3px 0;border-bottom:1px solid #1e3a5f15\">';
        html+='<span style=\"color:#334155;width:28px;text-align:right;font-size:9px;flex-shrink:0\">#'+st.id+'</span>';
        html+='<span style=\"color:#4a6080;width:60px;font-size:9px;flex-shrink:0\">'+st.t.toFixed(4)+'s</span>';
        html+='<span style=\"color:var(--text);width:140px;flex-shrink:0;font-size:10px\">'+st.src+'</span>';
        html+='<span style=\"color:'+fc+'\">→</span>';
        html+='<span style=\"color:var(--text);width:140px;flex-shrink:0;font-size:10px\">'+st.dst+'</span>';
        html+='<span style=\"font:700 9px var(--mono);padding:1px 6px;border-radius:3px;background:'+fc+'18;color:'+fc+';border:1px solid '+fc+'33\">'+(st.flags||'DATA')+'</span>';
        html+='<span class=\"muted\" style=\"font-size:9px\">'+st.bytes+'B</span>';
        html+='</div>';
      }} else {{
        // ARP pair
        const opCol=st.op==='REQUEST'?'#f59e0b':'#10b981';
        html+='<div style=\"display:flex;align-items:center;gap:8px;padding:3px 0;border-bottom:1px solid #1e3a5f15\">';
        html+='<span style=\"color:#334155;width:28px;text-align:right;font-size:9px;flex-shrink:0\">#'+st.id+'</span>';
        html+='<span style=\"color:#4a6080;width:60px;font-size:9px;flex-shrink:0\">'+st.t.toFixed(4)+'s</span>';
        html+='<span style=\"color:var(--text);width:120px;flex-shrink:0;font-size:10px\">'+st.src+'</span>';
        html+='<span style=\"color:'+opCol+'\">'+(st.op==='REQUEST'?'→ who has':'→ is at')+'</span>';
        html+='<span style=\"color:var(--text);width:120px;flex-shrink:0;font-size:10px\">'+st.dst+'</span>';
        html+='<span style=\"font:700 9px var(--mono);padding:1px 6px;border-radius:3px;background:'+opCol+'18;color:'+opCol+'\">'+st.op+'</span>';
        if(st.src_mac) html+='<span class=\"muted\" style=\"font-size:8px\">'+st.src_mac+'</span>';
        html+='</div>';
      }}
    }});
    html+='</div></div></div>';
  }});
  list.innerHTML=html;
}}

// ═══════════════════════════════════════════════════════════════
//  THEME TOGGLE
// ═══════════════════════════════════════════════════════════════
function toggleTheme(){{
  document.body.classList.toggle('light');
  const btn=document.getElementById('theme-btn');
  if(btn) btn.textContent=document.body.classList.contains('light')?'☀️':'🌙';
  try{{ localStorage.setItem('_theme',document.body.classList.contains('light')?'light':'dark'); }}catch(e){{}}
}}
// Restore saved theme
try{{ if(localStorage.getItem('_theme')==='light') toggleTheme(); }}catch(e){{}}

// ═══════════════════════════════════════════════════════════════
//  PACKET BOOKMARKS
// ═══════════════════════════════════════════════════════════════
const _bookmarks=new Set();
function toggleBookmark(id){{
  if(!id) id=curId;
  if(!id) return;
  if(_bookmarks.has(id)) _bookmarks.delete(id); else _bookmarks.add(id);
  // Update row visual
  const row=document.querySelector('#pt tr[data-id="'+id+'"]');
  if(row){{ if(_bookmarks.has(id)) row.classList.add('bookmarked'); else row.classList.remove('bookmarked'); }}
}}

// ═══════════════════════════════════════════════════════════════
//  COMMAND PALETTE (Ctrl+K / Cmd+K)
// ═══════════════════════════════════════════════════════════════
const _cmds=[
  {{label:'📊 Dashboard',               action:()=>goView('overview',document.getElementById('nb-overview')),    keys:'1'}},
  {{label:'📦 Packet Summary',           action:()=>goView('packets',document.getElementById('nb-packets')),      keys:'2'}},
  {{label:'⇄ Protocol Flow Summary',    action:()=>goView('flowproto',document.getElementById('nb-flowproto')),  keys:'3'}},
  {{label:'🔍 Anomaly Detection',        action:()=>goView('anomalies',document.getElementById('nb-anomalies')),  keys:'4'}},
  {{label:'⚡ Trap Analysis',            action:()=>goView('traps',document.getElementById('nb-traps')),          keys:'5'}},
  {{label:'⚡ Terminal',                 action:()=>goView('terminal',document.getElementById('nb-terminal')),    keys:'6'}},
  {{label:'★ Show Bookmarks',  action:()=>{{goView('packets',document.getElementById('nb-packets'));qFilter('bookmarked');}}, keys:''}},
  {{label:'🔍 Diagnose Anomalies', action:()=>diagnoseAnomalies(), keys:''}},
  {{label:'🌙 Toggle Theme',   action:()=>toggleTheme(), keys:'T'}},
  {{label:'📊 Ask AI: Stats',  action:()=>ask('Give a complete stats summary table of all protocols: count, bytes, requests vs replies'), keys:''}},
  {{label:'🛡️ Ask AI: Security', action:()=>ask('Any security threats? Port scans, floods, RST storms, gratuitous ARP?'), keys:''}},
  {{label:'📝 Full Report',    action:()=>ask('Give a complete network engineering report with recommendations'), keys:''}},
  {{label:'⬆ Upload PCAP',    action:()=>document.getElementById('pcap-file').click(), keys:''}},
  {{label:'⬇ Export JSON',    action:()=>{{ window.location='/export/json'; }}, keys:''}},
  {{label:'⬇ Export CSV',     action:()=>{{ window.location='/export/csv'; }}, keys:''}},
  {{label:'⌨ Keyboard Shortcuts', action:()=>showShortcuts(), keys:'?'}},
];
let _cmdIdx=0;
function openPalette(){{
  const pal=document.getElementById('cmd-palette');
  pal.classList.add('open');
  const inp=document.getElementById('cmd-input');
  inp.value='';inp.focus();
  filterCmds();
}}
function closePalette(){{
  document.getElementById('cmd-palette').classList.remove('open');
}}
function filterCmds(){{
  const q=document.getElementById('cmd-input').value.toLowerCase().trim();
  const res=document.getElementById('cmd-results');
  const matched=q?_cmds.filter(c=>c.label.toLowerCase().includes(q)):_cmds;
  res.innerHTML='';
  _cmdIdx=0;
  matched.forEach((c,i)=>{{
    const d=document.createElement('div');d.className='cmd-item'+(i===0?' sel':'');
    d.innerHTML=c.label+(c.keys?'<span class="cmd-key">'+c.keys+'</span>':'');
    d.onclick=()=>{{closePalette();c.action();}};
    d.dataset.idx=i;
    res.appendChild(d);
  }});
}}
function cmdKey(e){{
  const items=document.querySelectorAll('.cmd-item');
  if(e.key==='Escape'){{ closePalette(); e.preventDefault(); }}
  else if(e.key==='ArrowDown'){{ e.preventDefault();_cmdIdx=Math.min(_cmdIdx+1,items.length-1);items.forEach((it,i)=>it.classList.toggle('sel',i===_cmdIdx)); }}
  else if(e.key==='ArrowUp'){{ e.preventDefault();_cmdIdx=Math.max(_cmdIdx-1,0);items.forEach((it,i)=>it.classList.toggle('sel',i===_cmdIdx)); }}
  else if(e.key==='Enter'){{ e.preventDefault();const sel=items[_cmdIdx];if(sel)sel.click(); }}
}}

function showShortcuts(){{ document.getElementById('shortcut-modal').classList.add('open'); }}

// ═══════════════════════════════════════════════════════════════
//  GLOBAL KEYBOARD SHORTCUTS
// ═══════════════════════════════════════════════════════════════
document.addEventListener('keydown',(e)=>{{
  // Don't capture when typing in inputs
  const tag=document.activeElement.tagName;
  const inInput=(tag==='INPUT'||tag==='TEXTAREA'||tag==='SELECT');
  // Cmd/Ctrl+K → command palette
  if((e.metaKey||e.ctrlKey)&&e.key==='k'){{ e.preventDefault(); openPalette(); return; }}
  // Escape → close overlays
  if(e.key==='Escape'){{ closePalette(); document.getElementById('shortcut-modal').classList.remove('open'); return; }}
  if(inInput) return;
  // Number keys → navigate views
  const viewMap={{'1':'overview','2':'packets','3':'flowproto','4':'anomalies','5':'traps','6':'terminal'}};
  if(viewMap[e.key]){{ goView(viewMap[e.key],document.getElementById('nb-'+viewMap[e.key])); return; }}
  // Packet navigation (when in packets view)
  if(e.key==='j'||e.key==='ArrowDown'){{
    e.preventDefault();
    const rows=[...document.querySelectorAll('#ptb tr')];
    if(!rows.length)return;
    const idx=rows.findIndex(r=>r.classList.contains('sel'));
    const next=Math.min(idx+1,rows.length-1);
    const id=rows[next>=0?next:0].dataset.id;
    if(id) selPkt(parseInt(id));
  }}
  if(e.key==='k'||e.key==='ArrowUp'){{
    e.preventDefault();
    const rows=[...document.querySelectorAll('#ptb tr')];
    if(!rows.length)return;
    const idx=rows.findIndex(r=>r.classList.contains('sel'));
    const prev=Math.max(idx-1,0);
    const id=rows[prev].dataset.id;
    if(id) selPkt(parseInt(id));
  }}
  // B → bookmark
  if(e.key==='b'){{ toggleBookmark(); }}
  // / → focus filter
  if(e.key==='/'){{ e.preventDefault(); goView('packets',document.getElementById('nb-packets')); setTimeout(()=>document.getElementById('pf').focus(),50); }}
  // T → toggle theme
  if(e.key==='t'){{ toggleTheme(); }}
  // ? → show shortcuts
  if(e.key==='?'){{ showShortcuts(); }}
}});

// ═══════════════════════════════════════════════════════════════
//  INIT
// ═══════════════════════════════════════════════════════════════
window.addEventListener('load',()=>{{
  renderTable();
  goView('overview',document.getElementById('nb-overview'));
  // Build charts on first load
  requestAnimationFrame(()=>requestAnimationFrame(()=>{{
    buildDonut();
    buildTimeline('ALL');
  }}));

  // Check if we just uploaded a PCAP and should auto-ask AI
  const pendingAI = sessionStorage.getItem('_pcapUploadAI');
  if (pendingAI) {{
    sessionStorage.removeItem('_pcapUploadAI');
    try {{
      const info = JSON.parse(pendingAI);
      // Show the uploaded tab as active
      const ptUp = document.getElementById('pt-uploaded');
      if (ptUp) {{ ptUp.style.display = ''; ptUp.textContent = '📂 ' + info.file; ptUp.classList.add('active'); }}
      const ptOrig = document.getElementById('pt-original');
      if (ptOrig) ptOrig.classList.remove('active');
      // Navigate to AI view and auto-send analysis prompt
      setTimeout(()=>{{
        const nb = document.querySelector('[id="nb-overview"]');
        goView('overview', nb);
        // Build AI prompt about the uploaded PCAP
        const prompt = 'I just uploaded a new PCAP file: ' + info.file + '.\\n'
          + 'Summary: ' + info.summary + '\\n'
          + 'Anomalies: ' + info.anomalies + '\\n\\n'
          + 'Please give me a complete analysis: '
          + '1) What protocols are present and their purpose '
          + '2) Any security concerns or anomalies '
          + '3) Key observations about the traffic patterns '
          + '4) Recommended Switch Engine CLI commands for further investigation — ONLY from the official docs: '
          + 'Switch Engine v33.6.1 Command References (https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20Command%20References/downloads/Switch_Engine_33_6_1_Command_References.pdf) '
          + 'and User Guide (https://documentation.extremenetworks.com/Switch%20Engine%20v33.6.1%20User%20Guide/downloads/Switch_Engine_33_6_1_User_Guide.pdf). '
          + 'Do NOT use commands from other Extreme products (Fabric Engine, VOSS, EOS, SLX, etc.)';
        ask(prompt);
      }}, 500);
    }} catch(e) {{ /* ignore parse errors */ }}
  }}

  // Check if we just uploaded a Trap CSV — auto-navigate to Traps tab
  if (sessionStorage.getItem('_trapCsvLoaded')) {{
    sessionStorage.removeItem('_trapCsvLoaded');
    setTimeout(()=>{{
      const nb = document.getElementById('nb-traps');
      if (nb) goView('traps', nb);
      // Also make uploaded tab visible
      const ptUp = document.getElementById('pt-uploaded');
      if (ptUp) {{ ptUp.style.display = ''; ptUp.classList.add('active'); }}
      const ptOrig = document.getElementById('pt-original');
      if (ptOrig) ptOrig.classList.remove('active');
    }}, 300);
  }}
}});
// ═══════════════════════════════════════════════════════════════
//  TERMINAL (WebSocket → bash PTY)
// ═══════════════════════════════════════════════════════════════
let termWS = null;
let termHistory = [];
let termHistIdx = -1;

function termConnect() {{
  if (termWS && termWS.readyState === WebSocket.OPEN) return;
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  termWS = new WebSocket(`${{proto}}://${{location.host}}/ws/terminal`);
  termWS.binaryType = 'arraybuffer';

  termWS.onopen = () => {{
    termAppend('[Terminal connected — bash shell]\\n', 'sys');
    const inp = document.getElementById('term-inp');
    if (inp) inp.focus();
  }};

  termWS.onmessage = (e) => {{
    let raw;
    if (e.data instanceof ArrayBuffer) {{
      raw = new TextDecoder().decode(e.data);
    }} else {{
      raw = e.data;
    }}
    termAppend(raw);
  }};

  termWS.onclose = () => {{
    termAppend('\\n[Connection closed — click Terminal tab or type a command to reconnect]\\n', 'sys');
    termWS = null;
  }};

  termWS.onerror = (err) => {{
    termAppend('\\n[WebSocket error — is the server running?]\\n', 'sys');
  }};
}}

// Simple ANSI escape stripper for display (keeps text readable)
function ansiStrip(s) {{
  // Remove ANSI CSI sequences (colours, cursor moves, erase, etc.)
  s = s.replace(/\\x1b\\[[0-9;?]*[a-zA-Z]/g, '');
  // Remove OSC sequences (e.g. terminal title set)
  s = s.replace(/\\x1b\\][^\\x07\\x1b]*(\\x07|\\x1b\\\\)/g, '');
  // Remove other two-char ESC sequences
  s = s.replace(/\\x1b[^[\\]]/g, '');
  // Normalise CR+LF and bare CR (overwrite) → newline
  s = s.replace(/\\r\\n/g, '\\n').replace(/\\r/g, '\\n');
  return s;
}}

function termAppend(raw, cls) {{
  const out = document.getElementById('term-out');
  if (!out) return;
  const clean = ansiStrip(raw);
  // Always append — even if clean is empty a PTY ping could just be control codes;
  // but only create a DOM node when there's actual printable content.
  if (!clean) return;
  const span = document.createElement('span');
  if (cls === 'sys') span.style.color = 'var(--muted)';
  span.textContent = clean;
  out.appendChild(span);
  out.scrollTop = out.scrollHeight;
}}

function termKey(e) {{
  if (e.key === 'Enter') {{
    const inp = document.getElementById('term-inp');
    const cmd = inp.value;
    inp.value = '';
    // Save history
    if (cmd.trim()) {{
      termHistory.unshift(cmd);
      if (termHistory.length > 100) termHistory.pop();
    }}
    termHistIdx = -1;
    // Only echo and send if there's actual input
    if (cmd.trim()) termAppend('$ ' + cmd + '\\n', 'sys');
    // Send to PTY
    if (termWS && termWS.readyState === WebSocket.OPEN) {{
      termWS.send(cmd + '\\n');
    }} else {{
      termAppend('[Not connected — reconnecting\u2026]\\n', 'sys');
      termConnect();
    }}
  }} else if (e.key === 'ArrowUp') {{
    e.preventDefault();
    if (termHistIdx < termHistory.length - 1) {{
      termHistIdx++;
      document.getElementById('term-inp').value = termHistory[termHistIdx];
    }}
  }} else if (e.key === 'ArrowDown') {{
    e.preventDefault();
    if (termHistIdx > 0) {{
      termHistIdx--;
      document.getElementById('term-inp').value = termHistory[termHistIdx];
    }} else {{
      termHistIdx = -1;
      document.getElementById('term-inp').value = '';
    }}
  }} else if (e.key === 'c' && e.ctrlKey) {{
    if (termWS && termWS.readyState === WebSocket.OPEN) {{
      termWS.send('\x03');  // Ctrl+C
    }}
    document.getElementById('term-inp').value = '';
  }} else if (e.key === 'd' && e.ctrlKey) {{
    e.preventDefault();
    if (termWS && termWS.readyState === WebSocket.OPEN) {{
      termWS.send('\x04');  // Ctrl+D — EOF/logout
      termAppend('^D\\n', 'sys');
    }}
  }} else if (e.key === 'x' && e.ctrlKey) {{
    e.preventDefault();
    if (termWS && termWS.readyState === WebSocket.OPEN) {{
      termWS.send('\x18');  // Ctrl+X — exit many device CLIs
      termAppend('^X\\n', 'sys');
    }}
  }} else if ((e.key === ']' || e.key === '[') && e.ctrlKey) {{
    // Ctrl+] = Telnet escape. Mac blocks Ctrl+] so Ctrl+[ also sends \x1d.
    e.preventDefault();
    if (termWS && termWS.readyState === WebSocket.OPEN) {{
      termWS.send('\x1d');
      termAppend('^] Telnet escape sent\\n', 'sys');
    }}
  }} else if (e.key === 'l' && e.ctrlKey) {{
    e.preventDefault();
    termClear();
  }}
}}

function termClear() {{
  const out = document.getElementById('term-out');
  if (out) out.innerHTML = '';
}}

function termKill() {{
  if (termWS) {{ termWS.close(); termWS = null; }}
  termAppend('[Session killed. Click Terminal tab to reconnect.]\\n', 'sys');
}}

// Send raw escape bytes — Ctrl+X, Ctrl+], Ctrl+D, etc.
function termSendRaw(seq) {{
  if (termWS && termWS.readyState === WebSocket.OPEN) {{
    termWS.send(seq);
    const names = {{'\x03':'^C','\x04':'^D','\x18':'^X','\x1d':'^]'}};
    termAppend((names[seq] || '(ctrl)') + '\\n', 'sys');
  }} else {{
    termAppend('[Not connected]\\n', 'sys');
  }}
}}

// Send a full command line (e.g. "exit")
function termSendLine(cmd) {{
  if (termWS && termWS.readyState === WebSocket.OPEN) {{
    termAppend('$ ' + cmd + '\\n', 'sys');
    termWS.send(cmd + '\\n');
  }} else {{
    termAppend('[Not connected \u2014 reconnecting\u2026]\\n', 'sys');
    termConnect();
  }}
}}

// Quick Connect — build connect / tconnect command from the bar inputs
function quickConnect() {{
  const proto = document.getElementById('term-proto').value;
  const host  = document.getElementById('term-host').value.trim();
  const user  = document.getElementById('term-user').value.trim();
  const pass  = document.getElementById('term-pass').value;
  if (!host) {{ termAppend('[Enter an IP address first]\\n', 'sys'); return; }}
  let cmd;
  if (proto === 'telnet') {{
    cmd = 'tconnect ' + host;
    if (user) cmd += ' ' + user;
    if (pass) cmd += ' ' + pass;
  }} else {{
    cmd = 'connect ' + host;
    if (user) cmd += ' ' + user;
    if (pass) cmd += ' ' + pass;
  }}
  // Ensure WebSocket is open
  if (!termWS || termWS.readyState !== WebSocket.OPEN) {{
    termAppend('[Not connected — reconnecting\u2026]\\n', 'sys');
    termConnect();
    // Queue command after connection opens
    const _orig = termWS.onopen;
    termWS.onopen = (ev) => {{ if (_orig) _orig(ev); termWS.send(cmd + '\\n'); }};
    return;
  }}
  termAppend('$ ' + cmd + '\\n', 'sys');
  termWS.send(cmd + '\\n');
}}

// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
//  PCAP UPLOAD + SOURCE SWITCHING
// \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550
let _uploadedFile = null;  // track uploaded filename for tab label

function uploadPcap(file) {{
  if (!file) return;
  const overlay = document.getElementById('drop-overlay');
  overlay.classList.remove('active');
  const btn = document.querySelector('.upload-btn');
  const origText = btn.textContent;
  btn.textContent = '\u23f3 Uploading...';
  btn.disabled = true;
  const fd = new FormData();
  fd.append('pcap', file, file.name);
  fetch('/upload', {{method:'POST', body:fd}})
    .then(r => r.json())
    .then(data => {{
      btn.disabled = false;
      if (data.ok) {{
        btn.textContent = '\u2705 ' + data.file;
        _uploadedFile = data.file;
        // Show the uploaded tab and activate it
        const ptUp = document.getElementById('pt-uploaded');
        ptUp.style.display = '';
        ptUp.textContent = '📂 ' + data.file;
        // Auto-switch to uploaded view (reload page to render new data)
        // But first send AI prompt, then reload
        _autoAiOnUpload(data);
      }} else {{
        btn.textContent = origText;
        alert('Upload failed: ' + (data.error || 'Unknown error'));
      }}
    }})
    .catch(err => {{
      btn.textContent = origText;
      btn.disabled = false;
      alert('Upload error: ' + err);
    }});
}}

function _autoAiOnUpload(data) {{
  // Switch to the AI view and send an auto-analysis prompt
  const aiBtn = document.getElementById('nb-overview');
  // Navigate to dashboard first, then after reload go to AI chat
  // Store intent in sessionStorage so after reload we auto-ask
  sessionStorage.setItem('_pcapUploadAI', JSON.stringify({{
    file: data.file,
    packets: data.packets,
    summary: data.summary || '',
    anomalies: data.anomalies || 'none',
    slot: 'uploaded'
  }}));
  // Reload to render the new uploaded PCAP data
  setTimeout(() => location.reload(), 300);
}}

function uploadTrapCsvHeader(file) {{
  if (!file) return;
  const fd = new FormData();
  fd.append('csv', file, file.name);
  fetch('/upload-trap-csv', {{method: 'POST', body: fd}})
    .then(r => r.json())
    .then(data => {{
      if (data.ok) {{
        sessionStorage.setItem('_trapCsvLoaded', '1');
        setTimeout(() => location.reload(), 300);
      }} else {{
        alert('CSV upload failed: ' + (data.error || 'Unknown error'));
      }}
    }})
    .catch(err => alert('CSV upload error: ' + err));
}}

function switchPcap(slot, btn) {{
  // Switch between original and uploaded PCAP
  document.querySelectorAll('.pcap-tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  fetch('/api/switch-pcap', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{slot: slot}})
  }})
    .then(r => r.json())
    .then(data => {{
      if (data.ok) {{
        location.reload();
      }} else {{
        alert('Switch failed: ' + (data.error || 'Unknown'));
      }}
    }})
    .catch(err => alert('Switch error: ' + err));
}}

// Drag-and-drop handlers
(function() {{
  let dragCounter = 0;
  const overlay = document.getElementById('drop-overlay');
  document.addEventListener('dragenter', function(e) {{
    e.preventDefault();
    dragCounter++;
    if (e.dataTransfer && e.dataTransfer.types.indexOf('Files') >= 0) {{
      overlay.classList.add('active');
    }}
  }});
  document.addEventListener('dragleave', function(e) {{
    e.preventDefault();
    dragCounter--;
    if (dragCounter <= 0) {{
      dragCounter = 0;
      overlay.classList.remove('active');
    }}
  }});
  document.addEventListener('dragover', function(e) {{
    e.preventDefault();
  }});
  document.addEventListener('drop', function(e) {{
    e.preventDefault();
    dragCounter = 0;
    overlay.classList.remove('active');
    const files = e.dataTransfer && e.dataTransfer.files;
    if (files && files.length > 0) {{
      const f = files[0];
      if (f.name.endsWith('.pcap') || f.name.endsWith('.pcapng')) {{
        uploadPcap(f);
      }} else {{
        alert('Please drop a .pcap file');
      }}
    }}
  }});
}})();

</script>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
#  HTTP SERVER
# ═══════════════════════════════════════════════════════════════════════════════

ANALYSIS_DATA = {}
PCAP_SLOTS = {}       # {'original': {...}, 'uploaded': {...}} — stores both analyses
ACTIVE_SLOT = 'original'
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_pcaps')

def _reanalyse(pcap_path, slot='uploaded'):
    """Re-run the full parse→analyse pipeline, store in the named slot, and activate it."""
    global ANALYSIS_DATA, ACTIVE_SLOT
    raw = read_pcap(pcap_path)
    packets = parse_all(raw)
    tshark_data = _run_tshark(pcap_path)
    _merge_tshark(packets, tshark_data)
    analysis = analyse(packets)
    PCAP_SLOTS[slot] = {'analysis': analysis, 'fname': pcap_path}
    # Activate this slot
    ANALYSIS_DATA['analysis'] = analysis
    ANALYSIS_DATA['fname'] = pcap_path
    ACTIVE_SLOT = slot
    print(f'  [{slot}] Re-analysed {os.path.basename(pcap_path)}: {len(packets)} packets')
    return analysis

# ── Terminal session manager ──────────────────────────────────────────────────

# ── WebSocket handshake helpers ───────────────────────────────────────────────

_b64 = base64   # alias for WebSocket helper below (hashlib/base64 already imported at top)

def _ws_handshake(handler):
    key = handler.headers.get('Sec-WebSocket-Key', '')
    accept = _b64.b64encode(
        hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()
    ).decode()
    handler.send_response(101, 'Switching Protocols')
    handler.send_header('Upgrade', 'websocket')
    handler.send_header('Connection', 'Upgrade')
    handler.send_header('Sec-WebSocket-Accept', accept)
    handler.end_headers()
    handler.wfile.flush()  # Must flush so browser receives the 101 before we switch to raw I/O

def _ws_send(sock, data: bytes):
    """Send a WebSocket text frame."""
    length = len(data)
    if length < 126:
        header = bytes([0x81, length])
    elif length < 65536:
        header = bytes([0x81, 126]) + length.to_bytes(2, 'big')
    else:
        header = bytes([0x81, 127]) + length.to_bytes(8, 'big')
    try:
        sock.sendall(header + data)
    except OSError:
        pass

def _ws_recv(sock):  # returns bytes or None
    """Read one WebSocket frame payload (text or binary). Returns None on close."""
    try:
        header = _recv_exact(sock, 2)
        if not header: return None
        fin_op = header[0]; masked_len = header[1]
        opcode = fin_op & 0x0F
        if opcode == 0x8: return None  # close
        length = masked_len & 0x7F
        if length == 126:
            length = int.from_bytes(_recv_exact(sock, 2), 'big')
        elif length == 127:
            length = int.from_bytes(_recv_exact(sock, 8), 'big')
        masked = bool(masked_len & 0x80)
        mask = _recv_exact(sock, 4) if masked else b'\x00\x00\x00\x00'
        payload = bytearray(_recv_exact(sock, length))
        if masked:
            for i in range(length):
                payload[i] ^= mask[i % 4]
        return bytes(payload)
    except OSError:
        return None

def _recv_exact(sock, n) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk: raise OSError('connection closed')
        buf += chunk
    return buf


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        path = urlparse(self.path).path

        # WebSocket upgrade for terminal
        if path == '/ws/terminal':
            if self.headers.get('Upgrade', '').lower() == 'websocket':
                self._handle_terminal_ws()  # blocks this thread for WS lifetime; ThreadingHTTPServer handles concurrency
            else:
                self.send_response(400); self.end_headers()
            self.close_connection = True
            return

        # Home button: /reset clears loaded analysis and returns to welcome page
        if path == '/reset':
            ANALYSIS_DATA.clear()
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()
            return

        if path in ('/', '/index.html'):
            # If no PCAP loaded yet, show the welcome/setup page
            if not ANALYSIS_DATA.get('analysis'):
                html = _make_welcome_html().encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(html)
                return
            try:
                html = _encode_html(make_html(
                    ANALYSIS_DATA['analysis'],
                    ANALYSIS_DATA['fname'],
                    ANALYSIS_DATA.get('switch_ip'),
                ))
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(html)
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                err = f'<pre>Error: {e}\n\n{tb}</pre>'.encode()
                self.send_response(500)
                self.send_header('Content-Type', 'text/html')
                self.end_headers()
                self.wfile.write(err)

        elif path == '/api/capture-status':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(_CAPTURE_STATE).encode())

        # ── Export endpoints ──────────────────────────────────────────────────
        elif path == '/export/json':
            self._export_json()
        elif path == '/export/csv':
            self._export_csv()
        elif path == '/export/pcap':
            self._export_pcap()
        else:
            self.send_response(404); self.end_headers()

    def do_POST(self):
        p = urlparse(self.path).path
        if p == '/api/chat':
            n = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(n))
            prompt_text = body.get('prompt', '')
            chat_mode   = body.get('mode', '')      # 'mcp' when MCP tab is active
            switch_ip   = body.get('switch_ip', '')  # optional switch IP from MCP tab

            # ── MCP tab: always route to MCP server (no keyword check needed) ──
            if chat_mode == 'mcp' and MCP_ENABLED:
                print(f'  [chat] mode=mcp → routing directly to MCP server')
                # Inject switch IP into prompt if not already present
                if switch_ip and switch_ip not in prompt_text:
                    prompt_text = f'{prompt_text} on {switch_ip}'
                resp = _ask_mcp(prompt_text)
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'response': resp, 'via_mcp': True}).encode())
                return

            # ── RFC tab: RAG-backed protocol/RFC lookup, MCP explicitly bypassed ──
            if chat_mode == 'rfc':
                print(f'  [chat] mode=rfc -> RAG path (MCP bypassed)')
                try:
                    rfc_q = prompt_text
                    if '\n\nQuestion: ' in rfc_q:
                        rfc_q = rfc_q.split('\n\nQuestion: ', 1)[1]
                    if AI_BACKEND == 'claude' and CLAUDE_API_KEY:
                        resp_rfc = _ask_claude(rfc_q)
                    elif AI_BACKEND == 'openai' and OPENAI_API_KEY:
                        resp_rfc = _ask_openai(rfc_q)
                    else:
                        resp_rfc = _ask_ollama(rfc_q)
                except Exception as e:
                    print(f'  [chat] mode=rfc ERROR: {e}')
                    resp_rfc = f'Error processing RFC request: {e}'
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'response': resp_rfc, 'via_mcp': False}).encode())
                return

            # ── EXOS tab: RAG-backed Switch Engine docs, MCP explicitly bypassed ──
            if chat_mode == 'exos':
                print(f'  [chat] mode=exos → RAG path (MCP bypassed)')
                try:
                    detected_protos_exos = None
                    if ANALYSIS_DATA and 'analysis' in ANALYSIS_DATA:
                        proto_counts_exos = ANALYSIS_DATA['analysis'].get('proto_counts', {})
                        detected_protos_exos = [k for k, v in sorted(
                            proto_counts_exos.items(), key=lambda x: x[1], reverse=True)]
                    # Extract just the question (strip Context/Question wrapper if present)
                    exos_q = prompt_text
                    if '\n\nQuestion: ' in exos_q:
                        exos_q = exos_q.split('\n\nQuestion: ', 1)[1]
                    # Direct LLM call — no MCP keyword check, optional RAG enrichment
                    if AI_BACKEND == 'claude' and CLAUDE_API_KEY:
                        resp_exos = _ask_claude(exos_q)
                    elif AI_BACKEND == 'openai' and OPENAI_API_KEY:
                        resp_exos = _ask_openai(exos_q)
                    else:
                        resp_exos = _ask_ollama(exos_q)
                except Exception as e:
                    print(f'  [chat] mode=exos ERROR: {e}')
                    resp_exos = f'Error processing EXOS request: {e}'
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'response': resp_exos, 'via_mcp': False}).encode())
                return

            # ── Chat tab: multi-turn chatbot with short-memory history ──
            global _CHAT_HISTORY
            client_history = body.get('history', None)

            # Build the user message: strip Context wrapper, keep just the question
            chat_q = prompt_text
            if '\n\nQuestion: ' in chat_q:
                chat_q = chat_q.split('\n\nQuestion: ', 1)[1]

            # If client sends history use it; otherwise fall back to server-side
            history_to_use = client_history if client_history is not None else _CHAT_HISTORY

            # Prefix capture context on first message (no prior history)
            if not history_to_use and ANALYSIS_DATA and 'analysis' in ANALYSIS_DATA:
                proto_counts = ANALYSIS_DATA['analysis'].get('proto_counts', {})
                top_protos = [k for k, v in sorted(
                    proto_counts.items(), key=lambda x: x[1], reverse=True)][:6]
                ctx_note = (f"[Capture context: {ANALYSIS_DATA['analysis'].get('total',0)} packets, "
                            f"top protocols: {', '.join(top_protos)}]")
                chat_q = ctx_note + '\n\n' + chat_q

            resp, updated_history = _ask_chat_with_history(chat_q, history_to_use)
            _CHAT_HISTORY = updated_history  # update server-side copy too

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'response': resp,
                'history': updated_history,
                'via_mcp': False,
            }).encode())
        elif p == '/upload':
            self._handle_upload()
        elif p == '/upload-trap-csv':
            self._handle_upload_trap_csv()
        elif p == '/api/switch-pcap':
            self._handle_switch_pcap()
        elif p == '/api/config':
            self._handle_config()
        elif p == '/api/capture':
            self._handle_capture_start()
        elif p == '/api/capture-cancel':
            self._handle_capture_cancel()
        else:
            self.send_response(404); self.end_headers()

    def _handle_capture_start(self):
        """Start a background switch capture."""
        if _CAPTURE_STATE['running']:
            self.send_response(409)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Capture already in progress'}).encode())
            return
        n = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(n))
        switch_ip = body.get('switch_ip', '').strip()
        if not switch_ip:
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'switch_ip is required'}).encode())
            return
        user         = body.get('user', 'admin')
        password     = body.get('password', '')
        sw_port      = body.get('sw_port', '1')
        sw_interface = body.get('sw_interface', '').strip()  # interface-based capture
        vlan         = body.get('vlan', 'default')
        vlan_only    = bool(body.get('vlan_only', False))    # explicit VLAN-mode capture
        duration     = int(body.get('duration', 10))
        protocol     = body.get('protocol', 'ssh')  # ssh | telnet | auto
        if protocol not in ('ssh', 'telnet', 'auto'):
            protocol = 'ssh'
        # Launch in background thread
        t = threading.Thread(target=_bg_capture,
                             args=(switch_ip, user, password, sw_port, vlan, duration, protocol),
                             kwargs={'sw_interface': sw_interface, 'vlan_only': vlan_only},
                             daemon=True)
        t.start()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'ok': True, 'message': 'Capture started'}).encode())

    def _handle_capture_cancel(self):
        """Signal the running capture to abort and forcefully send cap_off to the switch."""
        _CAPTURE_STATE['cancel'] = True
        _CAPTURE_STATE['phase'] = 'Cancelling capture...'

        # Forcefully send cap_off in a background thread so this request returns fast
        cap_off   = _CAPTURE_STATE.get('_cap_off', '')
        sw_ip     = _CAPTURE_STATE.get('_sw_ip', '')
        sw_user   = _CAPTURE_STATE.get('_sw_user', '')
        sw_pass   = _CAPTURE_STATE.get('_sw_pass', '')
        use_tel   = _CAPTURE_STATE.get('_use_telnet', False)

        def _force_stop():
            if not cap_off or not sw_ip:
                return
            try:
                if use_tel:
                    print(f'  [cancel] Telnet force-stop: {cap_off}')
                    tel = _Telnet(sw_ip, sw_user, sw_pass)
                    tel.run(cap_off)
                    tel.close()
                    print('  [cancel] ✓ cap_off sent via Telnet')
                else:
                    print(f'  [cancel] SSH force-stop: {cap_off}')
                    c = _ssh_connect_exos(sw_ip, sw_user, sw_pass)
                    _ssh_exec_exos(c, cap_off, timeout=15)
                    c.close()
                    print('  [cancel] ✓ cap_off sent via SSH')
            except Exception as e:
                print(f'  [cancel] force-stop error: {e}')

        if cap_off and sw_ip:
            threading.Thread(target=_force_stop, daemon=True).start()

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'ok': True, 'message': 'Cancel signal sent'}).encode())

    def _handle_config(self):
        """Update AI backend/model/key at runtime."""
        global AI_BACKEND, OLLAMA_MODEL, CLAUDE_API_KEY, CLAUDE_MODEL, OPENAI_API_KEY
        n = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(n))
        backend = body.get('backend', AI_BACKEND)
        model   = body.get('model', '')
        key     = body.get('key', '')
        if backend in ('ollama','claude','openai'):
            AI_BACKEND = backend
        if backend == 'ollama' and model:
            OLLAMA_MODEL = model
        elif backend == 'claude':
            CLAUDE_MODEL = model or CLAUDE_MODEL
            if key: CLAUDE_API_KEY = key
        elif backend == 'openai':
            if key: OPENAI_API_KEY = key
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'ok': True, 'backend': AI_BACKEND, 'model': model or OLLAMA_MODEL}).encode())

    # ── PCAP Upload handler ───────────────────────────────────────────────

    def _handle_upload(self):
        """Accept a multipart/form-data POST with a PCAP file, re-analyse, redirect."""
        content_type = self.headers.get('Content-Type', '')
        if 'multipart/form-data' not in content_type:
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Expected multipart/form-data'}).encode())
            return

        # Parse boundary from Content-Type header
        boundary = None
        for part in content_type.split(';'):
            part = part.strip()
            if part.startswith('boundary='):
                boundary = part[len('boundary='):].strip('"')
        if not boundary:
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'No boundary in Content-Type'}).encode())
            return

        # Read the full body
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 200 * 1024 * 1024:  # 200 MB limit
            self.send_response(413)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'File too large (>200MB)'}).encode())
            return

        body = self.rfile.read(content_length)
        boundary_bytes = boundary.encode('utf-8')

        # Extract filename and file data from multipart body
        parts = body.split(b'--' + boundary_bytes)
        file_data = None
        filename = 'upload.pcap'
        for part in parts:
            if b'Content-Disposition' not in part:
                continue
            # Parse Content-Disposition header for filename
            header_end = part.find(b'\r\n\r\n')
            if header_end < 0:
                continue
            headers_section = part[:header_end].decode('utf-8', errors='replace')
            payload = part[header_end + 4:]
            # Strip trailing \r\n
            if payload.endswith(b'\r\n'):
                payload = payload[:-2]

            if 'name="pcap"' in headers_section or 'name="file"' in headers_section:
                # Extract filename
                fn_match = re.search(r'filename="([^"]+)"', headers_section)
                if fn_match:
                    filename = os.path.basename(fn_match.group(1))  # sanitize path
                file_data = payload

        if not file_data or len(file_data) < 24:
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'No valid PCAP file in upload'}).encode())
            return

        # Validate PCAP magic bytes
        magic = file_data[:4]
        if magic not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'):
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': f'Invalid PCAP file (magic: {magic.hex()}). Only .pcap format supported.'}).encode())
            return

        # Save to test_pcaps/
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        safe_name = re.sub(r'[^\w.\-]', '_', filename)
        save_path = os.path.join(UPLOAD_DIR, safe_name)
        with open(save_path, 'wb') as f:
            f.write(file_data)

        # Re-analyse
        try:
            analysis = _reanalyse(save_path, slot='uploaded')
            # Build a brief summary for auto AI prompt
            pc = analysis.get('proto_counts', {})
            top_protos = ', '.join(f'{p}({c})' for p,c in sorted(pc.items(), key=lambda x:x[1], reverse=True)[:5])
            anom_list = analysis.get('anomalies', [])
            anom_str = '; '.join(anom_list[:3]) if anom_list else 'none'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'ok': True, 'file': safe_name, 'slot': 'uploaded',
                'packets': analysis['total'],
                'summary': f'{analysis["total"]} packets — {top_protos}',
                'anomalies': anom_str,
                'hasOriginal': 'original' in PCAP_SLOTS,
            }).encode())
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': f'Analysis failed: {e}'}).encode())

    # ── PCAP slot switcher ────────────────────────────────────────────────────

    def _handle_upload_trap_csv(self):
        """Accept a CSV trap file upload, parse it, and synthesise an analysis slot."""
        global ANALYSIS_DATA, ACTIVE_SLOT
        content_type = self.headers.get('Content-Type', '')
        if 'multipart/form-data' not in content_type:
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Expected multipart/form-data'}).encode())
            return

        boundary = ''
        for part in content_type.split(';'):
            part = part.strip()
            if part.startswith('boundary='):
                boundary = part[9:].strip('"')
                break

        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 50 * 1024 * 1024:   # 50 MB max for CSV
            self.send_response(413)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'File too large (>50MB)'}).encode())
            return

        body = self.rfile.read(content_length)
        boundary_bytes = boundary.encode('utf-8')

        file_data = None
        filename   = 'traps.csv'
        for part in body.split(b'--' + boundary_bytes):
            if b'Content-Disposition' not in part:
                continue
            header_end = part.find(b'\r\n\r\n')
            if header_end < 0:
                continue
            headers_section = part[:header_end].decode('utf-8', errors='replace')
            payload = part[header_end + 4:]
            if payload.endswith(b'\r\n'):
                payload = payload[:-2]
            if 'name="csv"' in headers_section or 'name="file"' in headers_section:
                fn_match = re.search(r'filename="([^"]+)"', headers_section)
                if fn_match:
                    filename = os.path.basename(fn_match.group(1))
                file_data = payload

        if not file_data:
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'No CSV file found in upload'}).encode())
            return

        # Save CSV/JSON to upload dir
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        safe_name = re.sub(r'[^\w.\-]', '_', filename)
        if not any(safe_name.lower().endswith(e) for e in ('.csv', '.json', '.txt')):
            safe_name += '.csv'
        save_path = os.path.join(UPLOAD_DIR, safe_name)
        with open(save_path, 'wb') as fh:
            fh.write(file_data)

        # Parse CSV and run trap analysis
        try:
            from snmp_trap_analyzer import (parse_trap_csv as _parse_csv,
                                             analyse_traps as _analyse_traps)
            trap_session = _parse_csv(save_path)
            trap_result  = _analyse_traps(trap_session)

            # Synthesise a complete analysis dict matching analyse() output shape.
            # Traps tab will be fully populated; other tabs stay empty/placeholder.
            trap_count = len(trap_session.traps)
            synthetic = {
                'total':          trap_count,
                'proto_counts':   {'SNMP Trap (CSV)': trap_count},
                'arp':[], 'icmp':[], 'tcp':[], 'udp':[], 'other':[],
                'proto_buckets':  {},
                'src_ips':        dict(list(trap_session.agents.items())[:10]),
                'dst_ips':        {},
                'services':       {},
                'anomalies':      [],
                'all_packets':    [],
                'arp_reqs_total': 0, 'arp_reps_total': 0,
                'arp_pairs':      {}, 'arp_completed': {},
                'arp_unanswered': {}, 'arp_gratuitous': [],
                'tcp_syn': 0, 'tcp_synack': 0, 'tcp_ack': 0,
                'tcp_psh': 0, 'tcp_fin': 0, 'tcp_rst': 0,
                'icmp_req': 0, 'icmp_rep': 0, 'icmp_unr': 0, 'icmp_ttl': 0,
                'total_bytes':    0, 'proto_bytes': {},
                'trap_analysis':  trap_result,
                'csv_only':       True,
            }
            PCAP_SLOTS['uploaded'] = {'analysis': synthetic, 'fname': save_path}
            ANALYSIS_DATA['analysis'] = synthetic
            ANALYSIS_DATA['fname'] = save_path
            ACTIVE_SLOT = 'uploaded'

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                'ok':      True,
                'file':    safe_name,
                'traps':   len(trap_session.traps),
                'agents':  len(trap_session.agents),
                'csv_only': True,
            }).encode())
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': f'CSV analysis failed: {e}'}).encode())

    def _handle_switch_pcap(self):
        """Switch between 'original' and 'uploaded' PCAP analysis slots."""
        global ANALYSIS_DATA, ACTIVE_SLOT
        n = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(n)) if n else {}
        slot = body.get('slot', 'original')
        if slot not in PCAP_SLOTS:
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'error': f'No PCAP loaded in slot: {slot}'}).encode())
            return
        data = PCAP_SLOTS[slot]
        ANALYSIS_DATA['analysis'] = data['analysis']
        ANALYSIS_DATA['fname'] = data['fname']
        ACTIVE_SLOT = slot
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'ok': True, 'slot': slot,
            'file': os.path.basename(data['fname']),
            'packets': data['analysis']['total']}).encode())

    # ── Terminal WebSocket handler ────────────────────────────────────────────

    def _handle_terminal_ws(self):
        """Each WebSocket connection gets its own bash PTY."""
        # Terminal feature requires Unix/Linux (pty module)
        if IS_WINDOWS:
            _ws_handshake(self)
            sock = self.connection
            msg = '[Terminal feature not available on Windows - requires Unix/Linux PTY]\r\n'
            _ws_send(sock, msg.encode())
            return
        
        _ws_handshake(self)
        sock = self.connection
        sock.settimeout(None)  # blocking — _ws_recv depends on this

        # Spawn a fresh bash PTY for this connection
        try:
            pid, fd = pty.fork()
        except OSError as e:
            _ws_send(sock, f'[PTY error: {e}]\r\n'.encode())
            return

        if pid == 0:
            # ── Child process ─────────────────────────────────────────────────
            # Builds a smart bashrc that:
            #   • Auto-SSHs into the switch (if --switch was given)
            #   • Provides a `connect <IP> [user]` alias to hop to any device
            #   • On `exit` from SSH, drops back to local shell (terminal stays open)
            os.environ['PS1'] = r'\u@\h:\W\$ '
            switch_ip = ANALYSIS_DATA.get('switch_ip')
            sw_user   = ANALYSIS_DATA.get('switch_user', 'admin')

            # ── Write reusable `connect` helper ──────────────────────────────
            connect_sh = '/tmp/netscope_connect.sh'
            tconnect_sh = '/tmp/netscope_tconnect.sh'
            _default_ip = switch_ip or ''
            try:
                with open(connect_sh, 'w') as _f:
                    _f.write(
                        "#!/bin/bash\n"
                        "# NetScope SSH helper\n"
                        "# Usage:  connect <IP> [user] [password]\n"
                        "_IP=\"${1:-" + _default_ip + "}\"\n"
                        "_U=\"${2:-admin}\"\n"
                        "_P=\"$3\"\n"
                        "if [ -z \"$_IP\" ]; then echo 'Usage: connect <IP> [user] [password]'; exit 1; fi\n"
                        "_SSH_OPTS=\"-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa\"\n"
                        "echo \"[NetScope] Connecting via SSH to $_U@$_IP ...\"\n"
                        "if [ -n \"$_P\" ] && command -v sshpass >/dev/null 2>&1; then\n"
                        "  sshpass -p \"$_P\" ssh $_SSH_OPTS \"$_U@$_IP\"\n"
                        "elif [ -n \"$_P\" ]; then\n"
                        "  echo '  (sshpass not found — you will be prompted for password)'\n"
                        "  ssh $_SSH_OPTS \"$_U@$_IP\"\n"
                        "else\n"
                        "  ssh $_SSH_OPTS \"$_U@$_IP\"\n"
                        "fi\n"
                        "echo \"[NetScope] Disconnected from $_IP.\"\n"
                        "echo \"[NetScope] Type  connect <IP>  (SSH) or  tconnect <IP>  (Telnet)\"\n"
                    )
                import stat as _stat
                os.chmod(connect_sh, _stat.S_IRWXU | _stat.S_IRGRP | _stat.S_IXGRP)
            except Exception:
                connect_sh = None

            # ── Write reusable `tconnect` (Telnet) helper ────────────────────
            try:
                with open(tconnect_sh, 'w') as _f:
                    _f.write(
                        "#!/usr/bin/env python3\n"
                        "# NetScope Telnet helper\n"
                        "# Usage:  tconnect <IP> [user] [password] [port]\n"
                        "import sys, socket, time, select\n"
                        "\n"
                        "host = sys.argv[1] if len(sys.argv)>1 else ''\n"
                        "user = sys.argv[2] if len(sys.argv)>2 else 'admin'\n"
                        "pwd  = sys.argv[3] if len(sys.argv)>3 else ''\n"
                        "port = int(sys.argv[4]) if len(sys.argv)>4 else 23\n"
                        "\n"
                        "if not host:\n"
                        "    print('Usage: tconnect <IP> [user] [password] [port]')\n"
                        "    sys.exit(1)\n"
                        "\n"
                        "IAC,DO,DONT,WILL,WONT = 0xFF,0xFD,0xFE,0xFB,0xFC\n"
                        "\n"
                        "def iac_handle(sock, raw):\n"
                        "    out = bytearray(); i = 0\n"
                        "    while i < len(raw):\n"
                        "        b = raw[i]\n"
                        "        if b == IAC and i+1 < len(raw):\n"
                        "            cmd = raw[i+1]\n"
                        "            if cmd in (DO,DONT,WILL,WONT) and i+2<len(raw):\n"
                        "                opt = raw[i+2]\n"
                        "                reply = WONT if cmd in (DO,WILL) else DONT\n"
                        "                try: sock.sendall(bytes([IAC, reply, opt]))\n"
                        "                except: pass\n"
                        "                i += 3\n"
                        "            elif cmd == IAC: out.append(IAC); i += 2\n"
                        "            else: i += 2\n"
                        "        else: out.append(b); i += 1\n"
                        "    return bytes(out)\n"
                        "\n"
                        "print(f'[NetScope] Connecting via Telnet to {host}:{port} ...')\n"
                        "try:\n"
                        "    s = socket.create_connection((host, port), timeout=10)\n"
                        "    s.settimeout(0.5)\n"
                        "except Exception as e:\n"
                        "    print(f'[NetScope] Telnet connection failed: {e}')\n"
                        "    sys.exit(1)\n"
                        "\n"
                        "print(f'[NetScope] Connected! Interactive Telnet session to {host}')\n"
                        "print('[NetScope] Type  quit  or  exit  to disconnect')\n"
                        "print()\n"
                        "\n"
                        "import os, tty, termios\n"
                        "old = termios.tcgetattr(sys.stdin)\n"
                        "try:\n"
                        "    tty.setcbreak(sys.stdin.fileno())\n"
                        "    buf = b''\n"
                        "    # Wait for login prompt and auto-login\n"
                        "    login_done = False\n"
                        "    pwd_done = False\n"
                        "    while True:\n"
                        "        r,_,_ = select.select([s, sys.stdin],[],[],0.1)\n"
                        "        if s in r:\n"
                        "            try: raw = s.recv(4096)\n"
                        "            except: raw = b''\n"
                        "            if not raw: print('\\n[NetScope] Connection closed by remote host'); break\n"
                        "            data = iac_handle(s, raw)\n"
                        "            text = data.decode(errors='ignore')\n"
                        "            sys.stdout.write(text); sys.stdout.flush()\n"
                        "            buf += data\n"
                        "            low = buf[-200:].decode(errors='ignore').lower()\n"
                        "            if not login_done and ('ogin' in low or 'sername' in low):\n"
                        "                s.sendall((user + '\\r\\n').encode()); login_done = True\n"
                        "            elif login_done and not pwd_done and 'assword' in low:\n"
                        "                s.sendall((pwd + '\\r\\n').encode()); pwd_done = True\n"
                        "        if sys.stdin in r:\n"
                        "            ch = os.read(sys.stdin.fileno(), 1)\n"
                        "            if not ch: break\n"
                        "            s.sendall(ch)\n"
                        "except KeyboardInterrupt:\n"
                        "    print('\\n[NetScope] Interrupted')\n"
                        "finally:\n"
                        "    termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)\n"
                        "    s.close()\n"
                        "print(f'[NetScope] Disconnected from {host}')\n"
                        "print('[NetScope] Type  connect <IP>  (SSH) or  tconnect <IP>  (Telnet)')\n"
                    )
                os.chmod(tconnect_sh, _stat.S_IRWXU | _stat.S_IRGRP | _stat.S_IXGRP)
            except Exception:
                tconnect_sh = None

            # ── Build bashrc ──────────────────────────────────────────────────
            rc_lines = [
                "export PS1='\\u@\\h:\\W\\$ '\n",
            ]
            if connect_sh:
                rc_lines.append(f"alias connect='{connect_sh}'\n")
            if tconnect_sh:
                rc_lines.append(f"alias tconnect='{tconnect_sh}'\n")
            rc_lines.append("echo ''\n")

            if switch_ip:
                rc_lines += [
                    "echo '  ╔══════════════════════════════════════╗'\n",
                    "echo '  ║      NetScope Terminal               ║'\n",
                    "echo '  ╚══════════════════════════════════════╝'\n",
                    f"echo '  Connecting to {sw_user}@{switch_ip} ...'\n",
                    "echo '  Tip:  exit              — return to local shell'\n",
                    "echo '  Tip:  connect <IP> [user] [pass] — SSH into any device'\n",
                    "echo '  Tip:  tconnect <IP> [user] [pass] — Telnet into any device'\n",
                    "echo ''\n",
                    f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa {sw_user}@{switch_ip}\n",
                    # After SSH exits — show one clean message then go silent
                    # Turn off PS1 so bash stops printing the prompt repeatedly
                    "echo ''\n",
                    f"echo '[NetScope] Disconnected from {switch_ip}.'\n",
                    "echo '[NetScope] Type  connect <IP> (SSH)  or  tconnect <IP> (Telnet)'\n",
                    "echo ''\n",
                    # Replace PS1 with empty so no more prompts spam the terminal
                    "export PS1=''\n",
                    # Disable history and set a trap so Enter does nothing visible
                    "set +o history\n",
                    "PROMPT_COMMAND=''\n",
                    # Print a single waiting indicator and block silently
                    "echo '  (Shell is idle — type  connect <IP>  or close the tab)'\n",
                    "echo ''\n",
                ]
            else:
                rc_lines += [
                    "echo '  ╔══════════════════════════════════════╗'\n",
                    "echo '  ║      NetScope Terminal               ║'\n",
                    "echo '  ╚══════════════════════════════════════╝'\n",
                    "echo '  Type  connect <IP> [user]   — SSH into a network device'\n",
                    "echo '  Type  tconnect <IP> [user]  — Telnet into a network device'\n",
                    "echo ''\n",
                ]

            rc_path = '/tmp/netscope_bashrc'
            try:
                with open(rc_path, 'w') as _f:
                    _f.writelines(rc_lines)
                os.execvp('bash', ['bash', '--rcfile', rc_path, '--noprofile'])
            except Exception:
                os.execvp('bash', ['bash', '--norc', '--noprofile'])
            os._exit(1)

        # Parent — make PTY fd non-blocking for reads
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        alive = threading.Event()
        alive.set()

        def pty_to_ws():
            """Read PTY output → send to browser WebSocket."""
            while alive.is_set():
                try:
                    r, _, _ = select.select([fd], [], [], 0.05)
                    if r:
                        data = os.read(fd, 4096)
                        if data:
                            _ws_send(sock, data)
                        else:
                            break  # PTY closed (EOF)
                except OSError:
                    break
            alive.clear()
            # PTY died — unblock the main thread stuck in _ws_recv
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        reader = threading.Thread(target=pty_to_ws, daemon=True)
        reader.start()

        # Main loop: read WebSocket frames → write to PTY
        try:
            while alive.is_set():
                payload = _ws_recv(sock)
                if payload is None:
                    break
                try:
                    os.write(fd, payload)
                except OSError:
                    break
        except OSError:
            pass
        finally:
            alive.clear()
            try: os.kill(pid, signal.SIGTERM)
            except ProcessLookupError: pass
            try: os.waitpid(pid, os.WNOHANG)
            except (ChildProcessError, OSError): pass
            try: os.close(fd)
            except OSError: pass

    # ── Export helpers ────────────────────────────────────────────────────────

    def _export_json(self):
        analysis = ANALYSIS_DATA.get('analysis', {})
        pkts = analysis.get('all_packets', [])
        rows = []
        for p in pkts:
            rows.append({k: v for k, v in p.items() if k not in ('hex_data', 'layers')})
        data = json.dumps({'file': ANALYSIS_DATA.get('fname', ''),
                           'packets': rows,
                           'proto_counts': analysis.get('proto_counts', {}),
                           'anomalies': analysis.get('anomalies', [])},
                          indent=2).encode()
        fname = os.path.basename(ANALYSIS_DATA.get('fname', 'capture')) + '_export.json'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Disposition', f'attachment; filename="{fname}"')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _export_csv(self):
        import csv, io
        analysis = ANALYSIS_DATA.get('analysis', {})
        pkts = analysis.get('all_packets', [])
        buf = io.StringIO()
        fields = ['id','ts','proto','src_ip','dst_ip','src_mac','dst_mac',
                  'src_port','dst_port','frame_len','service','tcp_flags',
                  'tcp_seq','tcp_ack','tcp_window','ttl','arp_op','vlan_id','summary']
        w = csv.DictWriter(buf, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        for p in pkts:
            w.writerow({f: p.get(f, '') for f in fields})
        data = buf.getvalue().encode('utf-8')
        fname = os.path.basename(ANALYSIS_DATA.get('fname', 'capture')) + '_export.csv'
        self.send_response(200)
        self.send_header('Content-Type', 'text/csv')
        self.send_header('Content-Disposition', f'attachment; filename="{fname}"')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _export_pcap(self):
        pcap_path = ANALYSIS_DATA.get('fname', '')
        if not pcap_path or not os.path.exists(pcap_path):
            self.send_response(404); self.end_headers()
            return
        data = open(pcap_path, 'rb').read()
        fname = os.path.basename(pcap_path)
        self.send_response(200)
        self.send_header('Content-Type', 'application/vnd.tcpdump.pcap')
        self.send_header('Content-Disposition', f'attachment; filename="{fname}"')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# ═══════════════════════════════════════════════════════════════════════════════
#  SWITCH CAPTURE (reusable)
# ═══════════════════════════════════════════════════════════════════════════════

# Background capture state — polled by /api/capture-status
_CAPTURE_STATE = {'running': False, 'phase': '', 'error': None, 'pcap': None, 'cancel': False}

# ── Robust EXOS capture engine (ported from dashboard_v16) ───────────────────

def _telnet_check(host, port=23, timeout=5):
    """Pre-flight Telnet reachability check. Returns (ok, reason)."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        try:    banner = s.recv(256)
        except: banner = b''
        s.close()
        if banner:
            return True, f'Telnet port {port} open, banner received ({len(banner)} bytes)'
        return True, f'Telnet port {port} open (no banner)'
    except ConnectionRefusedError:
        return False, f'Telnet port {port} refused — enable telnet on switch'
    except socket.timeout:
        return False, f'Telnet port {port} timed out'
    except OSError as e:
        return False, f'Telnet port {port} unreachable: {e}'


class _Telnet:
    """Minimal Telnet client for EXOS switch CLI with IAC negotiation."""
    IAC=0xFF; DONT=0xFE; DO=0xFD; WONT=0xFC; WILL=0xFB

    def __init__(self, host, username, password, port=23, timeout=15):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self._buf = b''; self._host = host
        self._login(username, password)

    def _recv_raw(self):
        try:    return self.sock.recv(4096)
        except: return b''

    def _recv(self):
        raw = self._recv_raw()
        if not raw: return b''
        out = bytearray(); i = 0
        while i < len(raw):
            b = raw[i]
            if b == self.IAC and i + 1 < len(raw):
                cmd = raw[i+1]
                if cmd in (self.DO, self.DONT, self.WILL, self.WONT) and i+2 < len(raw):
                    opt = raw[i+2]
                    reply = self.WONT if cmd in (self.DO, self.WILL) else self.DONT
                    try: self.sock.sendall(bytes([self.IAC, reply, opt]))
                    except: pass
                    i += 3
                elif cmd == self.IAC: out.append(self.IAC); i += 2
                else: i += 2
            else: out.append(b); i += 1
        return bytes(out)

    def _read_until(self, *keys, timeout=12):
        end = time.time() + timeout
        while time.time() < end:
            data = self._recv()
            if data:
                self._buf += data
                for k in keys:
                    if k.encode() in self._buf:
                        out, self._buf = self._buf, b''
                        return out.decode(errors='ignore')
            time.sleep(0.05)
        out, self._buf = self._buf, b''
        return out.decode(errors='ignore')

    def _send(self, s): self.sock.sendall(s.encode())

    def _login(self, user, pwd):
        out = self._read_until('login:', 'Login:', 'Username:', 'ogin', timeout=12)
        if not any(k in out for k in ('ogin', 'sername')):
            raise RuntimeError(f'No login prompt from {self._host}:23 — is Telnet enabled?')
        self._send(user + '\r\n')
        out = self._read_until('assword:', '#', '>', timeout=10)
        if 'assword' in out:
            self._send(pwd + '\r\n')
            out = self._read_until('#', '>', 'error', 'Error', timeout=10)
            if any(k in out.lower() for k in ('error','invalid','denied')):
                raise RuntimeError(f'Authentication failed for user "{user}" via Telnet.')
        self._send('disable cli paging\r\n')
        self._read_until('#', '>', timeout=8)
        print('  ✓ Telnet logged in')

    def run(self, cmd, timeout=20):
        self._send(cmd + '\r\n')
        return self._read_until('#', '>', timeout=timeout)

    def close(self):
        try: self.sock.close()
        except: pass


def _ssh_connect_exos(host, username, password):
    """SSH connect with EXOS-compatible algorithm settings (handles older key types)."""
    import paramiko
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(hostname=host, username=username, password=password,
              timeout=15, look_for_keys=False, allow_agent=False,
              disabled_algorithms=dict(pubkeys=['rsa-sha2-256','rsa-sha2-512']))
    return c


def _ssh_exec_exos(client, cmd, timeout=30):
    """Execute a single non-interactive command over SSH, return (out, err, rc)."""
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    rc  = stdout.channel.recv_exit_status()
    out = stdout.read().decode('utf-8', 'ignore')
    err = stderr.read().decode('utf-8', 'ignore')
    return out, err, rc


def _ssh_check_exos(host, username, password):
    """Pre-flight SSH auth check. Returns (ok: bool, reason: str)."""
    try:
        import paramiko
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(hostname=host, username=username, password=password,
                  timeout=8, look_for_keys=False, allow_agent=False,
                  disabled_algorithms=dict(pubkeys=['rsa-sha2-256','rsa-sha2-512']))
        c.close()
        return True, 'SSH auth successful'
    except Exception as e:
        return False, str(e)


def _sftp_list_pcaps(sftp, directory='/usr/local/tmp'):
    """List .pcap files in a directory via SFTP. Returns {filename: mtime}."""
    result = {}
    try:
        for a in sftp.listdir_attr(directory):
            if a.filename.endswith('.pcap'):
                result[a.filename] = a.st_mtime or 0
    except Exception as e:
        print(f'  SFTP listdir {directory}: {e}')
    return result


def _download_pcap_robust(client, remote_path, local_path):
    """Download a PCAP from EXOS via SFTP with 3-tier fallback (SFTP get → SFTP read → SCP)."""
    # Method 1: sftp.get()
    try:
        print('  Trying SFTP get...')
        sftp = client.open_sftp()
        sftp.get(remote_path, local_path)
        sftp.close()
        sz = os.path.getsize(local_path) if os.path.exists(local_path) else 0
        if sz >= 24:
            print(f'  ✓ SFTP get OK  ({sz:,} bytes)'); return True
        print(f'  SFTP get returned {sz} bytes — trying open()')
    except Exception as e:
        print(f'  SFTP get failed: {e}')
    # Method 2: sftp.open() binary read
    try:
        print('  Trying SFTP open/read...')
        sftp = client.open_sftp()
        with sftp.open(remote_path, 'rb') as rf:
            rf.prefetch(); data = rf.read()
        sftp.close()
        if len(data) >= 24:
            with open(local_path, 'wb') as lf: lf.write(data)
            print(f'  ✓ SFTP open/read OK  ({len(data):,} bytes)'); return True
        if len(data) > 0:
            with open(local_path, 'wb') as lf: lf.write(data)
            return True
    except Exception as e:
        print(f'  SFTP open/read failed: {e}')
    # Method 3: SCP fallback
    try:
        from scp import SCPClient
        print('  Trying SCP...')
        with SCPClient(client.get_transport(), socket_timeout=30) as scp:
            scp.get(remote_path, local_path)
        sz = os.path.getsize(local_path) if os.path.exists(local_path) else 0
        if sz >= 24:
            print(f'  ✓ SCP OK  ({sz:,} bytes)'); return True
    except Exception as e:
        print(f'  SCP failed: {e}')
    raise RuntimeError(
        f'All download methods failed for {remote_path}.\n'
        f'  Manual fallback: scp {client.get_transport().getpeername()[0]}:{remote_path} ./capture.pcap'
    )


def _do_switch_capture(switch_ip, user, password, sw_port, duration, vlan='default', protocol='ssh', sw_interface='', vlan_only=False):
    """
    Robust EXOS switch capture with SSH/Telnet auto-detection, pre-flight auth checks,
    SFTP-based dynamic file discovery, and 3-tier download fallback.
    sw_interface: if set, uses 'debug packet capture on interface <iface> ...' instead of port/vlan.
    vlan_only: if True, forces VLAN-mode capture regardless of vlan value (handles 'Default' etc.).
    Returns local pcap path. Raises RuntimeError on failure (never calls sys.exit).
    """
    try:
        import paramiko
    except ImportError:
        raise RuntimeError(
            'paramiko is required for switch capture.\n'
            'Install with: pip3 install paramiko scp\n'
            'Or use --pcap <file> to analyse an existing capture.'
        )

    PCAP_DIR = '/usr/local/tmp'

    # ── Pre-flight: determine protocol ──────────────────────────────────────
    _CAPTURE_STATE['phase'] = f'Pre-flight: checking connectivity to {switch_ip}...'
    use_telnet = False

    if protocol == 'telnet':
        ok, reason = _telnet_check(switch_ip)
        print(f'  {"✓" if ok else "✗"} Telnet: {reason}')
        if not ok:
            raise RuntimeError(f'Telnet check failed: {reason}\nOr use protocol=ssh')
        use_telnet = True
    elif protocol == 'ssh':
        ok, reason = _ssh_check_exos(switch_ip, user, password)
        print(f'  {"✓" if ok else "✗"} SSH: {reason}')
        if not ok:
            raise RuntimeError(f'SSH check failed: {reason}\nOr try protocol=telnet or protocol=auto')
    else:  # auto
        ssh_ok, ssh_r = _ssh_check_exos(switch_ip, user, password)
        tel_ok, tel_r = _telnet_check(switch_ip)
        print(f'  SSH: {"✓" if ssh_ok else "✗"} {ssh_r}')
        print(f'  Telnet: {"✓" if tel_ok else "✗"} {tel_r}')
        if not ssh_ok and not tel_ok:
            raise RuntimeError(f'Neither SSH nor Telnet reachable.\n  SSH: {ssh_r}\n  Telnet: {tel_r}')
        use_telnet = tel_ok and not ssh_ok
        print(f'  → Using: {"Telnet for CLI + SSH/SFTP for download" if use_telnet else "SSH only"}')

    # ── Phase A: snapshot PCAP dir before capture ────────────────────────────
    _CAPTURE_STATE['phase'] = 'Phase A: Snapshotting PCAP directory...'
    print(f'\n  [Phase A] Snapshot {PCAP_DIR} before capture...')
    try:
        _ssh_pre  = _ssh_connect_exos(switch_ip, user, password)
        _sftp_pre = _ssh_pre.open_sftp()
        before    = _sftp_list_pcaps(_sftp_pre, PCAP_DIR)
        _sftp_pre.close(); _ssh_pre.close()
        print(f'  {len(before)} existing PCAP(s) noted')
    except Exception as e:
        raise RuntimeError(f'Cannot SFTP list {PCAP_DIR}: {e}\nCheck SSH is enabled on the switch.')

    # ── Phase B: trigger capture ─────────────────────────────────────────────
    import datetime as _dt
    _cap_ts   = _dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    _cap_file = f'networkanalyser_{_cap_ts}'

    if sw_interface:
        _CAPTURE_STATE['phase'] = f'Phase B: Starting capture on interface {sw_interface}...'
        cap_on  = f'debug packet capture on interface {sw_interface} file-name {_cap_file}'
        cap_off = f'debug packet capture off interface'
        _cap_desc = f'interface {sw_interface}'
    elif vlan_only or vlan.lower() != 'default':
        _CAPTURE_STATE['phase'] = f'Phase B: Starting capture on vlan {vlan}...'
        cap_on  = f'debug packet capture on vlan {vlan} file-name {_cap_file}'
        cap_off = f'debug packet capture off vlan'
        _cap_desc = f'vlan {vlan}'
    else:
        _CAPTURE_STATE['phase'] = f'Phase B: Starting capture on port {sw_port}...'
        cap_on  = f'debug packet capture ports {sw_port} on file-name {_cap_file}'
        cap_off = f'debug packet capture off ports'
        _cap_desc = f'port {sw_port}'

    # Store cap_off + connection details so cancel handler can forcefully stop
    _CAPTURE_STATE['_cap_off']    = cap_off
    _CAPTURE_STATE['_sw_ip']      = switch_ip
    _CAPTURE_STATE['_sw_user']    = user
    _CAPTURE_STATE['_sw_pass']    = password
    _CAPTURE_STATE['_use_telnet'] = use_telnet

    if use_telnet:
        print(f'\n  [Phase B] Telnet CLI capture on {_cap_desc}...')
        try:
            tel = _Telnet(switch_ip, user, password)
        except Exception as e:
            raise RuntimeError(f'Telnet connection failed: {e}')
        out = tel.run(cap_on)
        if 'invalid' in out.lower() or ('error' in out.lower() and 'capture' not in out.lower()):
            tel.close()
            raise RuntimeError(f'EXOS rejected command "{cap_on}":\n  {out.strip()[:300]}')
        print(f'  ✓ Capture started on port {sw_port}')
        for i in range(duration):
            if _CAPTURE_STATE.get('cancel'):
                print('\n  [Cancel] Abort signal received — stopping capture early')
                break
            time.sleep(1)
            pct = int((i+1)/duration*30)
            _CAPTURE_STATE['phase'] = f'Capturing... {int((i+1)/duration*100)}%'
            print(f'\r  [{"#"*pct}{"."*(30-pct)}] {int((i+1)/duration*100)}%', end='', flush=True)
        print(f'\r  [{"#"*30}] 100%                    ')
        tel.run(cap_off); print('  ✓ Capture stopped'); tel.close()
        if _CAPTURE_STATE.get('cancel'):
            raise RuntimeError('Capture cancelled by user')
    else:
        print(f'\n  [Phase B] SSH CLI capture on {_cap_desc}...')
        try:
            _ssh_cap = _ssh_connect_exos(switch_ip, user, password)
        except Exception as e:
            raise RuntimeError(f'SSH connect failed: {e}')
        out, err, _ = _ssh_exec_exos(_ssh_cap, cap_on, timeout=15)
        if 'invalid' in (out+err).lower():
            _ssh_cap.close()
            raise RuntimeError(f'EXOS rejected command "{cap_on}":\n  {(out+err).strip()[:300]}')
        print(f'  ✓ Capture started on port {sw_port}')
        for i in range(duration):
            if _CAPTURE_STATE.get('cancel'):
                print('\n  [Cancel] Abort signal received — stopping capture early')
                break
            time.sleep(1)
            pct = int((i+1)/duration*30)
            _CAPTURE_STATE['phase'] = f'Capturing... {int((i+1)/duration*100)}%'
            print(f'\r  [{"#"*pct}{"."*(30-pct)}] {int((i+1)/duration*100)}%', end='', flush=True)
        print(f'\r  [{"#"*30}] 100%                    ')
        _ssh_exec_exos(_ssh_cap, cap_off, timeout=15)
        print('  ✓ Capture stopped')
        _ssh_cap.close()
        if _CAPTURE_STATE.get('cancel'):
            raise RuntimeError('Capture cancelled by user')

    # ── Phase C: wait for EXOS to flush the PCAP file ────────────────────────
    _CAPTURE_STATE['phase'] = 'Phase C: Waiting for switch to write PCAP file...'
    print(f'\n  [Phase C] Waiting for EXOS to write PCAP file...')
    remote_path = None
    for attempt in range(1, 12):
        time.sleep(1)
        try:
            _ssh_post  = _ssh_connect_exos(switch_ip, user, password)
            _sftp_post = _ssh_post.open_sftp()
            after      = _sftp_list_pcaps(_sftp_post, PCAP_DIR)
            _sftp_post.close(); _ssh_post.close()
        except Exception as e:
            print(f'\n  SFTP check attempt {attempt} failed: {e}'); continue
        new_files = {f: m for f, m in after.items()
                     if f not in before or m > before.get(f, 0)}
        if new_files:
            newest = max(new_files, key=lambda f: new_files[f])
            remote_path = f'{PCAP_DIR}/{newest}'
            print(f'\n  ✓ New file: {newest}  ({after.get(newest, 0):,} mtime)'); break
        print(f'\r  Waiting... attempt {attempt}/11', end='', flush=True)

    print()
    if not remote_path:
        try:
            _ssh_d = _ssh_connect_exos(switch_ip, user, password)
            _sftp_d = _ssh_d.open_sftp()
            listing = ', '.join(sorted(_sftp_list_pcaps(_sftp_d, PCAP_DIR).keys())[-8:]) or '(none)'
            _sftp_d.close(); _ssh_d.close()
        except Exception: listing = '(could not list)'
        _hint = (f'  Interface {sw_interface} may have had no traffic — try a longer duration'
                 if sw_interface else
                 f'  {_cap_desc.capitalize()} may have had no traffic — try a longer duration\n'
                 f'  Or verify with: show port {sw_port} info')
        raise RuntimeError(
            f'No new PCAP appeared in {PCAP_DIR} after {duration}s capture.\n'
            f'  Most recent files: {listing}\n'
            f'{_hint}'
        )

    # ── Phase D: download ────────────────────────────────────────────────────
    _CAPTURE_STATE['phase'] = 'Phase D: Downloading PCAP via SFTP...'
    print(f'  [Phase D] Downloading {remote_path} via SFTP...')
    try:
        _ssh_dl = _ssh_connect_exos(switch_ip, user, password)
    except Exception as e:
        raise RuntimeError(f'SSH for download failed: {e}')
    os.makedirs('captures', exist_ok=True)
    local = os.path.join('captures', f'capture_{switch_ip.replace(".", "_")}_{int(time.time())}.pcap')
    try:
        _download_pcap_robust(_ssh_dl, remote_path, local)
    except RuntimeError as e:
        _ssh_dl.close()
        raise
    _ssh_dl.close()
    print(f'  ✓ PCAP saved to: {local}')
    return local


def _bg_capture(switch_ip, user, password, sw_port, vlan, duration, protocol='ssh', sw_interface='', vlan_only=False):
    """Background thread: capture → parse → analyse → update ANALYSIS_DATA."""
    global ANALYSIS_DATA
    _CAPTURE_STATE['running'] = True
    _CAPTURE_STATE['error'] = None
    _CAPTURE_STATE['pcap'] = None
    _CAPTURE_STATE['cancel'] = False
    try:
        pcap = _do_switch_capture(switch_ip, user, password, sw_port, duration,
                                  vlan=vlan, protocol=protocol, sw_interface=sw_interface,
                                  vlan_only=vlan_only)
        _CAPTURE_STATE['phase'] = 'Parsing packets...'
        raw = read_pcap(pcap)
        packets = parse_all(raw)
        _CAPTURE_STATE['phase'] = 'tshark enrichment...'
        tshark_data = _run_tshark(pcap)
        _merge_tshark(packets, tshark_data)
        _CAPTURE_STATE['phase'] = 'Analysing...'
        analysis = analyse(packets)
        ANALYSIS_DATA = {'analysis': analysis, 'fname': pcap,
                         'switch_ip': switch_ip, 'switch_user': user,
                         'switch_pass': password}
        PCAP_SLOTS['original'] = {'analysis': analysis, 'fname': pcap}
        _CAPTURE_STATE['pcap'] = pcap
        _CAPTURE_STATE['phase'] = 'Done'
        print(f'  [bg-capture] Complete: {len(packets)} packets from {switch_ip}')
    except (RuntimeError, Exception) as e:
        if _CAPTURE_STATE.get('cancel'):
            _CAPTURE_STATE['error'] = 'Capture cancelled by user'
            _CAPTURE_STATE['phase'] = 'Cancelled'
            print(f'  [bg-capture] Cancelled by user')
        else:
            _CAPTURE_STATE['error'] = str(e)
            print(f'  [bg-capture] Error: {e}')
    finally:
        _CAPTURE_STATE['running'] = False
        _CAPTURE_STATE['cancel'] = False


def _encode_html(html: str) -> bytes:
    """Encode HTML to UTF-8, healing any surrogate pair characters first.

    Python string literals with \\uD800-\\uDFFF escape sequences create lone
    surrogate code points that fail str.encode('utf-8').  This helper converts
    any surrogate pairs to the correct Unicode code point before encoding so
    the server never crashes with 'surrogates not allowed'.
    """
    try:
        return html.encode('utf-8')
    except UnicodeEncodeError:
        # Re-encode as UTF-16-LE with surrogatepass (preserves surrogate pairs
        # as raw 2-byte sequences), then decode back (combines pairs → proper
        # code points), then encode as valid UTF-8.
        healed = html.encode('utf-16-le', 'surrogatepass').decode('utf-16-le', 'surrogatepass')
        return healed.encode('utf-8', 'replace')


def _make_welcome_html():
    """Return a standalone welcome/setup page when no PCAP is loaded."""
    ai_model = (CLAUDE_MODEL if AI_BACKEND=='claude' else
                'gpt-4o' if AI_BACKEND=='openai' else OLLAMA_MODEL)
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Network Analyzer — Setup</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&family=Inter:wght@400;500;600;700;800&display=swap');
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#050a14;--panel:#0a1222;--card:#0e1a2e;--border:#1a2e4a;--acc:#00d4ff;--acc2:#7c5cfc;--ok:#34d399;--warn:#fbbf24;--err:#f87171;--text:#f1f5f9;--muted:#6b8ab0;--mono:'IBM Plex Mono',monospace;--sans:'Inter',system-ui,sans-serif}}
html,body{{height:100%;overflow:auto;background:var(--bg);color:var(--text);font-family:var(--sans)}}
.wrap{{max-width:740px;margin:0 auto;padding:40px 20px}}
.logo{{font-size:48px;text-align:center;margin-bottom:8px}}
h1{{text-align:center;font-size:24px;color:var(--acc);margin-bottom:4px}}
.sub{{text-align:center;color:var(--muted);font-size:12px;margin-bottom:36px}}
.section{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:24px 28px;margin-bottom:20px}}
.section h2{{font-size:14px;color:var(--acc);margin-bottom:16px;text-transform:uppercase;letter-spacing:.1em}}
.form-row{{display:flex;gap:12px;margin-bottom:12px;flex-wrap:wrap}}
.form-row label{{font:600 11px var(--sans);color:var(--muted);display:block;margin-bottom:4px}}
.form-row .fg{{flex:1;min-width:120px}}
.form-row input,.form-row select{{width:100%;padding:10px 14px;background:var(--panel);border:1px solid var(--border);border-radius:8px;color:var(--text);font:500 13px var(--mono);outline:none;transition:border .2s}}
.form-row input:focus{{border-color:var(--acc)}}
.form-row input::placeholder{{color:#3a506b}}
.btn{{display:inline-flex;align-items:center;gap:8px;padding:12px 28px;border:none;border-radius:8px;font:700 13px var(--sans);cursor:pointer;transition:all .2s}}
.btn-primary{{background:linear-gradient(135deg,var(--acc),#0099cc);color:#000}}
.btn-primary:hover{{filter:brightness(1.1);transform:translateY(-1px)}}
.btn-primary:disabled{{opacity:.5;cursor:not-allowed;transform:none}}
.btn-upload{{background:linear-gradient(135deg,var(--acc2),#5a3ec8);color:#fff}}
.btn-upload:hover{{filter:brightness(1.1);transform:translateY(-1px)}}
.or{{text-align:center;color:var(--muted);font:600 12px var(--sans);padding:8px 0;text-transform:uppercase;letter-spacing:.15em}}
.status{{margin-top:16px;padding:14px 18px;background:var(--panel);border:1px solid var(--border);border-radius:8px;display:none}}
.status.show{{display:block}}
.status .phase{{color:var(--acc);font:600 12px var(--mono);margin-bottom:6px}}
.status .bar-wrap{{background:#1e2535;border-radius:4px;height:6px;overflow:hidden;margin-top:8px}}
.status .bar-fill{{height:6px;background:linear-gradient(90deg,var(--acc),var(--acc2));border-radius:4px;transition:width .3s;animation:pulse-bar 1.5s infinite}}
@keyframes pulse-bar{{0%,100%{{opacity:1}}50%{{opacity:.6}}}}
.chip{{display:inline-block;padding:3px 10px;border-radius:6px;font:600 10px var(--mono);background:rgba(0,212,255,.1);color:var(--acc);border:1px solid rgba(0,212,255,.2)}}
.drop-zone{{border:2px dashed var(--border);border-radius:12px;padding:40px 20px;text-align:center;color:var(--muted);cursor:pointer;transition:all .2s;margin-top:12px}}
.drop-zone:hover,.drop-zone.drag{{border-color:var(--acc2);background:rgba(124,92,252,.05);color:var(--text)}}
.drop-zone .icon{{font-size:32px;margin-bottom:8px}}
.err{{color:var(--err);font:500 11px var(--sans);margin-top:8px}}
footer{{text-align:center;color:var(--muted);font-size:10px;margin-top:24px;padding-bottom:20px}}
</style>
</head>
<body>
<div class="wrap">
  <div class="logo">🔬</div>
  <h1>AI Network Analyzer</h1>
  <div class="sub">Choose a data source to begin — capture live from a switch or upload a PCAP file</div>

  <!-- ══ OPTION 1: SWITCH CAPTURE ══ -->
  <div class="section">
    <h2>📡 Option 1 — Capture from Switch</h2>
    <div class="form-row">
      <div class="fg" style="flex:2">
        <label>Switch IP <span style="color:var(--err)">*</span></label>
        <input id="s-ip" type="text" placeholder="e.g. 10.127.11.165" required>
      </div>
      <div class="fg">
        <label>Username</label>
        <input id="s-user" type="text" placeholder="admin" value="admin">
      </div>
      <div class="fg">
        <label>Password</label>
        <input id="s-pass" type="password" placeholder="(empty)">
      </div>
    </div>
    <div class="form-row" style="margin-bottom:6px">
      <div class="fg" style="flex:2">
        <label>Capture Target <span style="color:var(--err)">*</span></label>
        <select id="s-cap-type" onchange="_capTypeChange()" style="width:100%;padding:10px 14px;background:var(--panel);border:1px solid var(--border);border-radius:8px;color:var(--text);font:500 13px var(--mono);outline:none">
          <option value="port">Port (e.g. 1, 48, 1:2)</option>
          <option value="vlan">VLAN (Default / Mgmt / any VLAN name)</option>
          <option value="interface">Interface (Broadcom / netTx / mgmt0 / mgmt0:1)</option>
        </select>
      </div>
    </div>
    <div class="form-row" id="s-port-row">
      <div class="fg">
        <label>Port</label>
        <input id="s-port" type="text" placeholder="e.g. 48" value="1">
      </div>
      <div class="fg">
        <label>VLAN</label>
        <input id="s-vlan" type="text" placeholder="default" value="default">
      </div>
      <div class="fg">
        <label>Duration (sec)</label>
        <input id="s-dur" type="number" placeholder="10" value="10" min="3" max="120">
      </div>
    </div>
    <div class="form-row" id="s-iface-row" style="display:none">
      <div class="fg" style="flex:2">
        <label>Interface</label>
        <input id="s-iface" list="s-iface-list" type="text" placeholder="e.g. mgmt0" style="width:100%;padding:10px 14px;background:var(--panel);border:1px solid var(--border);border-radius:8px;color:var(--text);font:500 13px var(--mono);outline:none">
        <datalist id="s-iface-list">
          <option value="Broadcom">
          <option value="netTx">
          <option value="mgmt0">
          <option value="mgmt0:1">
        </datalist>
      </div>
      <div class="fg">
        <label>Duration (sec)</label>
        <input id="s-dur-iface" type="number" placeholder="10" value="10" min="3" max="120">
      </div>
    </div>
    <div class="form-row" id="s-vlan-row" style="display:none">
      <div class="fg" style="flex:2">
        <label>VLAN Name</label>
        <input id="s-vlan-name" list="s-vlan-list" type="text" placeholder="e.g. Default" style="width:100%;padding:10px 14px;background:var(--panel);border:1px solid var(--border);border-radius:8px;color:var(--text);font:500 13px var(--mono);outline:none">
        <datalist id="s-vlan-list">
          <option value="Default">
          <option value="Voice">
          <option value="Data">
        </datalist>
      </div>
      <div class="fg">
        <label>Duration (sec)</label>
        <input id="s-dur-vlan" type="number" placeholder="10" value="10" min="3" max="120">
      </div>
    </div>
    <button class="btn btn-primary" id="cap-btn" onclick="startCapture()">
      📡 Start Capture
    </button>
    <button id="cap-cancel-btn" onclick="cancelCapture()" style="display:none;margin-left:10px;padding:10px 20px;background:rgba(248,113,113,.15);border:1px solid var(--err);border-radius:8px;color:var(--err);font:700 13px var(--sans);cursor:pointer">
      ✕ Cancel Capture
    </button>
    <span class="chip" style="margin-left:12px">AI: {ai_model}</span>
    <div class="status" id="cap-status">
      <div class="phase" id="cap-phase">Initialising...</div>
      <div class="bar-wrap"><div class="bar-fill" id="cap-bar" style="width:10%"></div></div>
    </div>
    <div class="err" id="cap-err"></div>
  </div>

  <div class="or">— or —</div>

  <!-- ══ OPTION 2: UPLOAD PCAP ══ -->
  <div class="section">
    <h2>📂 Option 2 — Upload PCAP File</h2>
    <div class="form-row">
      <button class="btn btn-upload" onclick="document.getElementById('up-file').click()">
        ⬆ Choose PCAP File
      </button>
      <input type="file" id="up-file" accept=".pcap,.pcapng" style="display:none" onchange="uploadFile(this.files[0])">
      <span id="up-name" class="chip" style="display:none"></span>
    </div>
    <div class="drop-zone" id="drop-zone"
         ondragover="event.preventDefault();this.classList.add('drag')"
         ondragleave="this.classList.remove('drag')"
         ondrop="event.preventDefault();this.classList.remove('drag');uploadFile(event.dataTransfer.files[0])">
      <div class="icon">📂</div>
      Drag & drop a .pcap file here
    </div>
    <div class="status" id="up-status">
      <div class="phase" id="up-phase">Uploading...</div>
      <div class="bar-wrap"><div class="bar-fill" id="up-bar" style="width:50%"></div></div>
    </div>
    <div class="err" id="up-err"></div>
  </div>

  <div class="or">— or —</div>

  <!-- ══ OPTION 3: UPLOAD TRAP CSV ══ -->
  <div class="section" style="border-color:rgba(124,92,252,.4)">
    <h2 style="color:var(--acc2)">⚡ Option 3 — Upload Trap File (CSV Format)</h2>
    <p style="font:400 11px var(--sans);color:var(--muted);margin-bottom:14px">
      Upload a trap manager CSV export (columns: <code style="color:var(--acc)">time, IP, version, snmpTrapOID, varbinds</code>).
      Compatible with Extreme Networks trap manager, and similar SNMP manager exports.
    </p>
    <div class="form-row">
      <button class="btn" onclick="document.getElementById('csv-file').click()"
        style="background:linear-gradient(135deg,var(--acc2),#5a3ec8);color:#fff">
        ⬆ Choose Trap CSV File
      </button>
      <input type="file" id="csv-file" accept=".csv,.CSV,.json,.JSON,.txt" style="display:none" onchange="uploadTrapCsv(this.files[0])">
      <span id="csv-name" class="chip" style="display:none;border-color:rgba(124,92,252,.4);color:var(--acc2);background:rgba(124,92,252,.1)"></span>
    </div>
    <div class="drop-zone" id="csv-drop-zone" style="border-color:rgba(124,92,252,.3)"
         ondragover="event.preventDefault();this.classList.add('drag')"
         ondragleave="this.classList.remove('drag')"
         ondrop="event.preventDefault();this.classList.remove('drag');uploadTrapCsv(event.dataTransfer.files[0])">
      <div class="icon">⚡</div>
      Drag & drop a trap .csv or .json file here
    </div>
    <div class="status" id="csv-status">
      <div class="phase" id="csv-phase">Processing traps...</div>
      <div class="bar-wrap"><div class="bar-fill" id="csv-bar" style="width:40%;background:linear-gradient(90deg,var(--acc2),var(--acc))"></div></div>
    </div>
    <div class="err" id="csv-err"></div>
  </div>

  <footer>AI Network Analyzer · Zero-dependency dashboard · {ai_model}</footer>
</div>
<script>
function _capTypeChange() {{
  const t = document.getElementById('s-cap-type').value;
  document.getElementById('s-port-row').style.display  = t === 'port'      ? '' : 'none';
  document.getElementById('s-iface-row').style.display = t === 'interface' ? '' : 'none';
  document.getElementById('s-vlan-row').style.display  = t === 'vlan'      ? '' : 'none';
}}
async function startCapture() {{
  const ip   = document.getElementById('s-ip').value.trim();
  if (!ip) {{ document.getElementById('cap-err').textContent = 'Switch IP is required'; return; }}
  const user = document.getElementById('s-user').value.trim() || 'admin';
  const pass = document.getElementById('s-pass').value;
  const capType = document.getElementById('s-cap-type').value;

  let port = '', vlan = 'default', iface = '', dur = 10;
  if (capType === 'interface') {{
    iface = document.getElementById('s-iface').value.trim();
    if (!iface) {{ document.getElementById('cap-err').textContent = 'Interface name is required'; return; }}
    dur = parseInt(document.getElementById('s-dur-iface').value) || 10;
  }} else if (capType === 'vlan') {{
    vlan = document.getElementById('s-vlan-name').value.trim();
    if (!vlan) {{ document.getElementById('cap-err').textContent = 'VLAN name is required'; return; }}
    dur = parseInt(document.getElementById('s-dur-vlan').value) || 10;
  }} else {{
    port = document.getElementById('s-port').value.trim() || '1';
    vlan = document.getElementById('s-vlan').value.trim() || 'default';
    dur  = parseInt(document.getElementById('s-dur').value) || 10;
  }}

  document.getElementById('cap-btn').disabled = true;
  document.getElementById('cap-err').textContent = '';
  const st = document.getElementById('cap-status');
  st.classList.add('show');
  document.getElementById('cap-phase').textContent = 'Starting capture...';
  document.getElementById('cap-bar').style.width = '10%';

  try {{
    const body = {{switch_ip: ip, user, password: pass, duration: dur}};
    if (capType === 'interface') {{ body.sw_interface = iface; }}
    else if (capType === 'vlan') {{ body.vlan = vlan; body.vlan_only = true; }}
    else {{ body.sw_port = port; body.vlan = vlan; }}
    const r = await fetch('/api/capture', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify(body)
    }});
    const d = await r.json();
    if (d.error) {{ throw new Error(d.error); }}
    // Poll status
    document.getElementById('cap-cancel-btn').style.display = 'inline-flex';
    pollCapture();
  }} catch (e) {{
    document.getElementById('cap-err').textContent = 'Error: ' + e.message;
    document.getElementById('cap-btn').disabled = false;
    st.classList.remove('show');
  }}
}}

async function cancelCapture() {{
  const btn = document.getElementById('cap-cancel-btn');
  btn.disabled = true;
  btn.textContent = 'Cancelling...';
  document.getElementById('cap-phase').textContent = 'Cancelling — sending stop command to switch...';
  try {{
    await fetch('/api/capture-cancel', {{method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: '{{}}'}});
  }} catch (e) {{}}
}}

function pollCapture() {{
  const iv = setInterval(async () => {{
    try {{
      const r = await fetch('/api/capture-status');
      const d = await r.json();
      document.getElementById('cap-phase').textContent = d.phase || 'Working...';
      // Estimate progress
      const phases = ['Connecting', 'Cleaning', 'Capturing', 'Stopping', 'Downloading', 'Parsing', 'Analysing', 'Done'];
      const idx = phases.findIndex(p => (d.phase || '').includes(p));
      const pct = idx >= 0 ? Math.min(10 + idx * 12, 95) : 50;
      document.getElementById('cap-bar').style.width = pct + '%';

      if (!d.running) {{
        clearInterval(iv);
        document.getElementById('cap-cancel-btn').style.display = 'none';
        document.getElementById('cap-cancel-btn').disabled = false;
        document.getElementById('cap-cancel-btn').textContent = '✕ Cancel Capture';
        if (d.error) {{
          document.getElementById('cap-err').textContent = d.error.includes('cancelled') ? '✕ ' + d.error : 'Error: ' + d.error;
          document.getElementById('cap-btn').disabled = false;
          document.getElementById('cap-status').classList.remove('show');
        }} else {{
          document.getElementById('cap-phase').textContent = '✓ Capture complete! Loading dashboard...';
          document.getElementById('cap-bar').style.width = '100%';
          setTimeout(() => window.location.reload(), 800);
        }}
      }}
    }} catch (e) {{ /* retry */ }}
  }}, 1500);
}}

async function uploadFile(file) {{
  if (!file) return;
  document.getElementById('up-err').textContent = '';
  const nm = document.getElementById('up-name');
  nm.textContent = file.name; nm.style.display = '';
  const st = document.getElementById('up-status');
  st.classList.add('show');
  document.getElementById('up-phase').textContent = 'Uploading ' + file.name + '...';
  document.getElementById('up-bar').style.width = '30%';

  const fd = new FormData();
  fd.append('pcap', file, file.name);
  try {{
    const r = await fetch('/upload', {{method: 'POST', body: fd}});
    const d = await r.json();
    if (d.error) throw new Error(d.error);
    document.getElementById('up-phase').textContent = '✓ Uploaded! Loading dashboard...';
    document.getElementById('up-bar').style.width = '100%';
    setTimeout(() => window.location.reload(), 800);
  }} catch (e) {{
    document.getElementById('up-err').textContent = 'Error: ' + e.message;
    st.classList.remove('show');
  }}
}}

async function uploadTrapCsv(file) {{
  if (!file) return;
  document.getElementById('csv-err').textContent = '';
  const nm = document.getElementById('csv-name');
  nm.textContent = file.name; nm.style.display = '';
  const st = document.getElementById('csv-status');
  st.classList.add('show');
  document.getElementById('csv-phase').textContent = 'Uploading ' + file.name + '...';
  document.getElementById('csv-bar').style.width = '30%';

  const fd = new FormData();
  fd.append('csv', file, file.name);
  try {{
    const r = await fetch('/upload-trap-csv', {{method: 'POST', body: fd}});
    const d = await r.json();
    if (d.error) throw new Error(d.error);
    document.getElementById('csv-phase').textContent =
      '✓ Parsed ' + d.traps + ' traps from ' + d.agents + ' agent(s)! Loading dashboard...';
    document.getElementById('csv-bar').style.width = '100%';
    // Signal to auto-navigate to Traps tab after reload
    sessionStorage.setItem('_trapCsvLoaded', '1');
    setTimeout(() => window.location.reload(), 900);
  }} catch (e) {{
    document.getElementById('csv-err').textContent = 'Error: ' + e.message;
    st.classList.remove('show');
  }}
}}
</script>
</body>
</html>'''


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI + MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args():
    ap = argparse.ArgumentParser(description='AI Network Analyzer — Dashboard v3')
    ap.add_argument('--pcap',      metavar='FILE',  default=None,
                    help='PCAP file to analyse (optional — can be uploaded via UI)')
    ap.add_argument('--switch',    metavar='IP',    default=None,
                    help='Switch IP for live capture (optional — can be entered via UI)')
    ap.add_argument('--user',       metavar='USER',  default='admin')
    ap.add_argument('--password',   metavar='PASS',  default='')
    ap.add_argument('--sw-port',    metavar='PORT',  default='1')
    ap.add_argument('--vlan',       metavar='VLAN',  default='default')
    ap.add_argument('--protocol',   metavar='PROTO', default='ssh',
                    choices=['ssh','telnet','auto'],
                    help='Switch capture protocol: ssh (default), telnet, auto')
    ap.add_argument('--duration',   metavar='SECS',  type=int, default=10)
    ap.add_argument('--model',      metavar='MODEL', default='llama3.2')
    ap.add_argument('--ai',         metavar='BACKEND', default='ollama',
                    choices=['ollama','claude','openai'])
    ap.add_argument('--claude-key', metavar='KEY',   default='')
    ap.add_argument('--claude-model', metavar='MODEL', default='claude-sonnet-4-6',
                    help='Claude model to use (default: claude-sonnet-4-6)')
    ap.add_argument('--openai-key', metavar='KEY',   default='')
    ap.add_argument('--web-port',   metavar='PORT',  type=int, default=8765)
    ap.add_argument('--no-browser', action='store_true')
    ap.add_argument('--mcp-url',    metavar='URL',   default='',
                    help='SSE URL of the running exos-mcp-server '
                         '(default: http://localhost:8000/sse)')
    return ap.parse_args()


def main():
    print()
    print('+' + '='*62 + '+')
    print('|' + '  AI NETWORK ANALYZER — Dashboard v3'.center(62) + '|')
    print('|' + '  Zero-dependency dashboard | Works with any PCAP'.center(62) + '|')
    print('+' + '='*62 + '+')

    args = parse_args()
    global OLLAMA_MODEL, AI_BACKEND, CLAUDE_API_KEY, CLAUDE_MODEL, OPENAI_API_KEY, MCP_SERVER_URL
    OLLAMA_MODEL   = args.model
    AI_BACKEND     = args.ai
    CLAUDE_API_KEY = args.claude_key
    CLAUDE_MODEL   = args.claude_model
    OPENAI_API_KEY = args.openai_key
    if args.mcp_url:
        MCP_SERVER_URL = args.mcp_url

    if args.switch:
        _step('STEP 1 — Capturing from Switch')
        print(f'  Switch: {args.switch}  Port: {args.sw_port}  VLAN: {args.vlan}  Duration: {args.duration}s  Protocol: {args.protocol}')
        try:
            pcap = _do_switch_capture(args.switch, args.user, args.password,
                                      args.sw_port, args.duration,
                                      vlan=args.vlan, protocol=args.protocol)
        except RuntimeError as e:
            _die([str(e)])

    elif args.pcap:
        pcap = args.pcap
        if not Path(pcap).exists():
            _die([f'File not found: {pcap}'])
        _step('STEP 1 — Loading PCAP File')
        print(f'  File: {pcap}  ({os.path.getsize(pcap):,} bytes)')
    else:
        pcap = None   # No PCAP yet — dashboard will show setup page

    if pcap:
        _step('STEP 2 — Parsing Packets')
        raw     = read_pcap(pcap)
        print(f'  Raw records : {len(raw)}')
        packets = parse_all(raw)
        print(f'  Parsed      : {len(packets)}')

        _step('STEP 2b — tshark Enrichment')
        tshark_data = _run_tshark(pcap)
        _merge_tshark(packets, tshark_data)

        _step('STEP 3 — Analysis')
        analysis = analyse(packets)
        for proto, cnt in sorted(analysis['proto_counts'].items(), key=lambda x:x[1], reverse=True):
            rfc = RFC_REF.get(proto,'')
            bar = '#' * min(cnt, 35)
            print(f'  {proto:<18} {cnt:>5}  {bar}  {rfc}')

        _step('STEP 4 — Anomalies')
        for a in analysis['anomalies']: print(f'  ⚠ {a}')
        if not analysis['anomalies']: print('  ✓ None detected')

        _step('STEP 5 — Starting Dashboard')
        global ANALYSIS_DATA
        ANALYSIS_DATA = {'analysis': analysis, 'fname': pcap,
                         'switch_ip': args.switch if args.switch else None,
                         'switch_user': args.user, 'switch_pass': args.password}
        PCAP_SLOTS['original'] = {'analysis': analysis, 'fname': pcap}
    else:
        _step('STEP 1 — Starting Dashboard (no PCAP yet)')
        print('  No --switch or --pcap provided.')
        print('  Open the dashboard to capture from a switch or upload a PCAP file.')

    ai_model_str = (CLAUDE_MODEL if AI_BACKEND=='claude' else
                    'gpt-4o'     if AI_BACKEND=='openai' else OLLAMA_MODEL)

    port = _free_port(args.web_port)
    url  = f'http://localhost:{port}'
    from http.server import ThreadingHTTPServer
    srv  = ThreadingHTTPServer(('', port), Handler)
    srv.allow_reuse_address = True

    print(f'\n  Dashboard   : {url}')
    print(f'  AI Backend  : {AI_BACKEND}  ({ai_model_str})')
    print(f'  MCP Server  : {"ENABLED — " + MCP_SERVER_URL if MCP_ENABLED else "DISABLED"}')
    print(f'  Terminal    : ws://localhost:{port}/ws/terminal')
    print(f'  Export      : {url}/export/{{json|csv|pcap}}')
    print(f'\n  Press Ctrl+C to stop\n')

    if not args.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()

    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('\n  Stopped.')


if __name__ == '__main__':
    main()