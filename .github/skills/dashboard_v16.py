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

import os, json, struct, time, threading, webbrowser, socket, argparse, sys, base64, subprocess, pty, select, signal
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

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

KNOWN_ET = {0x0800, 0x0806, 0x8100, 0x86DD, 0x88CC, 0x888E, 0x88E7, 0x88F7}

PROTO_COLORS = {
    'ARP':'#f59e0b',  'ICMP':'#ef4444', 'TCP':'#3b82f6',   'UDP':'#10b981',
    'LLDP':'#8b5cf6', 'IPv6':'#06b6d4', 'EAPoL':'#f97316', 'IGMP':'#ec4899',
    'RARP':'#fb923c', 'STP':'#84cc16',  'OSPF':'#38bdf8',  'BGP':'#818cf8',
    'VRRP':'#f472b6', 'PIM':'#34d399',  'SCTP':'#a78bfa',  'DCCP':'#67e8f9',
    'DNS':'#fbbf24',  'DHCP':'#4ade80', 'NTP':'#a3e635',   'SSH':'#60a5fa',
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
    VALID_ET = {0x0800,0x0806,0x86DD,0x88CC,0x888E,0x88E7,0x88F7,0x8847,0x8848}
    VLAN_INNER = VALID_ET | {0x8100}
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
            fs    = _tcp_flags(flagb)
            fn    = ' | '.join(desc for bit,name,desc in TCP_FLAGS_MAP if flagb&bit) or 'none'
            pkt.update({'proto':'TCP','src_port':sp,'dst_port':dp,'tcp_flags':fs,
                        'tcp_seq':seq,'tcp_ack':ack,'tcp_window':win,'service':svc,
                        'tcp_state':_tcp_state(flagb),
                        'summary':f'TCP {src_ip}:{sp} → {dst_ip}:{dp}  [{fs}]{" "+svc if svc else ""}'})
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
        elif proto == 17 and len(ipp) >= 8:
            sp,dp  = struct.unpack('!HH', ipp[0:4])
            udplen = struct.unpack('!H',  ipp[4:6])[0]
            ck2    = struct.unpack('!H',  ipp[6:8])[0]
            svc    = SERVICES.get(dp) or SERVICES.get(sp,'')
            pkt.update({'proto':'UDP','src_port':sp,'dst_port':dp,'service':svc,
                        'summary':f'UDP {src_ip}:{sp} → {dst_ip}:{dp}{" "+svc if svc else ""}'})
            pkt['layers'].append({'title':'UDP — User Datagram Protocol  (RFC 768)','color':'#10b981','fields':[
                {'n':'Source Port',      'v':str(sp),                              'note':f'{"Service" if sp<1024 else "Client"} port'},
                {'n':'Destination Port', 'v':f'{dp}{" ("+svc+")" if svc else ""}','note':f'{"Service" if dp<1024 else "Client"} port'},
                {'n':'Length',           'v':f'{udplen} bytes',                   'note':'Header(8B)+payload'},
                {'n':'Checksum',         'v':f'0x{ck2:04x}',                     'note':'0x0000=disabled'},
                {'n':'Service',          'v':svc or 'Unknown',                    'note':RFC_REF.get(svc,'')},
                {'n':'Note',             'v':'Connectionless — no handshake',     'note':'No retransmit, low overhead'},
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
        else:
            pkt.update({'proto':f'IPv4-p{proto}','summary':f'IPv4 proto={proto} {src_ip}→{dst_ip}'})
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

# ── Analysis ──────────────────────────────────────────────────────────────────

def analyse(packets):
    pc={}; src_ips={}; dst_ips={}; services={}
    arp=[]; icmp=[]; tcp=[]; udp=[]; other=[]
    proto_buckets={}

    for p in packets:
        proto = p.get('proto','?')
        pc[proto] = pc.get(proto,0)+1
        {'ARP':arp,'ICMP':icmp,'TCP':tcp,'UDP':udp}.get(proto,other).append(p)
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

    # Anomalies
    anom = []
    if arp_reqs > 20: anom.append(f'ARP Storm: {arp_reqs} ARP requests detected')
    if len(arp_unanswered) > 5: anom.append(f'ARP: {len(arp_unanswered)} unanswered request pairs')
    if arp_gratuitous: anom.append(f'Gratuitous ARP: {len(arp_gratuitous)} unsolicited replies (IP conflict?)')
    rst_count = sum(1 for p in tcp if 'RST' in p.get('tcp_flags',''))
    if rst_count > 5: anom.append(f'TCP RST Storm: {rst_count} RST packets')
    udst = set(p.get('dst_port') for p in tcp if p.get('dst_port'))
    if len(udst) > 15: anom.append(f'Port Scan: {len(udst)} unique destination ports')
    pings = sum(1 for p in icmp if p.get('icmp_type')==8)
    if pings > 10: anom.append(f'ICMP Flood: {pings} Echo Requests')
    if tcp_syn > 20: anom.append(f'SYN Flood: {tcp_syn} SYN-only packets')

    total_bytes = sum(p.get('frame_len',0) for p in packets)
    proto_bytes = {}
    for p in packets:
        pr = p.get('proto','?')
        proto_bytes[pr] = proto_bytes.get(pr,0) + p.get('frame_len',0)

    return {
        'total':len(packets), 'proto_counts':pc,
        'arp':arp,'icmp':icmp,'tcp':tcp,'udp':udp,'other':other,
        'proto_buckets':proto_buckets,
        'src_ips':dict(sorted(src_ips.items(),key=lambda x:x[1],reverse=True)[:10]),
        'dst_ips':dict(sorted(dst_ips.items(),key=lambda x:x[1],reverse=True)[:10]),
        'services':services,'anomalies':anom,'all_packets':packets,
        'arp_reqs_total':arp_reqs,'arp_reps_total':arp_reps,
        'arp_pairs':arp_pairs,'arp_completed':arp_completed,
        'arp_unanswered':arp_unanswered,'arp_gratuitous':arp_gratuitous,
        'tcp_syn':tcp_syn,'tcp_synack':tcp_synack,'tcp_ack':tcp_ack,
        'tcp_psh':tcp_psh,'tcp_fin':tcp_fin,'tcp_rst':tcp_rst,
        'icmp_req':icmp_req,'icmp_rep':icmp_rep,'icmp_unr':icmp_unr,'icmp_ttl':icmp_ttl,
        'total_bytes':total_bytes,'proto_bytes':proto_bytes,
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

def ask_ai(prompt):
    if AI_BACKEND == 'claude' and CLAUDE_API_KEY: return _ask_claude(prompt)
    if AI_BACKEND == 'openai' and OPENAI_API_KEY: return _ask_openai(prompt)
    return _ask_ollama(prompt)

def _ask_ollama(prompt):
    try:
        import urllib.request, json as _j
        full = RFC_SYSTEM + '\n\n' + prompt
        data = _j.dumps({'model':OLLAMA_MODEL,'prompt':full,'stream':False}).encode()
        req  = urllib.request.Request('http://localhost:11434/api/generate', data=data,
                   method='POST', headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req, timeout=120) as r:
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
        }
        for p in pkts[:1000]
    })
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
    })

    # ── Protocol stats rows ─────────────────────────────────────────────────────
    proto_stat_rows = ''
    for proto, cnt in sorted(pc.items(), key=lambda x:x[1], reverse=True):
        pct  = cnt/total*100 if total else 0
        byt  = proto_bytes.get(proto,0)
        rfc  = RFC_REF.get(proto,'—')
        col  = _proto_color(proto)
        proto_stat_rows += (
            f'<tr>'
            f'<td><span class="badge" style="background:{col}">{proto}</span></td>'
            f'<td class="num">{cnt:,}</td>'
            f'<td><div style="display:flex;align-items:center;gap:6px">'
            f'<div style="width:80px;background:#1e2535;border-radius:2px;height:4px">'
            f'<div style="background:{col};height:4px;border-radius:2px;width:{pct:.0f}%"></div></div>'
            f'<span class="muted">{pct:.1f}%</span></div></td>'
            f'<td class="num muted">{byt:,} B</td>'
            f'<td class="muted sm">{rfc}</td>'
            f'</tr>'
        )

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
    anom_html = ''.join(
        f'<div class="anom-row"><span class="anom-icon">⚠</span>{a}</div>' for a in anom
    ) or '<div class="ok-row"><span>✓</span><span>No anomalies detected — traffic looks normal</span></div>'

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

    # ── Dynamic stat cards ────────────────────────────────────────────────────────
    dyn_cards = ''
    for proto, cnt in sorted(pc.items(), key=lambda x:x[1], reverse=True):
        col = _proto_color(proto)
        rfc = RFC_REF.get(proto,'')
        byt = proto_bytes.get(proto,0)
        dyn_cards += (
            f'<div class="sc" style="--c:{col}">'
            f'<div class="sc-n">{cnt:,}</div>'
            f'<div class="sc-l">{proto}</div>'
            f'<div class="sc-sub"><span>Bytes: <b>{byt:,}</b></span>'
            f'{f"<span>{rfc}</span>" if rfc else ""}</div>'
            f'</div>'
        )

    # ── Packet table rows (first 1000) ────────────────────────────────────────────
    pkt_rows = ''
    for p in pkts[:1000]:
        col = _proto_color(p.get('proto',''))
        src = p.get('src_ip', p.get('src_mac','?'))
        dst = p.get('dst_ip', p.get('dst_mac','?'))
        if p.get('src_port'): src += f':{p["src_port"]}'
        if p.get('dst_port'): dst += f':{p["dst_port"]}'
        vlan = (f'<span class="badge sm" style="background:#1e2535;color:#a78bfa;margin-left:3px">V{p["vlan_id"]}</span>'
                if p.get('vlan_id') else '')
        flags = p.get('tcp_flags','') or p.get('arp_op','') or p.get('icmp_type_str','')
        fc = ('#10b981' if 'SYN' in str(flags) and 'ACK' not in str(flags)
              else '#ef4444' if 'RST' in str(flags)
              else '#f59e0b' if 'FIN' in str(flags) else '#94a3b8')
        pkt_rows += (
            f'<tr data-id="{p["id"]}" style="border-left:3px solid {col}" onclick="selPkt({p["id"]})">'
            f'<td class="muted">{p["id"]}</td>'
            f'<td style="color:#64748b;font-size:10px">{p.get("ts",0):.4f}</td>'
            f'<td><span class="badge" style="background:{col}">{p.get("proto","?")}</span>{vlan}</td>'
            f'<td class="mono sm c-acc">{src}</td>'
            f'<td class="muted" style="font-size:10px">→</td>'
            f'<td class="mono sm" style="color:#86efac">{dst}</td>'
            f'<td class="muted sm">{p.get("frame_len",0)}B</td>'
            f'<td style="color:{fc};font-size:10px;font-family:monospace">{flags}</td>'
            f'<td class="muted sm clip">{p.get("summary","")}</td>'
            f'</tr>'
        )

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
        f'<tr><td style="color:#10b981">Total Replies</td><td class="num" style="color:#10b981">{arp_reps_total}</td><td class="muted sm">X is at MAC Y</td></tr>',
        f'<tr><td style="color:#3b82f6">Complete Pairs</td><td class="num" style="color:#3b82f6">{len(arp_completed)}</td><td class="muted sm">REQ+REPLY seen</td></tr>',
        f'<tr><td style="color:#ef4444">Unanswered</td><td class="num" style="color:#ef4444">{len(arp_unanswered)}</td><td class="muted sm">Host may be down</td></tr>',
        f'<tr><td style="color:#f59e0b">Gratuitous</td><td class="num" style="color:#f59e0b">{len(arp_gratuitous)}</td><td class="muted sm">IP conflict?</td></tr>',
    ])

    # ── Extra protocol panels (beyond ARP/ICMP/TCP/UDP) ───────────────────────────
    KNOWN_TABS = {'ARP','ICMP','TCP','UDP'}
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

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetScope v3 — {fname}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&family=DM+Sans:wght@400;600;800&display=swap');
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#070d1a;--panel:#0d1525;--card:#111d30;--border:#1a2d44;
  --acc:#00d4ff;--acc2:#7c5cfc;--ok:#10b981;--warn:#f59e0b;--err:#ef4444;
  --text:#e2e8f0;--muted:#4a6080;
  --mono:'IBM Plex Mono',monospace;--sans:'DM Sans',sans-serif;
}}
html,body{{height:100%;overflow:hidden;background:var(--bg);color:var(--text);font-family:var(--sans);font-size:13px}}
::-webkit-scrollbar{{width:4px;height:4px}}
::-webkit-scrollbar-thumb{{background:#1e2d45;border-radius:2px}}
.mono{{font-family:var(--mono)}}
.sm{{font-size:11px}}
.muted{{color:var(--muted)}}
.num{{font-family:var(--mono);font-weight:700;text-align:right}}
.c-acc{{color:var(--acc)}}
.clip{{max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.empty{{color:var(--muted);padding:16px;font-size:12px}}

/* ── BADGE ── */
.badge{{display:inline-block;padding:1px 8px;border-radius:3px;font:700 10px var(--mono);color:#fff;white-space:nowrap}}

/* ── HEADER ── */
#hdr{{
  height:46px;background:var(--panel);border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:10px;padding:0 16px;flex-shrink:0;
}}
.logo{{
  width:30px;height:30px;border-radius:8px;
  background:linear-gradient(135deg,var(--acc),var(--acc2));
  display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0
}}
.brand{{font-size:14px;font-weight:800;letter-spacing:-.4px}}
.brand em{{color:var(--acc);font-style:normal}}
.brand sup{{font-size:8px;background:var(--ok);color:#000;padding:1px 4px;border-radius:3px;
  font-weight:700;vertical-align:top;margin-top:2px}}
.nav{{display:flex;gap:1px;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:2px;margin-left:8px}}
.nav-btn{{
  background:none;border:none;color:var(--muted);font:700 11px var(--sans);
  cursor:pointer;padding:5px 13px;border-radius:6px;transition:all .15s
}}
.nav-btn:hover{{color:var(--text)}}
.nav-btn.on{{background:var(--acc);color:#000;font-weight:800}}
.hchips{{display:flex;gap:6px;margin-left:auto;align-items:center}}
.chip{{
  background:var(--card);border:1px solid var(--border);
  padding:3px 10px;border-radius:12px;font:500 10px var(--mono);color:var(--muted)
}}
.chip.ok{{color:var(--ok);border-color:#10b98133}}
.chip.warn{{color:var(--warn);border-color:#f59e0b33}}

/* ── SHELL ── */
#app{{display:flex;height:calc(100vh - 46px)}}
#main{{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0}}
.view{{display:none;flex:1;flex-direction:column;min-height:0;overflow:hidden}}
.view.on{{display:flex}}
.scroll{{overflow-y:auto;flex:1;min-height:0;padding:12px;display:flex;flex-direction:column;gap:10px}}

/* ── SIDEBAR ── */
#sb{{
  width:320px;flex-shrink:0;border-left:1px solid var(--border);
  background:var(--panel);display:flex;flex-direction:column;overflow:hidden
}}
.sb-hdr{{
  padding:10px 14px;border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:8px;flex-shrink:0
}}
.sb-hdr h3{{font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.07em}}
.ai-chip{{
  font-size:9px;font-family:var(--mono);color:var(--muted);padding:2px 7px;
  background:var(--bg);border:1px solid var(--border);border-radius:8px;margin-left:auto
}}
.pulse{{width:6px;height:6px;border-radius:50%;background:var(--ok);animation:pulse 2s infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.3}}}}
#msgs{{flex:1;overflow-y:auto;padding:10px;display:flex;flex-direction:column;gap:7px;min-height:0}}
.msg{{padding:9px 12px;border-radius:8px;font-size:11px;line-height:1.7}}
.mu{{background:#0f1e3a;border:1px solid #1a3252;color:#93c5fd;align-self:flex-end;max-width:90%}}
.mb{{background:#080f1e;border:1px solid var(--border);align-self:flex-start;max-width:96%}}
.mb strong{{color:var(--acc)}}
.mb code{{background:#0d1829;padding:1px 4px;border-radius:3px;font-family:var(--mono);font-size:10px}}
.think{{
  background:#080f1e;border:1px solid var(--border);padding:9px 12px;
  border-radius:8px;font-size:11px;color:var(--muted);display:flex;gap:6px;align-items:center
}}
.dots span{{
  display:inline-block;width:3px;height:3px;background:var(--acc);
  border-radius:50%;animation:bop .7s infinite
}}
.dots span:nth-child(2){{animation-delay:.15s}}.dots span:nth-child(3){{animation-delay:.3s}}
@keyframes bop{{0%,100%{{transform:translateY(0)}}50%{{transform:translateY(-4px)}}}}
.qbtns{{padding:0 10px 7px;display:flex;flex-wrap:wrap;gap:4px;flex-shrink:0}}
.qb{{
  background:#0c1729;border:1px solid var(--border);color:#93c5fd;
  padding:4px 9px;border-radius:8px;font:600 10px var(--sans);cursor:pointer
}}
.qb:hover{{background:#0f1e3a;border-color:var(--acc)}}
.inp-row{{padding:8px 10px;border-top:1px solid var(--border);display:flex;gap:6px;flex-shrink:0}}
.inp{{
  flex:1;background:#0c1729;border:1px solid var(--border);border-radius:6px;
  padding:7px 10px;color:var(--text);font:500 11px var(--sans);outline:none;resize:none;height:36px
}}
.inp:focus{{border-color:var(--acc)}}
.sbtn{{
  background:linear-gradient(135deg,var(--acc),var(--acc2));border:none;
  border-radius:6px;padding:7px 13px;color:#000;font-weight:800;cursor:pointer;font-size:14px
}}

/* ── CARDS ── */
.card{{background:var(--card);border:1px solid var(--border);border-radius:9px;overflow:hidden}}
.ch{{
  padding:8px 13px;background:#0a1220;border-bottom:1px solid var(--border);
  font:700 10px var(--sans);text-transform:uppercase;letter-spacing:.08em;color:var(--acc);
  display:flex;align-items:center;gap:7px
}}
.ch .cnt{{
  background:var(--panel);border:1px solid var(--border);color:var(--muted);
  font:400 9px var(--mono);padding:1px 6px;border-radius:8px;margin-left:auto
}}
.cb{{padding:12px 13px}}
.row2{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}
.row3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px}}

/* ── TABLES ── */
table{{width:100%;border-collapse:collapse;font-size:11px}}
th{{
  background:#07101a;padding:6px 9px;text-align:left;font-size:9px;
  text-transform:uppercase;letter-spacing:.06em;color:var(--muted);
  position:sticky;top:0;z-index:2;border-bottom:1px solid var(--border)
}}
td{{padding:5px 9px;border-bottom:1px solid #080f1a;vertical-align:middle}}
tr:hover td{{background:#0e1e35;cursor:pointer}}
tr:last-child td{{border-bottom:none}}

/* ── STAT CARDS ── */
.stats-row{{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:8px}}
.sc{{
  background:var(--card);border:1px solid var(--border);border-radius:9px;
  padding:10px 12px;position:relative;overflow:hidden;cursor:pointer;transition:border-color .15s
}}
.sc:hover{{border-color:var(--c,var(--acc))}}
.sc::after{{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--c,var(--acc))}}
.sc-n{{font-size:22px;font-weight:800;font-family:var(--mono);color:var(--c,var(--acc))}}
.sc-l{{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;margin-top:2px}}
.sc-sub{{display:flex;flex-wrap:wrap;gap:6px;margin-top:4px;font-size:9px;color:var(--muted);font-family:var(--mono)}}
.sc-sub b{{color:var(--text)}}

/* ── IP BARS ── */
.ip-row{{display:flex;align-items:center;gap:7px;margin-bottom:6px}}
.ip-addr{{font-family:var(--mono);min-width:110px;font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.ip-track{{flex:1;height:5px;background:#0d1829;border-radius:3px;overflow:hidden}}
.ip-fill{{height:100%;border-radius:3px;transition:width .3s}}
.ip-cnt{{font-family:var(--mono);color:var(--muted);font-size:9px;min-width:24px;text-align:right}}

/* ── ANOMALIES ── */
.anom-row{{
  background:#1a0a0a;border:1px solid #ef444433;border-radius:7px;
  padding:9px 13px;display:flex;align-items:center;gap:9px;font-size:11px;
  color:#fca5a5;margin-bottom:7px
}}
.anom-icon{{color:#ef4444;font-size:16px;flex-shrink:0}}
.ok-row{{
  background:#0a1d12;border:1px solid #10b98133;border-radius:7px;
  padding:9px 13px;display:flex;align-items:center;gap:9px;font-size:12px;color:#6ee7b7
}}

/* ── SERVICE CARDS ── */
.svc-card{{
  background:#080f1e;border:1px solid var(--border);padding:7px 12px;
  border-radius:7px;min-width:80px
}}
.svc-name{{color:var(--acc);font-size:12px;font-weight:700}}
.svc-cnt{{color:var(--muted);font-size:10px;margin-top:2px}}

/* ── PACKETS VIEW ── */
.ws-bar{{
  padding:7px 12px;background:#07101a;border-bottom:1px solid var(--border);
  display:flex;gap:7px;align-items:center;flex-shrink:0;flex-wrap:wrap
}}
.ws-filter{{
  flex:1;min-width:200px;background:#0c1729;border:1px solid var(--border);
  border-radius:6px;padding:5px 10px;color:var(--text);font:400 11px var(--mono);outline:none
}}
.ws-filter:focus{{border-color:var(--acc)}}
.ws-fbtn{{
  background:#0d1829;border:1px solid var(--border);color:#94a3b8;
  padding:4px 10px;border-radius:6px;font:600 10px var(--sans);cursor:pointer
}}
.ws-fbtn:hover{{border-color:var(--acc);color:var(--acc)}}
#ptw{{flex:1;overflow-y:auto;min-height:0}}
#pt{{width:100%;border-collapse:collapse;font-size:11px;font-family:var(--mono)}}
#pt th{{
  background:#06101d;padding:5px 8px;text-align:left;font-size:9px;text-transform:uppercase;
  letter-spacing:.06em;color:var(--muted);position:sticky;top:0;z-index:5;
  border-bottom:2px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap
}}
#pt th:hover{{color:var(--acc)}}
#pt td{{padding:4px 8px;border-bottom:1px solid #070e1a;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:200px}}
#pt tr{{cursor:pointer}}
#pt tr:hover td{{background:#0e1e35}}
#pt tr.sel td{{background:#102a40!important;outline-left:3px solid var(--acc)}}

/* ── DETAIL PANE ── */
#dpane{{flex-shrink:0;border-top:1px solid var(--border);display:flex;flex-direction:column}}
#dresz{{height:4px;background:var(--border);cursor:row-resize}}
#dresz:hover{{background:var(--acc)}}
#dtabs{{
  display:flex;background:#06101d;border-bottom:1px solid var(--border);
  flex-shrink:0;padding:0 12px
}}
.dtab{{
  padding:6px 14px;background:none;border:none;color:var(--muted);
  font:700 10px var(--sans);cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px
}}
.dtab:hover{{color:var(--text)}}
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
  background:#0d1829;border:1px solid var(--border);color:#64748b;
  padding:2px 8px;border-radius:6px;font:700 9px var(--sans);cursor:pointer;transition:all .15s
}}
.tl-btn:hover,.tl-btn.on{{color:#fff;border-color:var(--c,var(--acc));background:#0f1e35}}
#tl-sel{{display:none;margin-top:6px;background:#0d1829;border:1px solid var(--border);border-radius:5px;padding:6px 10px;font:400 10px var(--mono);color:var(--text)}}

/* ── PROTOCOLS EXTRA TABS ── */
.ptab-bar{{
  display:flex;gap:5px;flex-wrap:wrap;padding:8px 12px;background:#07101a;
  border-bottom:1px solid var(--border);flex-shrink:0
}}
.ptab{{
  background:#0c1729;border:1px solid var(--border);color:#94a3b8;
  padding:4px 10px;border-radius:6px;font:700 10px var(--sans);cursor:pointer;transition:all .15s
}}
.ptab:hover{{border-color:var(--c,var(--acc));color:var(--c,var(--acc))}}
.ptab.on{{background:var(--c,var(--acc));color:#000;border-color:var(--c,var(--acc))}}
.pcnt{{
  display:inline-block;background:#1e2d45;color:#94a3b8;
  font-family:var(--mono);font-size:9px;padding:0 5px;border-radius:8px;margin-left:4px
}}
/* ── EXPORT BUTTONS ── */
.exp-btn{{
  background:#0d1829;border:1px solid var(--border);color:#94a3b8;
  padding:3px 9px;border-radius:6px;font:600 9px var(--sans);cursor:pointer;
  text-decoration:none;display:inline-flex;align-items:center;gap:3px;transition:all .15s
}}
.exp-btn:hover{{border-color:var(--acc);color:var(--acc)}}

/* ── TERMINAL ── */
#term-out .t-err{{color:#f87171}}
#term-out .t-sys{{color:#4a6080}}
.ppanel{{display:none;overflow-y:auto;max-height:350px}}
</style>
</head>
<body>

<!-- ═══ HEADER ═══ -->
<div id="hdr">
  <div class="logo">🔬</div>
  <div class="brand">Net<em>Scope</em> <sup>v3</sup></div>
  <nav class="nav">
    <button class="nav-btn on"  id="nb-dashboard" onclick="goView('dashboard',this)">Dashboard</button>
    <button class="nav-btn"     id="nb-protocols" onclick="goView('protocols',this)">Protocols</button>
    <button class="nav-btn"     id="nb-packets"   onclick="goView('packets',this)">Packets</button>
    <button class="nav-btn"     id="nb-terminal"  onclick="goView('terminal',this)">Terminal</button>
  </nav>
  <div class="hchips">
    <span class="chip">📁 {fname}</span>
    <span class="chip">📦 {total:,} pkts</span>
    <span class="chip ok">✓ {switch_info}</span>
    {f'<span class="chip warn">⚠ {len(anom)} anomal{"y" if len(anom)==1 else "ies"}</span>' if anom else ''}
    <div style="display:flex;gap:4px;margin-left:4px">
      <a href="/export/json" class="exp-btn" title="Export JSON">⬇ JSON</a>
      <a href="/export/csv"  class="exp-btn" title="Export CSV">⬇ CSV</a>
      <a href="/export/pcap" class="exp-btn" title="Download PCAP">⬇ PCAP</a>
    </div>
  </div>
</div>

<!-- ═══ APP SHELL ═══ -->
<div id="app">
<div id="main">

<!-- ═══ DASHBOARD ═══ -->
<div id="view-dashboard" class="view on">
<div class="scroll">

  <div class="stats-row">
    <div class="sc" style="--c:var(--acc)" onclick="goView('packets',document.getElementById('nb-packets'))">
      <div class="sc-n">{total:,}</div>
      <div class="sc-l">Total Packets</div>
      <div class="sc-sub"><span>Bytes: <b>{total_bytes:,}</b></span></div>
    </div>
    {dyn_cards}
    <div class="sc" style="--c:{'#ef4444' if anom else '#10b981'}">
      <div class="sc-n" style="font-size:18px">{"⚠ "+str(len(anom)) if anom else "✓"}</div>
      <div class="sc-l">Anomalies</div>
      <div class="sc-sub"><span>{"Detected" if anom else "None found"}</span></div>
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
    <div class="ch">
      ARP Exchange
      <span style="color:var(--warn);font-size:10px;font-weight:400;margin-left:6px">▲{arp_reqs_total} Req</span>
      <span style="color:var(--ok);font-size:10px;font-weight:400;margin-left:4px">▼{arp_reps_total} Reply</span>
      <span style="color:#3b82f6;font-size:10px;font-weight:400;margin-left:4px">⇆{len(arp_completed)} Complete</span>
      <span style="color:var(--err);font-size:10px;font-weight:400;margin-left:4px">✗{len(arp_unanswered)} Unanswered</span>
    </div>
    <div style="overflow-x:auto;max-height:220px;overflow-y:auto">{arp_pair_table}</div>
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
      <div style="height:175px;position:relative;overflow:hidden"><canvas id="tl-cv"></canvas></div>
      <div class="sm muted" style="margin-top:4px;text-align:right">scroll=zoom · drag=pan · click=inspect</div>
      <div id="tl-sel"></div>
    </div>
  </div>

</div><!-- /scroll -->
</div><!-- /view-dashboard -->

<!-- ═══ PROTOCOLS ═══ -->
<div id="view-protocols" class="view">
<div class="scroll">

  <div class="card">
    <div class="ch">Protocol Statistics <span class="cnt">{len(pc)} protocols</span></div>
    <div style="overflow-y:auto;max-height:280px">
      <table><thead><tr><th>Protocol</th><th>Count</th><th>Share</th><th>Bytes</th><th>RFC / Standard</th></tr></thead>
      <tbody>{proto_stat_rows}</tbody></table>
    </div>
  </div>

  <div class="row2">
    <div class="card">
      <div class="ch">TCP Flags <span class="cnt">{len(tcp)} pkts</span></div>
      <div class="cb">
        <table><thead><tr><th>Flag</th><th>Count</th><th>Meaning</th></tr></thead>
        <tbody>{tcp_flag_rows}</tbody></table>
      </div>
    </div>
    <div class="card">
      <div class="ch">ICMP Types <span class="cnt">{len(icmp)} pkts</span></div>
      <div class="cb">
        <table><thead><tr><th>Type</th><th>Count</th><th>Dir</th></tr></thead>
        <tbody>{icmp_rows}</tbody></table>
      </div>
    </div>
  </div>

  <div class="row2">
    <div class="card">
      <div class="ch">ARP Analysis</div>
      <div class="cb">
        <table><thead><tr><th>Metric</th><th>Value</th><th>Notes</th></tr></thead>
        <tbody>{arp_analysis_rows}</tbody></table>
      </div>
    </div>
    <div class="card">
      <div class="ch">Services <span class="cnt">{len(svcs)}</span></div>
      <div class="cb">
        <table><thead><tr><th>Service</th><th>Packets</th><th>Share</th></tr></thead>
        <tbody>{svc_rows}</tbody></table>
      </div>
    </div>
  </div>

</div><!-- /scroll -->
{(f'<div class="ptab-bar" id="ptab-bar">' + extra_tabs_html + '</div>' + extra_panels_html) if extra_tabs_html else ''}
</div><!-- /view-protocols -->

<!-- ═══ PACKETS ═══ -->
<div id="view-packets" class="view" style="flex-direction:column">

  <div class="ws-bar">
    <input class="ws-filter" id="pf" type="text" placeholder="Filter: tcp  ip 10.x  port 443  flags RST  vlan 10  mac aa:bb" oninput="applyFilter()">
    <button class="ws-fbtn" onclick="clearFilter()">Clear</button>
    {proto_qbtns}
  </div>

  <div id="ptw">
    <table id="pt">
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
      <tbody id="ptb"></tbody>
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
        <button onclick="askPkt()" style="background:linear-gradient(135deg,var(--acc),var(--acc2));border:none;border-radius:6px;padding:8px 18px;color:#000;font:700 11px var(--sans);cursor:pointer;margin-bottom:8px">🤖 Ask AI — full RFC explanation of selected packet</button>
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

</div><!-- #main -->

<!-- ═══ SIDEBAR ═══ -->
<div id="sb">
  <div class="sb-hdr">
    <div class="pulse"></div>
    <h3>AI Protocol Analyst</h3>
    <span class="ai-chip">{ai_model}</span>
  </div>
  <div id="msgs">
    <div class="msg mb">
      Analysed <strong>{total:,} packets</strong> from <strong>{fname}</strong>.<br><br>
      <table style="font-size:10px">
        <tr><td style="color:var(--warn)">ARP</td><td class="num">{len(arp)}</td><td class="muted">Req:{arp_reqs_total} Rep:{arp_reps_total}</td></tr>
        <tr><td style="color:#ef4444">ICMP</td><td class="num">{len(icmp)}</td><td class="muted">Req:{icmp_req} Rep:{icmp_rep}</td></tr>
        <tr><td style="color:#3b82f6">TCP</td><td class="num">{len(tcp)}</td><td class="muted">SYN:{tcp_syn} RST:{tcp_rst}</td></tr>
        <tr><td style="color:var(--ok)">UDP</td><td class="num">{len(udp)}</td><td class="muted">Svcs:{len(svcs)}</td></tr>
      </table>
      {('<br><span style="color:#fca5a5">⚠ '+str(len(anom))+' anomal'+('y' if len(anom)==1 else 'ies')+' detected!</span>') if anom else ''}
      <br>Click any packet row → inspect → Ask AI for RFC breakdown.
    </div>
  </div>
  <div class="qbtns">
    <button class="qb" onclick="ask('Give a complete stats summary table of all protocols: count, bytes, requests vs replies')">📊 Stats</button>
    <button class="qb" onclick="ask('Explain all ARP packets with RFC 826 detail and exchange analysis')">ARP</button>
    <button class="qb" onclick="ask('Explain ICMP: RFC 792, type/code meanings, troubleshooting')">ICMP</button>
    <button class="qb" onclick="ask('Explain TCP sessions: SYN/ACK/RST/FIN, connection states, RFC 793')">TCP</button>
    <button class="qb" onclick="ask('What services are visible? Risk assessment for open ports')">Services</button>
    <button class="qb" onclick="ask('Any security threats? Port scans, floods, RST storms, gratuitous ARP?')">Security</button>
    <button class="qb" onclick="ask('Give a complete network engineering report with recommendations')">Full Report</button>
    <button class="qb" onclick="ask('What troubleshooting steps would you recommend based on this capture?')">Troubleshoot</button>
  </div>
  <div class="inp-row">
    <textarea class="inp" id="inp" placeholder="Ask about protocols, RFCs, analysis..."
      onkeydown="if(event.key==='Enter'&&!event.shiftKey){{event.preventDefault();send();}}"></textarea>
    <button class="sbtn" onclick="send()">▶</button>
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
const CTX={ctx_js};

// ═══════════════════════════════════════════════════════════════
//  COLOR MAP
// ═══════════════════════════════════════════════════════════════
const CMAP={{ARP:'#f59e0b',ICMP:'#ef4444',TCP:'#3b82f6',UDP:'#10b981',
  LLDP:'#8b5cf6',IPv6:'#06b6d4',EAPoL:'#f97316',IGMP:'#ec4899',
  RARP:'#fb923c',STP:'#84cc16',OSPF:'#38bdf8',BGP:'#818cf8',
  DNS:'#fbbf24',DHCP:'#4ade80',NTP:'#a3e635',SSH:'#60a5fa'}};
const FALL=['#00e5ff','#7c5cfc','#ff6b6b','#ffd93d','#6bcb77','#4d96ff','#ff9a3c','#c77dff'];
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
function buildTimeline(filter){{
  if(tlChart){{tlChart.destroy();tlChart=null;}}
  const canvas=document.getElementById('tl-cv');
  if(!canvas)return;
  const ctx=canvas.getContext('2d');
  const PAD={{l:48,r:14,t:10,b:34}};
  const byProto={{}};
  TL_DATA.forEach(p=>{{
    const pr=filter==='ALL'?p.proto:(p.proto===filter?p.proto:null);
    if(!pr)return;
    if(!byProto[pr])byProto[pr]=[];
    byProto[pr].push({{x:p.x,y:p.y,id:p.id,src:p.src,dst:p.dst}});
  }});
  const datasets=Object.entries(byProto).map(([proto,pts])=>{{return{{label:proto,data:pts,col:pc(proto)}};}} );
  const allPts=datasets.flatMap(d=>d.data);
  let minX=allPts.length?Math.min(...allPts.map(p=>p.x)):0;
  let maxX=allPts.length?Math.max(...allPts.map(p=>p.x)):1;
  let maxY=allPts.length?Math.max(...allPts.map(p=>p.y)):1;
  if(maxX===minX)maxX=minX+1;if(maxY===0)maxY=1;
  let vx=[minX,maxX],drag=false,ds=null,dvx=null,tip=null;
  function resize(){{canvas.width=canvas.parentElement.clientWidth||600;canvas.height=canvas.parentElement.clientHeight||175;}}
  function px(x){{return PAD.l+(x-vx[0])/(vx[1]-vx[0])*(canvas.width-PAD.l-PAD.r);}}
  function py(y){{return PAD.t+(canvas.height-PAD.t-PAD.b)*(1-y/(maxY*1.1));}}
  function draw(){{
    const W=canvas.width,H=canvas.height;ctx.clearRect(0,0,W,H);
    ctx.strokeStyle='#1e2d45';ctx.lineWidth=1;
    for(let i=0;i<=4;i++){{const y=PAD.t+(H-PAD.t-PAD.b)*i/4;ctx.beginPath();ctx.moveTo(PAD.l,y);ctx.lineTo(W-PAD.r,y);ctx.stroke();const v=maxY*1.1*(1-i/4);ctx.fillStyle='#4a6080';ctx.font='8px IBM Plex Mono,monospace';ctx.textAlign='right';ctx.textBaseline='middle';ctx.fillText(v.toFixed(0),PAD.l-3,y);}}
    for(let i=0;i<=5;i++){{const x=PAD.l+(W-PAD.l-PAD.r)*i/5;ctx.beginPath();ctx.moveTo(x,PAD.t);ctx.lineTo(x,H-PAD.b);ctx.stroke();const v=vx[0]+(vx[1]-vx[0])*i/5;ctx.fillStyle='#4a6080';ctx.font='8px IBM Plex Mono,monospace';ctx.textAlign='center';ctx.textBaseline='top';ctx.fillText(v.toFixed(3)+'s',x,H-PAD.b+3);}}
    ctx.fillStyle='#4a6080';ctx.font='9px DM Sans,sans-serif';ctx.textAlign='center';ctx.textBaseline='bottom';ctx.fillText('Time (s)',W/2,H-1);
    ctx.save();ctx.translate(10,H/2);ctx.rotate(-Math.PI/2);ctx.fillText('Bytes',0,0);ctx.restore();
    datasets.forEach(d=>{{ctx.fillStyle=d.col+'cc';d.data.forEach(p=>{{const x2=px(p.x),y2=py(p.y);if(x2<PAD.l||x2>W-PAD.r||y2<PAD.t||y2>H-PAD.b)return;ctx.beginPath();ctx.arc(x2,y2,3,0,Math.PI*2);ctx.fill();}});}});
    if(tip){{const{{x:tx,y:ty,text}}=tip;const lines=text.split('\\n'),lh=14,tw=170,th=lines.length*lh+10;let ox=tx+8,oy=ty-th-4;if(ox+tw>W-PAD.r)ox=tx-tw-8;if(oy<PAD.t)oy=ty+4;ctx.fillStyle='#0b1628';ctx.strokeStyle='#1e2d45';ctx.lineWidth=1;ctx.beginPath();if(ctx.roundRect)ctx.roundRect(ox,oy,tw,th,4);else ctx.rect(ox,oy,tw,th);ctx.fill();ctx.stroke();ctx.fillStyle='#e2e8f0';ctx.font='9px IBM Plex Mono,monospace';ctx.textAlign='left';ctx.textBaseline='top';lines.forEach((l,i)=>ctx.fillText(l,ox+6,oy+5+i*lh));}}
    let lgX=PAD.l+4,lgY=PAD.t+4;datasets.forEach(d=>{{ctx.fillStyle=d.col;ctx.fillRect(lgX,lgY,7,7);ctx.fillStyle='#64748b';ctx.font='8px DM Sans,sans-serif';ctx.textAlign='left';ctx.textBaseline='top';const lbl=d.label+'('+d.data.length+')';ctx.fillText(lbl,lgX+10,lgY);lgX+=ctx.measureText(lbl).width+22;if(lgX>W-60){{lgX=PAD.l+4;lgY+=12;}}}});
  }}
  canvas.style.cursor='crosshair';
  canvas.addEventListener('mousemove',e=>{{
    const rect=canvas.getBoundingClientRect();const mx=(e.clientX-rect.left)*(canvas.width/rect.width),my=(e.clientY-rect.top)*(canvas.height/rect.height);
    if(drag&&ds){{const dx=(mx-ds.x)/(canvas.width-PAD.l-PAD.r)*(dvx[1]-dvx[0]);vx=[dvx[0]-dx,dvx[1]-dx];tip=null;draw();return;}}
    let best=null,bestD=15;
    datasets.forEach(d=>d.data.forEach(p=>{{const dx=px(p.x)-mx,dy=py(p.y)-my,dd=Math.sqrt(dx*dx+dy*dy);if(dd<bestD){{bestD=dd;best={{p,d,x:px(p.x),y:py(p.y)}};}}}}));
    if(best){{tip={{x:best.x,y:best.y,text:'Pkt #'+best.p.id+' '+best.d.label+'\\n'+best.p.src+' → '+best.p.dst+'\\n'+best.p.y+'B  t='+best.p.x.toFixed(4)+'s'}};canvas.style.cursor='pointer';canvas.onclick=()=>selPkt(best.p.id);}}else{{tip=null;canvas.style.cursor='crosshair';canvas.onclick=null;}}
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
function goView(name,btn){{
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('on'));
  if(btn)btn.classList.add('on');
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('on'));
  const el=document.getElementById('view-'+name);
  if(el)el.classList.add('on');
  if(name==='dashboard'){{
    requestAnimationFrame(()=>requestAnimationFrame(()=>{{
      if(donutChart)donutChart.destroy();
      buildDonut();
      if(!tlChart)buildTimeline('ALL');
    }}));
  }}
  if(name==='packets'){{renderTable();}}
  if(name==='protocols'){{
    const bar=document.getElementById('ptab-bar');
    if(bar){{
      const first=bar.querySelector('.ptab');
      const anyVis=[...document.querySelectorAll('.ppanel')].some(p=>p.style.display==='block');
      if(first&&!anyVis){{const pid=first.getAttribute('data-panel');if(pid)ptab(first,pid);}}
    }}
  }}
  if(name==='terminal'){{
    termConnect();
    setTimeout(()=>{{const inp=document.getElementById('term-inp');if(inp)inp.focus();}},100);
  }}
}}

// ═══════════════════════════════════════════════════════════════
//  PACKET TABLE
// ═══════════════════════════════════════════════════════════════
let sortKey='id',sortDir=1,filterStr='',curId=null;

function renderTable(){{
  let pkts=Object.values(ALL_PKTS);
  if(filterStr){{
    const f=filterStr.toLowerCase().trim();
    const fv=f.split(' ',2);
    pkts=pkts.filter(p=>{{
      if(fv.length<2)return(p.proto||'').toLowerCase().startsWith(f)||JSON.stringify(p).toLowerCase().includes(f);
      const [k,v]=fv;
      if(k==='ip')return(p.src_ip||'').includes(v)||(p.dst_ip||'').includes(v);
      if(k==='port')return String(p.src_port)===v||String(p.dst_port)===v;
      if(k==='mac')return(p.src_mac||'').includes(v)||(p.dst_mac||'').includes(v);
      if(k==='vlan')return String(p.vlan_id||'')===v;
      if(k==='flags')return(p.tcp_flags||'').toUpperCase().includes(v.toUpperCase());
      if(k==='proto')return(p.proto||'').toLowerCase()===v;
      return JSON.stringify(p).toLowerCase().includes(f);
    }});
  }}
  pkts.sort((a,b)=>{{
    let av=sortKey==='id'?a.id:sortKey==='ts'?a.ts:sortKey==='proto'?a.proto:sortKey==='src'?(a.src_ip||''):sortKey==='dst'?(a.dst_ip||''):sortKey==='len'?a.frame_len:a.id;
    let bv=sortKey==='id'?b.id:sortKey==='ts'?b.ts:sortKey==='proto'?b.proto:sortKey==='src'?(b.src_ip||''):sortKey==='dst'?(b.dst_ip||''):sortKey==='len'?b.frame_len:b.id;
    return av<bv?-sortDir:av>bv?sortDir:0;
  }});
  const tbody=document.getElementById('ptb');
  tbody.innerHTML='';
  pkts.forEach(p=>{{
    const col=pc(p.proto);
    const src=(p.src_ip||p.src_mac||'?')+(p.src_port?':'+p.src_port:'');
    const dst=(p.dst_ip||p.dst_mac||'?')+(p.dst_port?':'+p.dst_port:'');
    const flags=p.tcp_flags||p.arp_op||p.icmp_type_str||'';
    const fc=flags.includes('SYN')&&!flags.includes('ACK')?'#10b981':flags.includes('RST')?'#ef4444':flags.includes('FIN')?'#f59e0b':'#94a3b8';
    const tr=document.createElement('tr');
    tr.dataset.id=p.id;tr.style.borderLeft='3px solid '+col;
    tr.innerHTML=
      `<td class="muted">${{p.id}}</td>`+
      `<td class="muted" style="font-size:10px">${{p.ts.toFixed(4)}}</td>`+
      `<td><span class="badge" style="background:${{col}}">${{p.proto}}</span></td>`+
      `<td style="color:#93c5fd;font-family:var(--mono);font-size:11px">${{src}}</td>`+
      `<td class="muted" style="font-size:10px">→</td>`+
      `<td style="color:#86efac;font-family:var(--mono);font-size:11px">${{dst}}</td>`+
      `<td class="muted" style="font-size:10px">${{p.frame_len}}B</td>`+
      `<td style="color:${{fc}};font-size:10px;font-family:monospace">${{flags}}</td>`+
      `<td class="muted" style="font-size:10px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${{(p.summary||'').replace(/"/g,"'")}}">${{p.summary||''}}</td>`;
    tr.onclick=()=>selPkt(p.id);
    tbody.appendChild(tr);
  }});
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
  // highlight row
  document.querySelectorAll('#pt tr').forEach(r=>r.classList.remove('sel'));
  const row=document.querySelector('#pt tr[data-id="'+id+'"]');
  if(row){{row.classList.add('sel');row.scrollIntoView({{block:'nearest'}});}}
  const sum=['Pkt #'+p.id,' · ',p.proto,' · ',p.frame_len+'B',' · ','t='+p.ts+'s'];
  if(p.src_ip)sum.push('  '+p.src_ip+' → '+(p.dst_ip||'?'));
  if(p.service)sum.push('  ['+p.service+']');
  document.getElementById('dsum').textContent=sum.join('');
  buildTree(p);buildHex(p);
  document.getElementById('ai-resp').textContent='';
  const tabs=document.querySelectorAll('.dtab');
  if(tabs.length)dtab(tabs[0],'dtree');
}}

function buildTree(p){{
  const wrap=document.getElementById('dtree');wrap.innerHTML='';
  (p.layers||[]).forEach(layer=>{{
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
function addThink(){{
  const box=document.getElementById('msgs');
  const d=document.createElement('div');d.className='think';
  d.innerHTML='Analysing<div class="dots"><span></span><span></span><span></span></div>';
  box.appendChild(d);box.scrollTop=box.scrollHeight;return d;
}}
async function send(){{
  const el=document.getElementById('inp');const q=el.value.trim();if(!q)return;
  el.value='';addMsg(q,true);const th=addThink();
  try{{
    const r=await fetch('/api/chat',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{prompt:'Context:\\n'+JSON.stringify(CTX)+'\\n\\nQuestion: '+q}})}});
    const d=await r.json();th.remove();addMsg(d.response||d.error||'No response',false);
  }}catch(e){{th.remove();addMsg('Error: '+e.message,false);}}
}}
function ask(q){{document.getElementById('inp').value=q;send();}}

// ═══════════════════════════════════════════════════════════════
//  INIT
// ═══════════════════════════════════════════════════════════════
window.addEventListener('load',()=>{{
  renderTable();
  goView('dashboard',document.querySelector('.nav-btn'));
  // Build charts on next animation frame so canvas has layout dimensions
  requestAnimationFrame(()=>requestAnimationFrame(()=>{{
    buildDonut();
    buildTimeline('ALL');
  }}));
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

</script>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
#  HTTP SERVER
# ═══════════════════════════════════════════════════════════════════════════════

ANALYSIS_DATA = {}

# ── Terminal session manager ──────────────────────────────────────────────────

# ── WebSocket handshake helpers ───────────────────────────────────────────────

import hashlib, base64 as _b64

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
            return

        if path in ('/', '/index.html'):
            try:
                html = make_html(
                    ANALYSIS_DATA['analysis'],
                    ANALYSIS_DATA['fname'],
                    ANALYSIS_DATA.get('switch_ip'),
                ).encode('utf-8')
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
            resp = ask_ai(body.get('prompt', ''))
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'response': resp}).encode())
        else:
            self.send_response(404); self.end_headers()

    # ── Terminal WebSocket handler ────────────────────────────────────────────

    def _handle_terminal_ws(self):
        """Each WebSocket connection gets its own bash PTY."""
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
            _default_ip = switch_ip or ''
            try:
                with open(connect_sh, 'w') as _f:
                    _f.write(
                        "#!/bin/bash\n"
                        "# NetScope SSH helper\n"
                        "# Usage:  connect [IP [user]]\n"
                        "_IP=\"${1:-" + _default_ip + "}\"\n"
                        "_U=\"${2:-admin}\"\n"
                        "if [ -z \"$_IP\" ]; then echo 'Usage: connect <IP> [user]'; exit 1; fi\n"
                        "echo \"[NetScope] Connecting to $_U@$_IP ...\"\n"
                        "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 \"$_U@$_IP\"\n"
                        "echo \"[NetScope] Disconnected from $_IP.\"\n"
                        "echo \"[NetScope] Type  connect <IP>  to SSH into another device.\"\n"
                    )
                import stat as _stat
                os.chmod(connect_sh, _stat.S_IRWXU | _stat.S_IRGRP | _stat.S_IXGRP)
            except Exception:
                connect_sh = None

            # ── Build bashrc ──────────────────────────────────────────────────
            rc_lines = [
                "export PS1='\\u@\\h:\\W\\$ '\n",
            ]
            if connect_sh:
                rc_lines.append(f"alias connect='{connect_sh}'\n")
            rc_lines.append("echo ''\n")

            if switch_ip:
                rc_lines += [
                    "echo '  ╔══════════════════════════════════════╗'\n",
                    "echo '  ║      NetScope Terminal               ║'\n",
                    "echo '  ╚══════════════════════════════════════╝'\n",
                    f"echo '  Connecting to {sw_user}@{switch_ip} ...'\n",
                    "echo '  Tip:  exit              — return to local shell'\n",
                    "echo '  Tip:  connect <IP>      — SSH into any other device'\n",
                    "echo '  Tip:  connect <IP> user — SSH as a specific user'\n",
                    "echo ''\n",
                    f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 {sw_user}@{switch_ip}\n",
                    # After SSH exits — show one clean message then go silent
                    # Turn off PS1 so bash stops printing the prompt repeatedly
                    "echo ''\n",
                    f"echo '[NetScope] Disconnected from {switch_ip}.'\n",
                    "echo '[NetScope] Type  connect <IP>  to connect to another device.'\n",
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
                    "echo '  Type  connect <IP> [user]  to SSH into a network device'\n",
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
        import fcntl
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
                except OSError:
                    break
            alive.clear()

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
#  CLI + MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def parse_args():
    ap = argparse.ArgumentParser(description='AI PCAP Protocol Analyser — Dashboard v3')
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument('--pcap',      metavar='FILE')
    grp.add_argument('--switch',    metavar='IP')
    ap.add_argument('--user',       metavar='USER',  default='admin')
    ap.add_argument('--password',   metavar='PASS',  default='')
    ap.add_argument('--sw-port',    metavar='PORT',  default='1')
    ap.add_argument('--vlan',       metavar='VLAN',  default='default')
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
    return ap.parse_args()


def main():
    print()
    print('+' + '='*62 + '+')
    print('|' + '  AI PCAP PROTOCOL ANALYSER — Dashboard v3'.center(62) + '|')
    print('|' + '  Zero-dependency dashboard | Works with any PCAP'.center(62) + '|')
    print('+' + '='*62 + '+')

    args = parse_args()
    global OLLAMA_MODEL, AI_BACKEND, CLAUDE_API_KEY, CLAUDE_MODEL, OPENAI_API_KEY
    OLLAMA_MODEL   = args.model
    AI_BACKEND     = args.ai
    CLAUDE_API_KEY = args.claude_key
    CLAUDE_MODEL   = args.claude_model
    OPENAI_API_KEY = args.openai_key

    if args.switch:
        # Try to import from parent project, otherwise error
        try:
            from capmain12_fixed import capture_from_switch as _cap
            pcap = _cap(args.switch, args.user, args.password,
                        args.duration, args.sw_port, args.vlan)
        except ImportError:
            try:
                from main_1 import capture_from_switch as _cap
                pcap = _cap(args.switch, args.user, args.password,
                            args.duration, args.sw_port, args.vlan)
            except ImportError:
                _die(['Could not import capture_from_switch.',
                      'Run with --pcap <file> or copy this file next to main_1.py'])
    else:
        pcap = args.pcap
        if not Path(pcap).exists():
            _die([f'File not found: {pcap}'])
        _step('STEP 1 — Loading PCAP File')
        print(f'  File: {pcap}  ({os.path.getsize(pcap):,} bytes)')

    _step('STEP 2 — Parsing Packets')
    raw     = read_pcap(pcap)
    print(f'  Raw records : {len(raw)}')
    packets = parse_all(raw)
    print(f'  Parsed      : {len(packets)}')

    _step('STEP 3 — Analysis')
    analysis = analyse(packets)
    for proto, cnt in sorted(analysis['proto_counts'].items(), key=lambda x:x[1], reverse=True):
        rfc = RFC_REF.get(proto,'')
        bar = '#' * min(cnt, 35)
        print(f'  {proto:<18} {cnt:>5}  {bar}  {rfc}')

    _step('STEP 4 — Anomalies')
    for a in analysis['anomalies']: print(f'  ⚠ {a}')
    if not analysis['anomalies']: print('  ✓ None detected')

    _step('STEP 5 — Starting Dashboard v4')
    global ANALYSIS_DATA
    ANALYSIS_DATA = {'analysis': analysis, 'fname': pcap,
                     'switch_ip': args.switch if args.switch else None,
                     'switch_user': args.user, 'switch_pass': args.password}

    ai_model_str = (CLAUDE_MODEL if AI_BACKEND=='claude' else
                    'gpt-4o'     if AI_BACKEND=='openai' else OLLAMA_MODEL)

    port = _free_port(args.web_port)
    url  = f'http://localhost:{port}'
    from http.server import ThreadingHTTPServer
    srv  = ThreadingHTTPServer(('', port), Handler)
    srv.allow_reuse_address = True

    print(f'\n  Dashboard   : {url}')
    print(f'  AI Backend  : {AI_BACKEND}  ({ai_model_str})')
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
