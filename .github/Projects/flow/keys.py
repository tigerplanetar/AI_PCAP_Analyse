"""
flow/keys.py — Flow Key Computation
=====================================
Bidirectional, normalised flow keys for L2, L3, and L4 granularity.

Used by flow/engine.py to assign every packet to exactly one flow,
mirroring the Wireshark "conversation" concept.

Public API
----------
    from flow.keys import l2_key, l3_key, l4_key, base_proto

    key = l4_key(pkt)   # 5-tuple, or None if ports not present
    key = l3_key(pkt)   # IP pair + proto, or None if IPs missing
    key = l2_key(pkt)   # MAC pair + VLAN — always succeeds

Design notes
------------
- All keys are bidirectional: (A→B) and (B→A) produce the same key by
  normalising the two endpoints so the lexicographically smaller one is
  always first.  This matches Wireshark behaviour.
- VLAN ID is included in the L2 key so conversations on different VLANs
  are kept separate even if MACs are identical.
- l4_key() uses _base_proto() so HTTP, HTTPS, SSH etc. all group under
  the same 'TCP' transport bucket, avoiding per-service key fragmentation.
"""

from __future__ import annotations
from typing import Optional


# ── Application → transport base protocol map ─────────────────────────────────

_TCP_APPS: frozenset[str] = frozenset({
    'HTTP', 'HTTPS', 'HTTP-Alt', 'HTTPS-Alt',
    'SSH', 'Telnet', 'FTP', 'FTP-Data',
    'SMTP', 'SMTPS', 'POP3', 'POP3S',
    'IMAP', 'IMAPS', 'LDAP', 'LDAPS',
    'SMB', 'NetBIOS-SSN', 'RDP', 'SIP', 'SIPS',
    'MSSQL', 'Oracle', 'MySQL', 'PostgreSQL',
    'MongoDB', 'Redis', 'VNC', 'Kerberos', 'BGP',
})

_UDP_APPS: frozenset[str] = frozenset({
    'DNS', 'DHCP-Server', 'DHCP-Client', 'TFTP',
    'NBNS', 'NetBIOS-DGM', 'NTP', 'SNMP', 'SNMP-Trap',
    'Syslog', 'RIP', 'OpenVPN', 'RTP',
    'SIP', 'RADIUS-Auth', 'RADIUS-Acct', 'RADIUS-CoA',
    'VXLAN',
})


def base_proto(proto: str) -> str:
    """
    Return the transport-layer base for an application protocol name.

    HTTP → 'TCP', DNS → 'UDP', ICMP → 'ICMP', etc.
    Preserves the original string for unknown protocols.
    """
    if proto in _TCP_APPS:
        return 'TCP'
    if proto in _UDP_APPS:
        return 'UDP'
    return proto


# ── Key functions ─────────────────────────────────────────────────────────────

def l4_key(pkt: dict) -> Optional[tuple]:
    """
    5-tuple bidirectional flow key for TCP/UDP sessions.

    Returns:
        ('L4', lo_ip, lo_port, hi_ip, hi_port, base_proto_str)
        or None if src_ip / dst_ip / src_port / dst_port are missing.

    The (lo, hi) normalisation ensures (A:1234→B:80) and (B:80→A:1234)
    map to the same key.
    """
    src_ip   = pkt.get('src_ip',   '')
    dst_ip   = pkt.get('dst_ip',   '')
    src_port = pkt.get('src_port')
    dst_port = pkt.get('dst_port')

    if not src_ip or not dst_ip or src_port is None or dst_port is None:
        return None

    proto  = base_proto(pkt.get('proto', ''))
    ep_src = (src_ip, int(src_port))
    ep_dst = (dst_ip, int(dst_port))
    lo, hi = (ep_src, ep_dst) if ep_src <= ep_dst else (ep_dst, ep_src)
    return ('L4', lo[0], lo[1], hi[0], hi[1], proto)


def l3_key(pkt: dict) -> Optional[tuple]:
    """
    IP-pair + protocol key for ICMP, IGMP, and other IP traffic without ports.

    Returns:
        ('L3', lo_ip, hi_ip, base_proto_str)
        or None if src_ip / dst_ip are missing.
    """
    src_ip = pkt.get('src_ip', '')
    dst_ip = pkt.get('dst_ip', '')
    if not src_ip or not dst_ip:
        return None

    proto = base_proto(pkt.get('proto', ''))
    lo, hi = (src_ip, dst_ip) if src_ip <= dst_ip else (dst_ip, src_ip)
    return ('L3', lo, hi, proto)


def l3_key_directed(pkt: dict) -> Optional[tuple]:
    """
    Directed L3 key — src and dst are NOT normalised.

    Used for DHCP and multicast protocols where direction matters for
    correct request/response grouping.
    """
    src_ip = pkt.get('src_ip', '')
    dst_ip = pkt.get('dst_ip', '')
    if not src_ip or not dst_ip:
        return None
    proto = base_proto(pkt.get('proto', ''))
    return ('L3D', src_ip, dst_ip, proto)


def l2_key(pkt: dict) -> tuple:
    """
    MAC-pair + VLAN bidirectional key for ARP, LLDP and unknown EtherTypes.

    Always returns a valid key (falls back to empty strings if MACs absent).
    """
    src = pkt.get('src_mac', '')
    dst = pkt.get('dst_mac', '')
    vlan = pkt.get('vlan_id')   # None means untagged
    lo, hi = (src, dst) if src <= dst else (dst, src)
    return ('L2', lo, hi, vlan)


def packet_direction(pkt: dict, flow_src_ip: str, flow_src_port: int = 0) -> str:
    """
    Determine if *pkt* is travelling in the forward or reverse direction
    relative to the first packet that created the flow.

    Returns 'fwd' or 'rev'.
    """
    if pkt.get('src_ip', '') == flow_src_ip:
        if flow_src_port == 0 or pkt.get('src_port', 0) == flow_src_port:
            return 'fwd'
    return 'rev'
