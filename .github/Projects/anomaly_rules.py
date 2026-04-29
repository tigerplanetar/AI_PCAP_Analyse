"""
anomaly_rules.py — Extended Anomaly Detection Rules
=====================================================
Supplementary rule set for the AI PCAP Analyzer anomaly engine.

This module extends the existing _rule_engine() in AI_PCAP_new_Apr27.py
with additional L2–L7 detection rules without modifying existing logic.

Design
------
- All functions return lists of finding dicts compatible with the
  existing anomaly finding schema in AI_PCAP_new_Apr27.py
- Safe to call independently or merge with existing rule_engine output
- No external dependencies

Integration
-----------
    from anomaly_rules import run_extended_rules
    extra_findings = run_extended_rules(packets, analysis, features)
    # Merge with existing findings:
    all_findings = existing_findings + extra_findings

Finding schema (mirrors existing _rule_engine output):
    {
        'category': str,     # e.g. 'L2:Loop', 'L7:DNS'
        'layer':    str,     # 'L2' | 'L3' | 'L4' | 'L5L6' | 'L7'
        'title':    str,     # short description shown in UI
        'severity': str,     # 'critical' | 'high' | 'medium' | 'low' | 'info'
        'detail':   str,     # explanation in plain English
        'evidence': str,     # supporting statistics
        'protocol': str,     # affected protocol
        'rfc_ref':  str,     # RFC reference
    }
"""

from __future__ import annotations
from collections import defaultdict
from typing import Any


# ── Severity constants (match main script) ────────────────────────────────────
SEV_CRITICAL = 'critical'
SEV_HIGH     = 'high'
SEV_MEDIUM   = 'medium'
SEV_LOW      = 'low'
SEV_INFO     = 'info'


# ── Rule: ARP Extended Analysis ───────────────────────────────────────────────

def _rule_arp_extended(packets: list, analysis: dict) -> list:
    findings = []
    arp_pkts  = [p for p in packets if p.get('proto') == 'ARP']
    if not arp_pkts:
        return findings

    total       = len(packets)
    arp_count   = len(arp_pkts)
    arp_pct     = arp_count / max(total, 1) * 100

    # Duration
    ts_list = [p.get('ts', 0) for p in packets]
    duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 1.0
    arp_rate = arp_count / max(duration, 0.001)

    # ARP flood: > 50 ARP/s is suspicious
    if arp_rate > 50:
        findings.append({
            'category': 'L2:ARP', 'layer': 'L2',
            'title': f'ARP flood: {arp_rate:.0f}/s ({arp_count} packets)',
            'severity': SEV_HIGH,
            'detail': ('Extremely high ARP request rate. Possible causes: '
                       'broadcast storm, misconfigured device, or network reconnaissance. '
                       'ARP flood can degrade switch performance by exhausting ARP tables.'),
            'evidence': f'arp_count={arp_count} rate={arp_rate:.0f}/s duration={duration:.1f}s',
            'protocol': 'ARP', 'rfc_ref': 'RFC 826',
        })
    elif arp_rate > 10:
        findings.append({
            'category': 'L2:ARP', 'layer': 'L2',
            'title': f'Elevated ARP rate: {arp_rate:.1f}/s',
            'severity': SEV_MEDIUM,
            'detail': 'ARP rate is above normal. May indicate network instability or a scanning host.',
            'evidence': f'arp_count={arp_count} rate={arp_rate:.1f}/s',
            'protocol': 'ARP', 'rfc_ref': 'RFC 826',
        })

    # High ARP percentage
    if arp_pct > 40 and total > 50:
        findings.append({
            'category': 'L2:ARP', 'layer': 'L2',
            'title': f'Dominant ARP traffic: {arp_pct:.0f}% of capture',
            'severity': SEV_MEDIUM,
            'detail': ('ARP constitutes an unusually high proportion of traffic. '
                       'Normal networks rarely exceed 5-10% ARP. '
                       'This may indicate a broadcast storm, misconfigured host, or IP conflict.'),
            'evidence': f'arp={arp_count} total={total} pct={arp_pct:.1f}%',
            'protocol': 'ARP', 'rfc_ref': 'RFC 826',
        })

    # IP conflict: two MACs claiming same IP
    ip_mac_map: dict[str, set] = defaultdict(set)
    for p in arp_pkts:
        if p.get('arp_op') == 'REPLY':
            ip  = p.get('src_ip', '')
            mac = p.get('arp_src_mac', '')
            if ip and mac:
                ip_mac_map[ip].add(mac)
    conflicts = {ip: macs for ip, macs in ip_mac_map.items() if len(macs) > 1}
    if conflicts:
        for ip, macs in conflicts.items():
            findings.append({
                'category': 'L2:ARP', 'layer': 'L2',
                'title': f'ARP IP conflict: {ip} claimed by {len(macs)} MACs',
                'severity': SEV_CRITICAL,
                'detail': (f'IP address {ip} is being claimed by multiple MAC addresses: '
                           f'{", ".join(sorted(macs))}. '
                           'This indicates an IP address conflict or ARP spoofing/poisoning attack. '
                           'Hosts may experience intermittent connectivity. '
                           'EXOS: show arp | grep <ip> to investigate.'),
                'evidence': f'ip={ip} macs={sorted(macs)}',
                'protocol': 'ARP', 'rfc_ref': 'RFC 826',
            })

    return findings


# ── Rule: DHCP Extended Analysis ─────────────────────────────────────────────

def _rule_dhcp_extended(packets: list, analysis: dict) -> list:
    findings = []
    dhcp_pkts = [p for p in packets
                 if p.get('proto') in ('DHCP', 'DHCP-Server', 'DHCP-Client')]
    if not dhcp_pkts:
        return findings

    # Count by message type
    msg_types: dict[str, int] = defaultdict(int)
    server_ips: set[str] = set()
    client_macs: set[str] = set()

    for p in dhcp_pkts:
        mt = p.get('dhcp_msg_type', '')
        if mt:
            msg_types[mt] += 1
        # Offers come from server (src_port=67)
        if p.get('src_port') == 67:
            server_ips.add(p.get('src_ip', ''))
        client_macs.add(p.get('src_mac', ''))

    server_ips.discard('')
    client_macs.discard('')

    # Multiple DHCP servers
    if len(server_ips) > 1:
        findings.append({
            'category': 'L7:DHCP', 'layer': 'L7',
            'title': f'Multiple DHCP servers detected: {len(server_ips)}',
            'severity': SEV_HIGH,
            'detail': (f'More than one DHCP server is responding on this segment: '
                       f'{", ".join(sorted(server_ips))}. '
                       'Clients may receive conflicting IP assignments. '
                       'Only one authoritative DHCP server should exist per subnet. '
                       'EXOS: configure dhcp-server to identify rogue servers.'),
            'evidence': f'servers={sorted(server_ips)}',
            'protocol': 'DHCP', 'rfc_ref': 'RFC 2131',
        })

    # DHCP starvation pattern
    discover_count = msg_types.get('DHCP Discover', 0)
    ack_count = msg_types.get('DHCP ACK', 0)
    if discover_count > 20 and ack_count < discover_count * 0.3:
        findings.append({
            'category': 'L7:DHCP', 'layer': 'L7',
            'title': f'DHCP starvation pattern: {discover_count} Discovers, {ack_count} ACKs',
            'severity': SEV_HIGH,
            'detail': ('Many DHCP Discover messages without corresponding ACKs. '
                       'This may indicate DHCP pool exhaustion, starvation attack, '
                       'or misconfigured clients. DHCP starvation can prevent legitimate '
                       'hosts from obtaining IP addresses.'),
            'evidence': f'discovers={discover_count} acks={ack_count} clients={len(client_macs)}',
            'protocol': 'DHCP', 'rfc_ref': 'RFC 2131',
        })

    # DHCP NAK storm
    nak_count = msg_types.get('DHCP NAK', 0)
    if nak_count > 5:
        findings.append({
            'category': 'L7:DHCP', 'layer': 'L7',
            'title': f'DHCP NAK storm: {nak_count} rejections',
            'severity': SEV_MEDIUM,
            'detail': ('Server is rejecting many DHCP requests (NAK). '
                       'Clients may be requesting IPs from a different subnet (VLAN misconfiguration) '
                       'or the IP pool has no available addresses.'),
            'evidence': f'naks={nak_count} msg_types={dict(msg_types)}',
            'protocol': 'DHCP', 'rfc_ref': 'RFC 2131',
        })

    return findings


# ── Rule: DNS Extended Analysis ───────────────────────────────────────────────

def _rule_dns_extended(packets: list, analysis: dict) -> list:
    findings = []
    dns_pkts = [p for p in packets if p.get('proto') == 'DNS']
    if len(dns_pkts) < 5:
        return findings

    ts_list  = [p.get('ts', 0) for p in packets]
    duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 1.0

    query_names: dict[str, int] = defaultdict(int)
    nxdomain_names: set[str]    = set()
    response_times: list[float] = []
    dns_servers: set[str]       = set()

    req_map: dict[int, float] = {}   # txid → timestamp

    for p in dns_pkts:
        name = p.get('dns_query', '')
        if name:
            query_names[name] += 1
        txid = p.get('dns_txid')
        qr   = p.get('dns_qr', '')
        if txid is not None:
            if qr == 'Query':
                req_map[txid] = p.get('ts', 0)
            elif qr == 'Response' and txid in req_map:
                rtt = p.get('ts', 0) - req_map.pop(txid)
                if 0 < rtt < 10:
                    response_times.append(rtt)
        if p.get('src_port') == 53:
            dns_servers.add(p.get('src_ip', ''))

    dns_servers.discard('')

    # High-entropy domain names (DNS tunneling indicator)
    suspicious_names = []
    for name, count in query_names.items():
        labels = [l for l in name.split('.') if l]
        for label in labels:
            if len(label) > 30:
                chars = set(label.lower())
                entropy = len(chars) / len(label)
                if entropy > 0.65:
                    suspicious_names.append((name, entropy, count))

    if suspicious_names:
        top_name, top_entropy, top_count = sorted(suspicious_names, key=lambda x: x[1], reverse=True)[0]
        findings.append({
            'category': 'L7:DNS', 'layer': 'L7',
            'title': f'DNS tunneling indicator: high-entropy subdomain',
            'severity': SEV_HIGH,
            'detail': (f'DNS query "{top_name}" has unusually high label entropy ({top_entropy:.2f}). '
                       'Long random-looking subdomains are a hallmark of DNS tunneling (data exfiltration '
                       'or C2 communication encoded in DNS). '
                       'Reference: RFC 1035 §2.3.1 — labels are typically readable hostnames.'),
            'evidence': f'name="{top_name}" entropy={top_entropy:.2f} count={top_count}',
            'protocol': 'DNS', 'rfc_ref': 'RFC 1035',
        })

    # NX domain storm
    unanswered_queries = len(req_map)   # queries with no matching response
    if unanswered_queries > 20:
        findings.append({
            'category': 'L7:DNS', 'layer': 'L7',
            'title': f'DNS unanswered queries: {unanswered_queries} without responses',
            'severity': SEV_MEDIUM,
            'detail': ('Many DNS queries have no matching responses. '
                       'Possible causes: DNS server unreachable, high query rate, '
                       'or DGA (Domain Generation Algorithm) malware cycling through many fake domains.'),
            'evidence': f'unanswered={unanswered_queries} total_queries={len(dns_pkts)}',
            'protocol': 'DNS', 'rfc_ref': 'RFC 1035',
        })

    # High DNS query rate
    dns_rate = len(dns_pkts) / max(duration, 0.001)
    if dns_rate > 20:
        findings.append({
            'category': 'L7:DNS', 'layer': 'L7',
            'title': f'High DNS query rate: {dns_rate:.0f}/s',
            'severity': SEV_MEDIUM,
            'detail': (f'DNS rate of {dns_rate:.0f}/s is abnormally high. '
                       'Normal hosts make a few DNS lookups per minute. '
                       'High rates may indicate malware, misconfigured application, or DNS tunneling.'),
            'evidence': f'dns_pkts={len(dns_pkts)} duration={duration:.1f}s rate={dns_rate:.0f}/s',
            'protocol': 'DNS', 'rfc_ref': 'RFC 1035',
        })

    # Slow DNS responses
    if response_times and sum(response_times) / len(response_times) > 0.5:
        avg_ms = sum(response_times) / len(response_times) * 1000
        findings.append({
            'category': 'L7:DNS', 'layer': 'L7',
            'title': f'Slow DNS responses: avg {avg_ms:.0f}ms',
            'severity': SEV_LOW,
            'detail': (f'Average DNS response time of {avg_ms:.0f}ms is above the typical <50ms. '
                       'Slow DNS can cause user-visible application delays. '
                       'Check DNS server load and network path.'),
            'evidence': f'avg_rtt={avg_ms:.0f}ms samples={len(response_times)}',
            'protocol': 'DNS', 'rfc_ref': 'RFC 1035',
        })

    return findings


# ── Rule: SNMP Security Analysis ─────────────────────────────────────────────

def _rule_snmp_extended(packets: list, analysis: dict) -> list:
    findings = []
    snmp_pkts = [p for p in packets if p.get('proto') in ('SNMP', 'SNMP-Trap')]
    if not snmp_pkts:
        return findings

    trap_pkts = [p for p in snmp_pkts if p.get('proto') == 'SNMP-Trap']
    set_pkts  = [p for p in snmp_pkts
                 if 'SetRequest' in p.get('summary', '') or '3 (SetRequest)' in p.get('summary', '')]
    sources: set[str] = set(p.get('src_ip', '') for p in snmp_pkts)
    sources.discard('')

    ts_list  = [p.get('ts', 0) for p in packets]
    duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 1.0

    # Trap storm
    if len(trap_pkts) > 10:
        trap_rate = len(trap_pkts) / max(duration, 0.001)
        findings.append({
            'category': 'L7:SNMP', 'layer': 'L7',
            'title': f'SNMP Trap storm: {len(trap_pkts)} traps ({trap_rate:.1f}/s)',
            'severity': SEV_HIGH if len(trap_pkts) > 50 else SEV_MEDIUM,
            'detail': ('High rate of SNMP traps indicates device instability or an alarm condition. '
                       'Check managed devices for errors, link failures, or hardware issues. '
                       'EXOS: show snmp trap to review trap configuration.'),
            'evidence': f'traps={len(trap_pkts)} rate={trap_rate:.1f}/s sources={sorted(sources)}',
            'protocol': 'SNMP-Trap', 'rfc_ref': 'RFC 3411',
        })

    # SNMP Set requests (configuration change attempts)
    if set_pkts:
        set_sources = set(p.get('src_ip', '') for p in set_pkts)
        findings.append({
            'category': 'L7:SNMP', 'layer': 'L7',
            'title': f'SNMP SetRequest detected: {len(set_pkts)} config change attempts',
            'severity': SEV_HIGH,
            'detail': ('SNMP SetRequest messages modify device configuration. '
                       'This is normal for NMS systems, but unexpected SetRequests may indicate '
                       'unauthorized device management. Verify these sources are authorised NMS systems.'),
            'evidence': f'set_requests={len(set_pkts)} sources={sorted(set_sources)}',
            'protocol': 'SNMP', 'rfc_ref': 'RFC 3411',
        })

    # Wide SNMP polling (many sources polling = unusual)
    if len(sources) > 3:
        findings.append({
            'category': 'L7:SNMP', 'layer': 'L7',
            'title': f'Multiple SNMP managers: {len(sources)} sources',
            'severity': SEV_LOW,
            'detail': (f'SNMP traffic from {len(sources)} different sources detected. '
                       f'Sources: {", ".join(sorted(sources))}. '
                       'Multiple NMS systems polling the same device can cause excessive load. '
                       'Verify all sources are authorised management systems.'),
            'evidence': f'sources={sorted(sources)} count={len(sources)}',
            'protocol': 'SNMP', 'rfc_ref': 'RFC 3411',
        })

    return findings


# ── Rule: TCP Session Quality ─────────────────────────────────────────────────

def _rule_tcp_quality(packets: list, analysis: dict) -> list:
    findings = []
    tcp_pkts = [p for p in packets
                if p.get('proto') in ('TCP',) or (p.get('src_port') and p.get('dst_port')
                                                   and p.get('tcp_flags'))]
    if len(tcp_pkts) < 10:
        return findings

    ts_list  = [p.get('ts', 0) for p in packets]
    duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 1.0

    # Zero-window segments
    zero_win = [p for p in tcp_pkts if p.get('tcp_window', 1) == 0]
    if len(zero_win) > 5:
        findings.append({
            'category': 'L4:TCP', 'layer': 'L4',
            'title': f'TCP Zero Window: {len(zero_win)} segments — receiver buffer full',
            'severity': SEV_MEDIUM,
            'detail': ('Zero window size means the receiver\'s buffer is full and cannot accept more data. '
                       'This causes the sender to pause, leading to performance degradation. '
                       'Causes: slow application reading, memory pressure, or mismatched speeds. '
                       'RFC 793 §3.7: Window size controls flow control.'),
            'evidence': f'zero_window_count={len(zero_win)} total_tcp={len(tcp_pkts)}',
            'protocol': 'TCP', 'rfc_ref': 'RFC 793',
        })

    # Null scan: no flags set
    null_scan = [p for p in tcp_pkts if p.get('tcp_flags', 'NONE') == 'NONE']
    if null_scan:
        null_sources = set(p.get('src_ip', '') for p in null_scan)
        findings.append({
            'category': 'L4:TCP', 'layer': 'L4',
            'title': f'TCP Null scan: {len(null_scan)} segments with no flags',
            'severity': SEV_HIGH,
            'detail': ('TCP segments with no flags set (Null scan) are invalid per RFC 793. '
                       'They are used by port scanners (e.g., nmap -sN) to probe firewalls '
                       'and detect open ports by observing RST responses. '
                       'Sources: ' + ', '.join(sorted(null_sources))),
            'evidence': f'null_pkts={len(null_scan)} sources={sorted(null_sources)}',
            'protocol': 'TCP', 'rfc_ref': 'RFC 793',
        })

    # Xmas scan: FIN+URG+PSH all set
    xmas_scan = [p for p in tcp_pkts
                 if all(f in p.get('tcp_flags', '') for f in ('FIN', 'URG', 'PSH'))]
    if xmas_scan:
        xmas_sources = set(p.get('src_ip', '') for p in xmas_scan)
        findings.append({
            'category': 'L4:TCP', 'layer': 'L4',
            'title': f'TCP Xmas scan: {len(xmas_scan)} segments (FIN+URG+PSH)',
            'severity': SEV_HIGH,
            'detail': ('FIN+URG+PSH flags combination is the "Xmas scan" technique. '
                       'Like Null scans, these are used for stealth port scanning. '
                       'No legitimate application sets all three flags simultaneously.'),
            'evidence': f'xmas_pkts={len(xmas_scan)} sources={sorted(xmas_sources)}',
            'protocol': 'TCP', 'rfc_ref': 'RFC 793',
        })

    # RST injection detection (RST from unexpected source)
    rst_pkts = [p for p in tcp_pkts if 'RST' in p.get('tcp_flags', '')]
    if len(rst_pkts) > 10:
        rst_rate = len(rst_pkts) / max(duration, 0.001)
        if rst_rate > 5:
            findings.append({
                'category': 'L4:TCP', 'layer': 'L4',
                'title': f'TCP RST storm: {rst_rate:.1f} RST/s ({len(rst_pkts)} total)',
                'severity': SEV_HIGH,
                'detail': ('High TCP RST rate indicates connections being forcefully terminated. '
                           'Causes: service rejecting connections, firewall blocking, '
                           'or RST injection attack (spoofed RSTs to terminate legitimate sessions). '
                           'RFC 793 §3.4: RST should only be sent when a segment arrives for a closed port.'),
                'evidence': f'rst_count={len(rst_pkts)} rate={rst_rate:.1f}/s duration={duration:.1f}s',
                'protocol': 'TCP', 'rfc_ref': 'RFC 793',
            })

    return findings


# ── Rule: Unknown Protocol Analysis ──────────────────────────────────────────

def _rule_unknown_protos(packets: list, analysis: dict) -> list:
    findings = []
    unknown_pkts = [p for p in packets
                    if p.get('proto', '').startswith('ET-') or p.get('proto', '') in ('?', '')]
    if not unknown_pkts:
        return findings

    # Group by EtherType
    et_groups: dict[str, int] = defaultdict(int)
    et_macs: dict[str, set]   = defaultdict(set)
    for p in unknown_pkts:
        et = p.get('proto', 'ET-unknown')
        et_groups[et] += 1
        et_macs[et].add(p.get('src_mac', ''))

    total = len(packets)
    for et, count in sorted(et_groups.items(), key=lambda x: x[1], reverse=True)[:5]:
        pct = count / max(total, 1) * 100
        sources = sorted(et_macs[et] - {''})
        sev = SEV_MEDIUM if pct > 5 else SEV_LOW

        et_hex = et.replace('ET-', '') if et.startswith('ET-') else 'unknown'
        findings.append({
            'category': 'L2:Unknown', 'layer': 'L2',
            'title': f'Unknown protocol {et}: {count} packets ({pct:.1f}%)',
            'severity': sev,
            'detail': (f'EtherType {et_hex} is not a registered standard protocol. '
                       f'May be a vendor-proprietary protocol (e.g., Extreme Networks, Cisco CDP/VTP). '
                       f'Sources: {", ".join(sources[:5])}. '
                       'Use Wireshark with vendor protocol dissectors for identification. '
                       'If sourced from EXOS switches, review EXOS proprietary frame documentation.'),
            'evidence': f'count={count} pct={pct:.1f}% et={et_hex} sources={sources[:3]}',
            'protocol': et, 'rfc_ref': '',
        })

    return findings


# ── Rule: LLDP Topology Analysis ──────────────────────────────────────────────

def _rule_lldp_topology(packets: list, analysis: dict) -> list:
    findings = []
    lldp_pkts = [p for p in packets if p.get('proto') == 'LLDP']
    if len(lldp_pkts) < 2:
        return findings

    ts_list  = [p.get('ts', 0) for p in packets]
    duration = max(ts_list) - min(ts_list) if len(ts_list) > 1 else 1.0
    lldp_rate = len(lldp_pkts) / max(duration, 0.001)

    advertisers: dict[str, list] = defaultdict(list)   # src_mac → list of ts
    neighbor_names: dict[str, str] = {}

    for p in lldp_pkts:
        src = p.get('src_mac', '')
        if src:
            advertisers[src].append(p.get('ts', 0))
        name = p.get('lldp_system_name', '')
        if src and name:
            neighbor_names[src] = name

    # LLDP storm: rapid advertising
    if lldp_rate > 2:
        findings.append({
            'category': 'L2:LLDP', 'layer': 'L2',
            'title': f'LLDP storm: {lldp_rate:.1f}/s ({len(lldp_pkts)} packets)',
            'severity': SEV_MEDIUM,
            'detail': ('LLDP should be sent once every 30s per IEEE 802.1AB. '
                       f'Rate of {lldp_rate:.1f}/s is abnormally high, indicating topology instability, '
                       'a misconfigured device, or possible LLDP flood attack.'),
            'evidence': f'rate={lldp_rate:.1f}/s count={len(lldp_pkts)} duration={duration:.1f}s',
            'protocol': 'LLDP', 'rfc_ref': 'IEEE 802.1AB',
        })

    # Multiple advertisers on same segment (informational)
    if len(advertisers) > 5:
        names = [f'{mac} ({neighbor_names.get(mac, "?")})'
                 for mac in sorted(advertisers.keys())[:6]]
        findings.append({
            'category': 'L2:LLDP', 'layer': 'L2',
            'title': f'LLDP: {len(advertisers)} neighbors discovered',
            'severity': SEV_INFO,
            'detail': 'Multiple LLDP-capable devices detected on this segment.',
            'evidence': f'neighbors={len(advertisers)} examples={names[:3]}',
            'protocol': 'LLDP', 'rfc_ref': 'IEEE 802.1AB',
        })

    return findings


# ── Rule: VLAN Traffic Analysis ───────────────────────────────────────────────

def _rule_vlan_analysis(packets: list, analysis: dict) -> list:
    findings = []
    vlan_pkts = [p for p in packets if p.get('vlan_id') is not None]
    if not vlan_pkts:
        return findings

    vlans: set = set(p['vlan_id'] for p in vlan_pkts)
    untagged_pkts = [p for p in packets if p.get('vlan_id') is None and
                     p.get('src_ip')]   # IP traffic without VLAN tag

    # Mixed tagged/untagged on same port
    if vlans and untagged_pkts:
        findings.append({
            'category': 'L2:VLAN', 'layer': 'L2',
            'title': f'Mixed tagged/untagged traffic: VLANs {sorted(vlans)[:5]}',
            'severity': SEV_INFO,
            'detail': ('Both 802.1Q-tagged and untagged frames are present. '
                       'This is normal on trunk/hybrid ports but unexpected on pure access ports. '
                       'Verify EXOS port VLAN configuration matches expected topology.'),
            'evidence': f'vlans={sorted(vlans)[:5]} untagged_ip_pkts={len(untagged_pkts)}',
            'protocol': 'VLAN', 'rfc_ref': 'IEEE 802.1Q',
        })

    # Large number of VLANs
    if len(vlans) > 20:
        findings.append({
            'category': 'L2:VLAN', 'layer': 'L2',
            'title': f'High VLAN count: {len(vlans)} VLANs observed',
            'severity': SEV_INFO,
            'detail': (f'{len(vlans)} different VLAN IDs seen in this capture. '
                       'This is expected on trunk ports. '
                       'Verify all VLANs are intentional — stale or rogue VLANs may indicate misconfiguration.'),
            'evidence': f'vlans={sorted(vlans)[:10]}{"…" if len(vlans) > 10 else ""}',
            'protocol': 'VLAN', 'rfc_ref': 'IEEE 802.1Q',
        })

    return findings


# ── Main entry point ──────────────────────────────────────────────────────────

def run_extended_rules(packets: list, analysis: dict,
                       features: dict = None) -> list:
    """
    Run all extended anomaly detection rules.
    Returns list of finding dicts compatible with the main anomaly engine.

    Usage:
        from anomaly_rules import run_extended_rules
        extra = run_extended_rules(packets, analysis, features)
        all_findings = existing_findings + extra
    """
    all_findings: list = []
    features = features or {}

    rule_functions = [
        _rule_arp_extended,
        _rule_dhcp_extended,
        _rule_dns_extended,
        _rule_snmp_extended,
        _rule_tcp_quality,
        _rule_unknown_protos,
        _rule_lldp_topology,
        _rule_vlan_analysis,
    ]

    for rule_fn in rule_functions:
        try:
            findings = rule_fn(packets, analysis)
            all_findings.extend(findings)
        except Exception as e:
            # Never let a rule crash the whole engine
            all_findings.append({
                'category': 'System', 'layer': 'META',
                'title': f'Rule {rule_fn.__name__} failed',
                'severity': SEV_INFO,
                'detail': f'Internal error in extended rule: {e}',
                'evidence': str(e),
                'protocol': '', 'rfc_ref': '',
            })

    # Sort by severity
    _sev_order = {SEV_CRITICAL: 5, SEV_HIGH: 4, SEV_MEDIUM: 3, SEV_LOW: 2, SEV_INFO: 1}
    all_findings.sort(key=lambda f: _sev_order.get(f.get('severity', 'info'), 0), reverse=True)
    return all_findings


def merge_findings(existing: list, extended: list) -> list:
    """
    Merge existing rule findings with extended findings, deduplicating
    by title to avoid double-reporting the same issue.
    """
    existing_titles = {f.get('title', '') for f in existing}
    unique_extended = [f for f in extended if f.get('title', '') not in existing_titles]
    return existing + unique_extended
