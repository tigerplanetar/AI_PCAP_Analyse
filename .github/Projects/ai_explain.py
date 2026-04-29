"""
ai_explain.py — Rich Human-Readable Protocol Explanations
==========================================================
Extends ai_summaries.py with deeper, narrative-style explanations.

While ai_summaries.py handles structured summaries and AI prompt building,
this module focuses on:
  - Narrating TCP handshakes step-by-step from packet sequences
  - Explaining ARP conversations end-to-end
  - Producing conversation prose (not just summaries)
  - Verbose anomaly explanations with root cause and remediation
  - Best-effort analysis for completely unknown protocols

Public API
----------
    from ai_explain import (
        explain_tcp_session,        # Full TCP session narrative
        explain_arp_exchange,       # ARP request/reply narrative
        explain_udp_conversation,   # UDP conversation narrative
        explain_anomaly,            # Verbose anomaly explanation
        explain_unknown_protocol,   # Unknown EtherType / protocol
        explain_retransmissions,    # TCP retransmission narrative
        ConversationNarrator,       # Class: narrates any flow dict
        capture_health_summary,     # Overall capture health assessment
    )

Integration with AI_PCAP_new_Apr27.py
--------------------------------------
    from ai_explain import ConversationNarrator, capture_health_summary

    narrator = ConversationNarrator(packets, analysis)

    # Per-flow narrative in the dashboard detail panel:
    narrative = narrator.narrate(flow_dict)

    # Capture health block for the AI prompt:
    health = capture_health_summary(analysis)

Design notes
------------
- Never raises — all functions return strings, even for empty/bad inputs.
- Explanations are written for mixed audiences (engineers and beginners).
- Technical terms are always followed by a plain-English parenthetical
  on first use within a narrative.
- EXOS CLI commands are included wherever a remediation applies.
"""

from __future__ import annotations
from typing import Optional


# ── Shared constants ──────────────────────────────────────────────────────────

# Known EtherTypes for unknown-protocol heuristics
_KNOWN_ETHERTYPES: dict[int, str] = {
    0x0800: 'IPv4',        0x0806: 'ARP',        0x8100: '802.1Q VLAN',
    0x86DD: 'IPv6',        0x88CC: 'LLDP',       0x888E: 'EAPoL (802.1X)',
    0x8863: 'PPPoE Disc',  0x8864: 'PPPoE Sess', 0x8847: 'MPLS Unicast',
    0x8848: 'MPLS Mcast',  0x88E7: 'PBB',        0x88F7: 'PTP (IEEE 1588)',
    0x88B5: 'Extreme Networks Local',
    0x88B6: 'Extreme Networks Remote',
    0x88B7: 'Extreme Networks EDP',
    0x9100: 'QinQ (double VLAN)',
    0x8902: 'CFM / OAM',   0x8906: 'FCoE',
    0x8914: 'FCoE Init',   0x22F3: 'TRILL',
    0x6558: 'Trans Ether Bridging',
}

# OUI prefixes → vendor (first 3 bytes of MAC)
_OUI_VENDORS: dict[str, str] = {
    '00:00:0c': 'Cisco',         '00:1b:17': 'Cisco',
    '00:04:96': 'Extreme Networks', '00:e0:2b': 'Extreme Networks',
    '00:19:30': 'Extreme Networks', '08:00:27': 'VirtualBox',
    '00:0c:29': 'VMware',        '00:50:56': 'VMware',
    '52:54:00': 'QEMU/KVM',      '00:1a:4b': 'Juniper Networks',
    'f4:8e:38': 'Arista Networks','00:0b:86': 'Aruba Networks',
}

# TCP state → plain-English transition label
_TCP_TRANSITIONS: dict[str, str] = {
    'SYN only':       'Step 1 — Client is requesting a new connection.',
    'SYN+ACK':        'Step 2 — Server accepted the connection request.',
    'ACK after SYN':  'Step 3 — Client confirmed. The 3-way handshake is complete.',
    'PSH+ACK':        'Data transfer — both sides are exchanging application data.',
    'FIN only':       'Graceful close started — one side has finished sending data.',
    'FIN+ACK':        'Graceful close confirmed — both sides acknowledge the end.',
    'RST':            'Abrupt reset — the connection was forcibly terminated.',
    'RST+ACK':        'Abrupt reset with acknowledgment — the peer acknowledged and terminated.',
}

# Anomaly severity → impact description
_SEVERITY_IMPACT: dict[str, str] = {
    'critical': 'This may cause immediate service disruption or represents a security breach.',
    'high':     'This is likely affecting network performance or security.',
    'medium':   'This could indicate a configuration issue or intermittent problem.',
    'low':      'This is worth investigating but may not be causing visible problems.',
    'info':     'This is informational — normal protocol behavior or minor observation.',
}


# ── TCP session explanation ───────────────────────────────────────────────────

def explain_tcp_session(flow: dict, related_packets: Optional[list] = None) -> str:
    """
    Narrate a TCP session from start to finish in plain English.

    Parameters
    ----------
    flow : dict
        FlowRecord.to_dict() output from the flow engine.
    related_packets : list, optional
        Packet dicts belonging to this flow (from pkt_ids lookup).
        When provided, the handshake packets are identified by sequence.

    Returns
    -------
    Multi-paragraph narrative string.
    """
    src_ip   = flow.get('src_ip', '?')
    dst_ip   = flow.get('dst_ip', '?')
    src_port = flow.get('src_port', 0)
    dst_port = flow.get('dst_port', 0)
    proto    = flow.get('app_proto') or flow.get('proto', 'TCP')
    pkts     = flow.get('pkt_count', 0)
    dur_ms   = flow.get('duration_ms', 0)
    state    = flow.get('tcp_state', '')
    retx     = flow.get('retransmissions', 0)
    dup_acks = flow.get('dup_acks', 0)
    zero_win = flow.get('zero_windows', 0)
    syn      = flow.get('tcp_syn', 0)
    synack   = flow.get('tcp_synack', 0)
    fin      = flow.get('tcp_fin', 0)
    rst      = flow.get('tcp_rst', 0)
    is_one_way  = flow.get('is_one_way', False)
    is_complete = flow.get('is_complete', False)
    has_errors  = flow.get('has_errors', False)
    fwd_bytes   = flow.get('fwd_bytes', 0)
    rev_bytes   = flow.get('rev_bytes', 0)
    service     = flow.get('service', '')

    paragraphs: list[str] = []

    # ── Opening line ──────────────────────────────────────────────────────
    svc_note = f' ({service})' if service else ''
    paragraphs.append(
        f'**{proto}{svc_note} session between {src_ip}:{src_port} and {dst_ip}:{dst_port}**'
    )

    # ── Handshake narrative ───────────────────────────────────────────────
    if syn > 0:
        if syn > 0 and synack == 0:
            paragraphs.append(
                f'The client ({src_ip}) sent a SYN packet (connection request) to '
                f'{dst_ip}:{dst_port}, but never received a SYN+ACK reply. '
                f'This is a **half-open connection** — the server may be down, '
                f'the port may be closed, or a firewall may be blocking the connection. '
                f'(RFC 793 §3.4)'
            )
        elif synack > 0:
            paragraphs.append(
                f'**3-way handshake** (RFC 793 §3.4):\n'
                f'  1. {src_ip} → SYN → {dst_ip}:{dst_port}  '
                f'(client requests connection)\n'
                f'  2. {dst_ip} → SYN+ACK → {src_ip}  '
                f'(server accepts and sends its own sequence number)\n'
                f'  3. {src_ip} → ACK → {dst_ip}  '
                f'(client confirms — connection is established)\n'
                f'The connection was successfully established.'
            )
    else:
        # Mid-stream capture
        paragraphs.append(
            f'The capture started mid-session — the initial TCP handshake '
            f'(SYN/SYN+ACK) is not present. This is normal when capturing starts '
            f'after a connection was already established.'
        )

    # ── Data transfer ─────────────────────────────────────────────────────
    if pkts > 3:
        direction = 'bidirectional' if (fwd_bytes > 0 and rev_bytes > 0) else 'one-directional'
        paragraphs.append(
            f'**Data transfer**: {pkts} packets exchanged over '
            f'{dur_ms:.0f}ms ({direction}). '
            f'Sent: {_human_bytes(fwd_bytes)}, Received: {_human_bytes(rev_bytes)}.'
        )

    # ── TCP quality signals ───────────────────────────────────────────────
    quality_notes: list[str] = []
    if retx > 0:
        quality_notes.append(
            f'  • **{retx} retransmission{"s" if retx > 1 else ""}** detected — '
            f'packets were re-sent because the sender did not receive acknowledgment. '
            f'This indicates packet loss or a degraded network path.'
        )
    if dup_acks >= 3:
        quality_notes.append(
            f'  • **{dup_acks} duplicate ACKs** — receiver kept acknowledging the same '
            f'sequence number, signalling that it\'s waiting for a missing segment '
            f'(RFC 5681 fast retransmit trigger).'
        )
    if zero_win > 0:
        quality_notes.append(
            f'  • **{zero_win} zero-window advertisement{"s" if zero_win > 1 else ""}** — '
            f'the receiver\'s buffer was full. The sender had to pause transmission until '
            f'the receiver processed its backlog. This is a performance bottleneck signal.'
        )
    if quality_notes:
        paragraphs.append('**Session quality signals:**\n' + '\n'.join(quality_notes))

    # ── Teardown / termination ─────────────────────────────────────────────
    if rst > 0:
        paragraphs.append(
            f'⚠ **Abrupt reset ({rst} RST packet{"s" if rst > 1 else ""})**: '
            f'The connection was forcibly terminated — this was NOT a graceful close. '
            f'Possible causes: application crash, firewall rejection, port not open, '
            f'or a deliberate connection abort.'
        )
    elif fin > 0 and is_complete:
        paragraphs.append(
            f'**Graceful teardown**: Both sides exchanged FIN packets to close the '
            f'connection cleanly. The session completed normally (RFC 793 §3.5).'
        )
    elif fin > 0:
        paragraphs.append(
            f'**Partial close**: FIN seen but the capture ended before the full '
            f'teardown sequence completed.'
        )

    # ── One-way flag ──────────────────────────────────────────────────────
    if is_one_way and pkts > 2:
        paragraphs.append(
            f'⚠ **One-way traffic only**: All {pkts} packets came from {src_ip}. '
            f'No response was seen. The destination may be unreachable, silently '
            f'dropping traffic, or the response may have taken a different path.'
        )

    # ── EXOS hint ─────────────────────────────────────────────────────────
    if has_errors or retx > 5 or is_one_way:
        paragraphs.append(
            'EXOS investigation commands:\n'
            f'  show ports {dst_port} information  '
            f'# Check port status\n'
            f'  show iparp                          '
            f'# Verify ARP entries for {dst_ip}\n'
            f'  show iproute                        '
            f'# Verify route to {dst_ip}'
        )

    return '\n\n'.join(paragraphs)


# ── ARP exchange explanation ──────────────────────────────────────────────────

def explain_arp_exchange(arp_exchanges: dict) -> str:
    """
    Explain ARP request/reply conversations in plain English.

    Parameters
    ----------
    arp_exchanges : dict
        Output of pair_arp_exchanges() from flow/arp_tracker.py or
        flow_engine.pair_arp_exchanges().

    Returns
    -------
    Multi-section narrative string.
    """
    pairs      = arp_exchanges.get('pairs', [])
    unanswered = arp_exchanges.get('unanswered', [])
    conflicts  = arp_exchanges.get('conflicts', [])
    gratuitous = arp_exchanges.get('gratuitous', [])
    total_req  = arp_exchanges.get('total_requests', len(pairs) + len(unanswered))
    resp_rate  = arp_exchanges.get('response_rate_pct', 0)
    ip_mac     = arp_exchanges.get('ip_mac_table', {})

    paragraphs: list[str] = []

    # ── Overview ──────────────────────────────────────────────────────────
    paragraphs.append(
        f'**ARP Overview (RFC 826)**\n'
        f'ARP (Address Resolution Protocol) maps IP addresses to MAC addresses '
        f'on the local network segment. Devices broadcast "Who has IP X?" and '
        f'the owner replies with their MAC address.\n\n'
        f'Capture summary: {total_req} ARP request{"s" if total_req != 1 else ""}, '
        f'{len(pairs)} answered ({resp_rate}% response rate), '
        f'{len(unanswered)} unanswered.'
    )

    # ── Successful pairs ──────────────────────────────────────────────────
    if pairs:
        pair_lines = [f'**Resolved ARP pairs ({len(pairs)}):**']
        for p in pairs[:10]:
            rtt    = p.get('rtt_ms', 0)
            req_ip = p.get('requester_ip', '?')
            tgt_ip = p.get('target_ip', '?')
            rep_mac = p.get('responder_mac', '?')
            pair_lines.append(
                f'  • {req_ip} asked "Who has {tgt_ip}?" → '
                f'{tgt_ip} replied: "I am at {rep_mac}" ({rtt}ms)'
            )
        if len(pairs) > 10:
            pair_lines.append(f'  … and {len(pairs) - 10} more resolved pairs.')
        paragraphs.append('\n'.join(pair_lines))

    # ── Unanswered requests ───────────────────────────────────────────────
    if unanswered:
        unans_lines = [f'⚠ **Unanswered ARP requests ({len(unanswered)}):**']
        for u in unanswered[:10]:
            unans_lines.append(
                f'  • {u.get("requester_ip", "?")} asked for {u.get("target_ip", "?")} '
                f'— no reply received.'
            )
        if len(unanswered) > 10:
            unans_lines.append(f'  … and {len(unanswered) - 10} more.')
        unans_lines.append(
            'Unanswered ARP requests may indicate: '
            'host is down, IP not assigned on this subnet, or broadcast blocking.'
        )
        paragraphs.append('\n'.join(unans_lines))

    # ── Gratuitous ARP ────────────────────────────────────────────────────
    if gratuitous:
        grat_lines = [
            f'ℹ **Gratuitous ARP detected ({len(gratuitous)} packets)**\n'
            f'Gratuitous ARP is when a device sends an ARP for its own IP address. '
            f'This is normal during: HSRP/VRRP failover, IP address changes, '
            f'or network interface restarts. However, it can also indicate ARP spoofing.'
        ]
        for g in gratuitous[:5]:
            grat_lines.append(
                f'  • {g.get("ip", "?")} announced MAC {g.get("mac", "?")} '
                f'({g.get("op", "?")})'
            )
        paragraphs.append('\n'.join(grat_lines))

    # ── ARP conflicts ─────────────────────────────────────────────────────
    if conflicts:
        conflict_lines = [
            f'🔴 **ARP conflicts detected ({len(conflicts)}) — possible ARP spoofing!**\n'
            f'An ARP conflict occurs when two different MAC addresses claim the same IP. '
            f'This can cause traffic to be misdirected and is a common ARP spoofing technique.'
        ]
        for c in conflicts[:5]:
            conflict_lines.append(
                f'  • IP {c.get("ip", "?")} was at {c.get("known_mac", "?")} '
                f'— new claim from {c.get("new_mac", "?")}'
            )
        conflict_lines.append(
            'EXOS mitigation:\n'
            '  configure arp validation   # Enable ARP validation\n'
            '  show arp                   # Review ARP table for conflicts\n'
            '  show fdb                   # Check MAC forwarding table'
        )
        paragraphs.append('\n'.join(conflict_lines))

    # ── IP-MAC table ──────────────────────────────────────────────────────
    if ip_mac:
        table_lines = [f'**Learned IP→MAC table ({len(ip_mac)} entries):**']
        for ip, mac in list(ip_mac.items())[:10]:
            vendor = _oui_vendor(mac)
            vendor_str = f' ({vendor})' if vendor else ''
            table_lines.append(f'  {ip:<18}  {mac}{vendor_str}')
        paragraphs.append('\n'.join(table_lines))

    return '\n\n'.join(paragraphs)


# ── UDP conversation explanation ──────────────────────────────────────────────

def explain_udp_conversation(flow: dict, related_packets: Optional[list] = None) -> str:
    """
    Explain a UDP conversation in plain English.

    Parameters
    ----------
    flow : dict
        FlowRecord.to_dict() from the flow engine.
    related_packets : list, optional
        Packets belonging to this flow.
    """
    src_ip   = flow.get('src_ip', '?')
    dst_ip   = flow.get('dst_ip', '?')
    src_port = flow.get('src_port', 0)
    dst_port = flow.get('dst_port', 0)
    proto    = flow.get('app_proto') or flow.get('proto', 'UDP')
    pkts     = flow.get('pkt_count', 0)
    dur_ms   = flow.get('duration_ms', 0)
    fwd      = flow.get('fwd_pkts', 0)
    rev      = flow.get('rev_pkts', 0)
    service  = flow.get('service', '')
    rfc      = flow.get('rfc_ref', '')
    is_complete = flow.get('is_complete', False)
    is_one_way  = flow.get('is_one_way', False)
    udp_timeout = flow.get('udp_timeout', False)

    paragraphs: list[str] = []

    svc_note = f' ({service})' if service else ''
    rfc_note = f'  [{rfc}]' if rfc else ''
    paragraphs.append(
        f'**{proto}{svc_note} conversation{rfc_note}**\n'
        f'{src_ip}:{src_port} ↔ {dst_ip}:{dst_port}'
    )

    # Protocol-specific explanation
    proto_explanations = _udp_proto_explanation(proto, src_ip, dst_ip, src_port, dst_port)
    if proto_explanations:
        paragraphs.append(proto_explanations)

    # Traffic summary
    if fwd > 0 or rev > 0:
        dir_desc = (
            f'{fwd} packets from {src_ip}, {rev} packets from {dst_ip}'
            if rev > 0 else
            f'All {fwd} packets from {src_ip} (one-way)'
        )
        paragraphs.append(
            f'Traffic: {pkts} packets over {dur_ms:.0f}ms — {dir_desc}.'
        )

    if is_complete:
        paragraphs.append(
            f'This conversation had matched request/response pairs — '
            f'the {proto} transaction completed successfully.'
        )
    elif is_one_way and pkts > 2:
        paragraphs.append(
            f'⚠ One-way traffic: only packets from {src_ip} were seen. '
            f'Responses from {dst_ip} may have taken a different path, '
            f'or the destination may be unreachable.'
        )

    if udp_timeout:
        paragraphs.append(
            f'This conversation ended by idle timeout — no packets were received '
            f'within the expected window for {proto}.'
        )

    return '\n\n'.join(paragraphs)


def _udp_proto_explanation(
    proto: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int
) -> str:
    """Return a protocol-specific explanation string for a UDP conversation."""
    if proto == 'DNS':
        return (
            f'DNS (Domain Name System, RFC 1035): {src_ip} is sending DNS queries to '
            f'{dst_ip}:{dst_port} to resolve hostnames to IP addresses. '
            f'Each query should receive a matching response with the answer.'
        )
    if proto in ('DHCP-Server', 'DHCP-Client', 'DHCP'):
        return (
            'DHCP (RFC 2131): Automatic IP address assignment in progress. '
            'The DORA process: Discover (client broadcasts) → Offer (server proposes IP) → '
            'Request (client accepts offer) → ACK (server confirms lease).'
        )
    if proto == 'NTP':
        return (
            f'NTP (Network Time Protocol, RFC 5905): {src_ip} is synchronising its '
            f'clock with the NTP server at {dst_ip}. '
            f'Each query should receive a time response within a few milliseconds.'
        )
    if proto in ('SNMP', 'SNMP-Trap'):
        return (
            f'SNMP (RFC 3411): Network management traffic. '
            + ('Unsolicited trap from device reporting an event.' if proto == 'SNMP-Trap'
               else f'{src_ip} is polling {dst_ip} for device metrics.')
        )
    if proto == 'RTP':
        return (
            'RTP (Real-time Transport Protocol, RFC 3550): '
            'Media streaming — audio or video data. '
            'High packet rate and consistent inter-packet timing are expected. '
            'Gaps or jitter indicate network problems affecting call quality.'
        )
    if proto == 'Syslog':
        return (
            f'Syslog (RFC 5424): {src_ip} is sending log messages to the log '
            f'collector at {dst_ip}:{dst_port}. '
            f'This is one-way — no response is expected.'
        )
    return ''


# ── Anomaly explanation ───────────────────────────────────────────────────────

def explain_anomaly(anomaly: dict, verbose: bool = True) -> str:
    """
    Produce a rich, actionable explanation for an anomaly finding.

    Replaces the minimal anomaly_to_english() for cases where more detail
    is needed (e.g. AI prompt injection, dashboard detail panel).

    Parameters
    ----------
    anomaly : dict
        Finding dict from _rule_engine(), run_extended_rules(), or
        anomaly_rules.run_extended_rules().
    verbose : bool
        If True, includes impact, root causes, and EXOS commands.
        If False, returns a single-sentence summary.
    """
    title    = anomaly.get('title', 'Unknown anomaly')
    detail   = anomaly.get('detail', '')
    evidence = anomaly.get('evidence', {})
    severity = anomaly.get('severity', 'info')
    layer    = anomaly.get('layer', '')
    proto    = anomaly.get('protocol', '')
    rfc_ref  = anomaly.get('rfc_ref', '')
    category = anomaly.get('category', '')

    # Short form
    severity_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡',
                      'low': '🔵', 'info': 'ℹ'}.get(severity, 'ℹ')
    short = f'{severity_emoji} [{severity.upper()}] {title}'
    if not verbose:
        return short + (f': {detail}' if detail else '')

    parts: list[str] = [short]

    # Detail
    if detail:
        parts.append(detail)

    # Impact
    impact = _SEVERITY_IMPACT.get(severity, '')
    if impact:
        parts.append(f'**Impact**: {impact}')

    # Evidence
    if evidence:
        if isinstance(evidence, dict):
            ev_str = ', '.join(f'{k}={v}' for k, v in list(evidence.items())[:6])
        else:
            ev_str = str(evidence)
        parts.append(f'**Evidence**: {ev_str}')

    # RFC context
    if rfc_ref:
        parts.append(f'**Standard**: {rfc_ref}')

    # Root cause analysis
    root_causes = _anomaly_root_causes(title.lower(), proto, severity)
    if root_causes:
        parts.append('**Possible root causes**:\n' +
                     '\n'.join(f'  • {rc}' for rc in root_causes))

    # EXOS remediation
    exos_cmds = _anomaly_exos_commands(title.lower(), proto, layer)
    if exos_cmds:
        parts.append('**EXOS investigation commands**:\n' +
                     '\n'.join(f'  {cmd}' for cmd in exos_cmds))

    return '\n'.join(parts)


def _anomaly_root_causes(title: str, proto: str, severity: str) -> list[str]:
    """Return a list of probable root causes for an anomaly."""
    if 'arp flood' in title or 'arp storm' in title:
        return [
            'Broadcast storm caused by a network loop',
            'Misconfigured or malfunctioning host generating excessive ARP traffic',
            'Network scanning tool running on the network',
        ]
    if 'arp conflict' in title or 'duplicate ip' in title:
        return [
            'Static IP address already assigned to another device',
            'DHCP lease conflict (address still in use after lease expiry)',
            'ARP spoofing / man-in-the-middle attack',
        ]
    if 'syn flood' in title or 'half-open' in title:
        return [
            'SYN flood DDoS attack targeting the server',
            'Client application crashing after SYN without completing handshake',
            'Firewall or ACL blocking SYN-ACK responses',
            'Server overloaded — cannot respond to connection requests',
        ]
    if 'rst storm' in title or 'reset' in title:
        return [
            'Application crash or service restart',
            'Firewall injecting TCP RST packets',
            'Server refusing connections (port not open)',
            'Network equipment resetting idle connections',
        ]
    if 'zero window' in title:
        return [
            'Receiving application processing data too slowly',
            'High CPU or memory pressure on the receiver',
            'Network buffer tuning mismatch',
        ]
    if 'retransmission' in title:
        return [
            'Packet loss on the network path',
            'Network congestion causing queue drops',
            'Duplex mismatch causing late collisions',
            'Wireless interference or weak signal',
        ]
    if 'dns tunnel' in title or 'dns entropy' in title:
        return [
            'Malware using DNS for command-and-control communication',
            'Data exfiltration over DNS',
            'Legitimate DNS-based CDN with long TXT records (false positive)',
        ]
    if 'dhcp starvation' in title:
        return [
            'Network scanning tool exhausting DHCP pool',
            'Misconfigured device with rapid DHCP Discover loop',
            'Malicious DHCP starvation attack',
        ]
    if 'snmp' in title and ('trap' in title or 'storm' in title):
        return [
            'Device experiencing repeated error conditions',
            'SNMP polling interval too aggressive',
            'Device instability (hardware fault or software bug)',
        ]
    if 'broadcast storm' in title:
        return [
            'Switching loop — STP not converged or disabled',
            'Misconfigured port (access port receiving tagged frames)',
            'Device generating excessive broadcasts',
        ]
    return []


def _anomaly_exos_commands(title: str, proto: str, layer: str) -> list[str]:
    """Return EXOS CLI commands relevant to the anomaly."""
    cmds: list[str] = []

    if 'arp' in title or proto == 'ARP':
        cmds += [
            'show arp              # View current ARP table',
            'show iparp            # ARP statistics and aging',
        ]
    if 'syn flood' in title or 'half-open' in title or 'tcp' in proto.lower():
        cmds += [
            'show access-list      # Review rate-limiting ACLs',
            'show port rxerrors    # Check port receive errors',
        ]
    if 'retransmission' in title or 'packet loss' in title:
        cmds += [
            'show ports statistics  # Detailed port counters',
            'show ports rxerrors    # Receive error counters',
            'show ports txerrors    # Transmit error counters',
        ]
    if 'dns' in title or proto == 'DNS':
        cmds += [
            'show dns-client        # DNS client configuration',
        ]
    if 'dhcp' in title or 'DHCP' in proto:
        cmds += [
            'show dhcp-server       # DHCP server lease status',
            'show dhcp-client       # Client lease information',
        ]
    if 'snmp' in title or 'SNMP' in proto:
        cmds += [
            'show snmp              # SNMP configuration',
            'show snmp traps        # SNMP trap history',
        ]
    if 'stp' in title or proto == 'STP':
        cmds += [
            'show stpd detail       # Spanning tree state',
            'show stpd ports        # Per-port STP state',
        ]
    if 'lldp' in title or proto == 'LLDP':
        cmds += [
            'show lldp neighbors    # LLDP neighbor table',
        ]
    if 'broadcast storm' in title or 'loop' in title:
        cmds += [
            'show stpd              # STP domain status',
            'show fdb statistics    # MAC table statistics',
            'show port info         # Port link status',
        ]
    if not cmds:
        cmds = [
            'show port rxerrors     # Receive error counters',
            'show port txerrors     # Transmit error counters',
            'show port info         # Port status',
        ]
    return cmds


# ── Retransmission explanation ────────────────────────────────────────────────

def explain_retransmissions(flow: dict) -> str:
    """
    Explain TCP retransmissions in plain English with severity assessment.

    Parameters
    ----------
    flow : dict
        FlowRecord.to_dict() containing retransmissions, dup_acks, etc.
    """
    retx     = flow.get('retransmissions', 0)
    dup_acks = flow.get('dup_acks', 0)
    zero_win = flow.get('zero_windows', 0)
    pkts     = flow.get('pkt_count', 1)
    proto    = flow.get('app_proto') or flow.get('proto', 'TCP')
    src_ip   = flow.get('src_ip', '?')
    dst_ip   = flow.get('dst_ip', '?')

    if retx == 0 and dup_acks == 0 and zero_win == 0:
        return (
            f'The {proto} session between {src_ip} and {dst_ip} '
            f'shows no retransmissions or congestion signals. '
            f'Network path quality appears healthy.'
        )

    retx_rate = round(retx / max(pkts, 1) * 100, 1)
    parts: list[str] = []

    if retx > 0:
        severity = 'severe' if retx_rate > 5 else 'moderate' if retx_rate > 1 else 'minor'
        parts.append(
            f'**{retx} TCP retransmission{"s" if retx > 1 else ""}** ({retx_rate}% of traffic) — '
            f'{severity} packet loss on this path. '
            f'Retransmissions occur when the sender does not receive an ACK '
            f'within the retransmission timeout (RTO, RFC 6298). '
            f'Each retransmission adds {_estimate_rto()}ms latency to the session.'
        )

    if dup_acks >= 3:
        parts.append(
            f'**{dup_acks} duplicate ACKs** — the receiver detected missing segments '
            f'and is signalling via repeated ACKs (RFC 5681 §3.2). '
            f'Three or more duplicate ACKs trigger fast retransmit, '
            f'skipping the normal RTO timeout.'
        )

    if zero_win > 0:
        parts.append(
            f'**{zero_win} zero-window event{"s" if zero_win > 1 else ""}** — '
            f'the receiver\'s TCP buffer filled up. The sender was blocked until '
            f'the receiver sent a window update. '
            f'This indicates the receiving application is processing data too slowly '
            f'relative to the network speed.'
        )

    parts.append(
        'EXOS investigation:\n'
        '  show ports statistics   # Check error counters\n'
        '  show ports rxerrors     # Receive-side errors (CRC, alignment)\n'
        '  show ports txerrors     # Transmit-side errors (late collisions)\n'
        '  show port info          # Duplex and speed negotiation status'
    )

    return '\n\n'.join(parts)


def _estimate_rto() -> str:
    """Return a typical RTO estimate string."""
    return '200–3000'


# ── Unknown protocol explanation ──────────────────────────────────────────────

def explain_unknown_protocol(pkt: dict) -> str:
    """
    Best-effort explanation for traffic with no registered decoder.

    Uses EtherType lookup, OUI vendor identification, port heuristics,
    and payload byte patterns to form a hypothesis.

    Parameters
    ----------
    pkt : dict
        Parsed packet dict. May contain proto='ET-0x...', or unknown UDP/TCP.
    """
    proto    = pkt.get('proto', '?')
    src_ip   = pkt.get('src_ip', '')
    dst_ip   = pkt.get('dst_ip', '')
    src_port = pkt.get('src_port', 0)
    dst_port = pkt.get('dst_port', 0)
    src_mac  = pkt.get('src_mac', '')
    dst_mac  = pkt.get('dst_mac', '')
    vlan     = pkt.get('vlan_id')
    layers   = pkt.get('layers', [])

    parts: list[str] = []

    # EtherType-based identification
    if proto.startswith('ET-0x') or proto.startswith('ET-'):
        raw_et = proto.replace('ET-0x', '').replace('ET-', '').strip()
        try:
            et_int = int(raw_et, 16)
            known  = _KNOWN_ETHERTYPES.get(et_int)
            if known:
                parts.append(
                    f'EtherType 0x{et_int:04X} is registered as **{known}**. '
                    f'A decoder for this protocol is not yet implemented in this version.'
                )
            elif 0x8800 <= et_int <= 0x88FF:
                parts.append(
                    f'EtherType 0x{et_int:04X} is in the IEEE 802.x range (0x8800–0x88FF). '
                    f'This is likely a vendor-specific or IEEE extension protocol.'
                )
            elif 0x8900 <= et_int <= 0x89FF:
                parts.append(
                    f'EtherType 0x{et_int:04X} is in the vendor-extended range. '
                    f'This may be an Extreme Networks or other vendor proprietary protocol.'
                )
            else:
                parts.append(
                    f'EtherType 0x{et_int:04X} is not in the standard registry. '
                    f'This is likely a proprietary or custom protocol.'
                )
        except ValueError:
            parts.append(f'Unknown protocol identifier: {proto}')

    # Port-based heuristics for unknown TCP/UDP
    elif src_port or dst_port:
        port = dst_port or src_port
        parts.append(_port_heuristic(port, proto, src_ip, dst_ip))

    # OUI vendor identification
    vendor_src = _oui_vendor(src_mac) if src_mac else ''
    vendor_dst = _oui_vendor(dst_mac) if dst_mac else ''
    if vendor_src or vendor_dst:
        vendor_note = []
        if vendor_src:
            vendor_note.append(f'{src_mac} is a **{vendor_src}** device')
        if vendor_dst:
            vendor_note.append(f'{dst_mac} is a **{vendor_dst}** device')
        parts.append(
            'MAC vendor identification: ' + '; '.join(vendor_note) + '. '
            'Check vendor-specific protocol documentation.'
        )

    # Multicast destination heuristics
    if dst_mac and dst_mac.startswith(('01:', '33:', 'ff:')):
        mcast_known = {
            '01:80:c2:00:00:0e': 'LLDP multicast',
            '01:80:c2:00:00:00': 'STP multicast',
            '01:00:5e':          'IPv4 multicast (RFC 1112)',
            '33:33:':            'IPv6 multicast (RFC 4291)',
            'ff:ff:ff:ff:ff:ff': 'Ethernet broadcast',
        }
        for prefix, label in mcast_known.items():
            if dst_mac.startswith(prefix):
                parts.append(f'Destination {dst_mac} is a **{label}** address.')
                break

    # Payload pattern analysis (from layers)
    payload_hints = _payload_hints(layers)
    if payload_hints:
        parts.append(payload_hints)

    # VLAN context
    if vlan:
        parts.append(f'Traffic is on VLAN {vlan}.')

    # Final fallback guidance
    if not parts:
        parts.append(
            f'No protocol match found for "{proto}". '
            f'Best-effort analysis: inspect the payload bytes in the hex dump, '
            f'check source/destination ports, and compare against vendor documentation.'
        )

    parts.append(
        'To identify further:\n'
        '  • Check Extreme Networks EXOS documentation for proprietary protocols\n'
        '  • Use Wireshark with custom dissectors if available\n'
        '  • Compare the payload with known protocol signatures\n'
        '  • Enable debug capture on the EXOS switch port: '
        'debug packet capture ports <port> on'
    )

    return '\n\n'.join(parts)


def _port_heuristic(port: int, proto: str, src_ip: str, dst_ip: str) -> str:
    """Generate a heuristic explanation based on port number."""
    if 16384 <= port <= 32767:
        return (
            f'Port {port} is in the RTP media range (16384–32767, RFC 3550). '
            f'This traffic likely represents audio or video streaming.'
        )
    if 49152 <= port <= 65535:
        return (
            f'Port {port} is in the IANA ephemeral range (49152–65535). '
            f'This is a dynamically assigned client port — '
            f'the conversation is initiated from {src_ip}.'
        )
    if 1024 <= port <= 49151:
        return (
            f'Port {port} is in the registered port range (IANA). '
            f'Check the IANA service registry for the specific assignment.'
        )
    return (
        f'Port {port} is a well-known port. '
        f'No decoder is registered for this service on {proto}.'
    )


def _payload_hints(layers: list) -> str:
    """Inspect layer dicts for payload clues."""
    for layer in layers:
        title = layer.get('title', '').lower()
        if 'unknown' in title or 'proprietary' in title:
            for f in layer.get('fields', []):
                if f.get('n', '').lower() == 'payload preview':
                    preview = f.get('v', '')
                    if preview:
                        return (
                            f'Payload preview (first bytes): `{preview}`\n'
                            f'Check for known protocol signatures in this byte sequence.'
                        )
    return ''


def _oui_vendor(mac: str) -> str:
    """Return vendor name for a MAC OUI prefix, or empty string."""
    if not mac or len(mac) < 8:
        return ''
    prefix = mac[:8].lower()
    # Try 3-byte prefix
    v = _OUI_VENDORS.get(prefix, '')
    if v:
        return v
    # Try 2-byte prefix (e.g. '52:54')
    return _OUI_VENDORS.get(mac[:5].lower(), '')


def _human_bytes(n: int) -> str:
    if n < 1024:
        return f'{n}B'
    if n < 1024 ** 2:
        return f'{n / 1024:.1f}KB'
    return f'{n / 1024 ** 2:.1f}MB'


# ── ConversationNarrator ──────────────────────────────────────────────────────

class ConversationNarrator:
    """
    Produces full narrative explanations for any flow type.

    Dispatches to the appropriate explain_*() function based on the
    flow's protocol and layer.

    Usage
    -----
        narrator = ConversationNarrator(packets, analysis)
        text     = narrator.narrate(flow_dict)
    """

    def __init__(self, packets: list, analysis: dict):
        self.packets  = packets
        self.analysis = analysis
        # Build pkt_id → pkt lookup for related_packets retrieval
        self._pkt_by_id: dict[int, dict] = {
            p.get('id', i): p for i, p in enumerate(packets)
        }

    def narrate(self, flow: dict) -> str:
        """
        Generate a full narrative explanation for *flow*.

        Returns a multi-paragraph string suitable for the dashboard
        detail panel or AI prompt injection.
        """
        proto = flow.get('app_proto') or flow.get('proto', '')
        layer = flow.get('layer', 'L4')
        base  = _base_proto(proto)

        # Gather related packets
        related = [
            self._pkt_by_id[pid]
            for pid in flow.get('pkt_ids', [])[:20]
            if pid in self._pkt_by_id
        ]

        if base == 'TCP':
            return explain_tcp_session(flow, related)

        if base == 'UDP':
            return explain_udp_conversation(flow, related)

        if proto == 'ARP' or layer == 'L2':
            arp_ex = self.analysis.get('arp_exchanges', {})
            if arp_ex:
                return explain_arp_exchange(arp_ex)
            # Fallback for L2 flow with no ARP exchange data
            return _explain_l2_flow(flow)

        if proto == 'ICMP':
            return _explain_icmp_flow(flow)

        # Unknown or other protocol
        # Use the first packet in the flow as representative
        sample_pkt = related[0] if related else flow
        return explain_unknown_protocol(sample_pkt)

    def narrate_anomalies(self, verbose: bool = True) -> str:
        """
        Return a full narrative explanation for all anomalies in the analysis.
        """
        anomalies = self.analysis.get('anomalies', [])
        if not anomalies:
            return 'No anomalies detected in this capture.'
        parts = [f'## Anomaly Report ({len(anomalies)} findings)\n']
        for anom in anomalies:
            parts.append(explain_anomaly(anom, verbose=verbose))
            parts.append('')  # blank line separator
        return '\n'.join(parts)


def _base_proto(proto: str) -> str:
    """Map app proto names to transport base."""
    _TCP = {
        'HTTP', 'HTTPS', 'HTTP-Alt', 'HTTPS-Alt', 'SSH', 'Telnet',
        'FTP', 'FTP-Data', 'SMTP', 'SMTPS', 'POP3', 'POP3S',
        'IMAP', 'IMAPS', 'LDAP', 'LDAPS', 'SMB', 'NetBIOS-SSN',
        'RDP', 'SIP', 'SIPS', 'MSSQL', 'Oracle', 'MySQL',
        'PostgreSQL', 'MongoDB', 'Redis', 'VNC', 'Kerberos', 'BGP',
    }
    _UDP = {
        'DNS', 'DHCP-Server', 'DHCP-Client', 'NTP', 'SNMP', 'SNMP-Trap',
        'Syslog', 'RIP', 'OpenVPN', 'RTP', 'TFTP', 'NBNS', 'RADIUS-Auth',
        'RADIUS-Acct', 'VXLAN',
    }
    if proto in _TCP:
        return 'TCP'
    if proto in _UDP:
        return 'UDP'
    return proto


def _explain_l2_flow(flow: dict) -> str:
    """Brief explanation for a Layer 2 flow."""
    proto   = flow.get('proto', 'L2')
    src_mac = flow.get('src_mac', '?')
    dst_mac = flow.get('dst_mac', '?')
    pkts    = flow.get('pkt_count', 0)
    vlan    = flow.get('vlan_id')
    rfc     = flow.get('rfc_ref', '')

    rfc_note = f'  [{rfc}]' if rfc else ''
    vlan_note = f' on VLAN {vlan}' if vlan else ''
    return (
        f'**{proto} Layer 2 flow{rfc_note}**\n'
        f'{src_mac} ↔ {dst_mac}{vlan_note} — {pkts} packets.\n'
        f'{explain_unknown_protocol(flow)}'
    )


def _explain_icmp_flow(flow: dict) -> str:
    """Brief explanation for an ICMP flow."""
    src_ip = flow.get('src_ip', '?')
    dst_ip = flow.get('dst_ip', '?')
    pkts   = flow.get('pkt_count', 0)
    has_errors = flow.get('has_errors', False)
    fwd    = flow.get('fwd_pkts', 0)
    rev    = flow.get('rev_pkts', 0)

    if has_errors:
        return (
            f'**ICMP flow with errors (RFC 792)**\n'
            f'{src_ip} ↔ {dst_ip} — {pkts} packets.\n'
            f'ICMP error messages (Destination Unreachable or TTL Exceeded) '
            f'were observed. This indicates a routing failure or a host that '
            f'cannot be reached from {src_ip}.'
        )
    if rev > 0:
        return (
            f'**ICMP ping session (RFC 792)**\n'
            f'{src_ip} → {dst_ip}: {fwd} echo requests, {rev} replies.\n'
            f'{dst_ip} is reachable from {src_ip}.'
        )
    return (
        f'**ICMP flow (one-way, RFC 792)**\n'
        f'{src_ip} → {dst_ip}: {fwd} packets, no replies seen.\n'
        f'{dst_ip} may be unreachable or ICMP replies are blocked by a firewall.'
    )


# ── Capture health summary ────────────────────────────────────────────────────

def capture_health_summary(analysis: dict) -> str:
    """
    Generate a plain-English capture health assessment.

    Combines flow stats, anomaly counts, and protocol distribution
    into a paragraph suitable for the top of an AI prompt or dashboard panel.

    Parameters
    ----------
    analysis : dict
        The full analysis dict from analyse() in AI_PCAP_new_Apr27.py.
    """
    total_pkts  = analysis.get('total', 0)
    anomalies   = analysis.get('anomalies', [])
    flows       = analysis.get('flows', [])
    flow_stats  = analysis.get('flow_stats', {})
    proto_cnt   = analysis.get('proto_counts', {})

    # Overall verdict
    critical = [a for a in anomalies if a.get('severity') == 'critical']
    high     = [a for a in anomalies if a.get('severity') == 'high']
    resets   = flow_stats.get('reset_flows', 0)
    half_open = flow_stats.get('half_open_flows', 0)
    retx_flows = flow_stats.get('retransmission_flows', 0)
    error_flows = flow_stats.get('flows_with_errors', 0)

    if critical:
        verdict = f'🔴 **CRITICAL ISSUES DETECTED** ({len(critical)} critical anomaly findings)'
    elif high or resets > 5 or retx_flows > 10:
        verdict = f'🟠 **ATTENTION REQUIRED** ({len(high)} high-severity findings)'
    elif anomalies:
        verdict = f'🟡 **MINOR ISSUES** ({len(anomalies)} anomaly findings, no critical)'
    else:
        verdict = '🟢 **CAPTURE LOOKS HEALTHY** — no significant anomalies detected'

    lines: list[str] = [
        '## Capture Health Assessment\n',
        verdict,
        '',
        f'- **Packets**: {total_pkts:,}',
        f'- **Flows**: {len(flows):,} '
        f'({flow_stats.get("complete_flows", 0)} complete, '
        f'{half_open} half-open, {resets} reset)',
        f'- **Protocols**: {len(proto_cnt)}',
        f'- **Anomalies**: {len(anomalies)} findings '
        f'({len(critical)} critical, {len(high)} high)',
        f'- **TCP quality**: {retx_flows} flows with retransmissions, '
        f'{error_flows} flows with errors',
    ]

    # Top concerns
    if critical or high:
        lines += ['', '**Top concerns:**']
        for a in (critical + high)[:5]:
            sev = a.get('severity', 'info').upper()
            lines.append(f'  • [{sev}] {a.get("title", "")}')

    # Top protocols
    if proto_cnt:
        top = sorted(proto_cnt.items(), key=lambda x: x[1], reverse=True)[:5]
        lines += ['', '**Dominant protocols**: ' +
                  ', '.join(f'{p} ({c})' for p, c in top)]

    return '\n'.join(lines)
