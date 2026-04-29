"""
ai_summaries.py — RFC-Aware AI Packet Summary Generator
=========================================================
Generates rich, human-readable packet and flow summaries for the AI PCAP Analyzer.

This module enhances the AI analysis layer by:
  1. Producing structured packet summaries with RFC context
  2. Generating per-flow narrative explanations
  3. Providing RFC-aware protocol analysis prompts for the AI backends
  4. Explaining anomalies in plain English
  5. Handling unknown protocols with best-effort analysis

Integration with AI_PCAP_new_Apr27.py
--------------------------------------
    from ai_summaries import PacketSummaryEngine, build_ai_prompt
    engine = PacketSummaryEngine(packets, analysis)
    summary = engine.generate_capture_summary()
    prompt  = build_ai_prompt(summary, question="Why are there so many ARP requests?")
"""

from __future__ import annotations
from typing import Optional
import textwrap

try:
    from ai_explain import (
        explain_tcp_session,
        explain_arp_exchange,
        explain_unknown_protocol as _explain_unknown,
        explain_anomaly as _explain_anomaly_verbose,
    )
    _AI_EXPLAIN_AVAILABLE = True
except ImportError:
    _AI_EXPLAIN_AVAILABLE = False


# ── RFC reference database ────────────────────────────────────────────────────

RFC_DB: dict[str, dict] = {
    'ARP': {
        'rfc': 'RFC 826', 'full': 'Address Resolution Protocol',
        'purpose': 'Maps IP addresses to MAC addresses on a local network segment.',
        'normal': 'REQUEST sent as broadcast, REPLY sent as unicast.',
        'anomalies': [
            'ARP storm: many requests in short time (broadcast storm indicator)',
            'Gratuitous ARP: sender claims ownership of an IP (can indicate ARP spoofing)',
            'Unanswered ARP: target host may be down or unreachable',
            'Duplicate IP: two MACs responding to same IP (ARP conflict)',
        ],
    },
    'ICMP': {
        'rfc': 'RFC 792', 'full': 'Internet Control Message Protocol',
        'purpose': 'Network diagnostic and error reporting protocol.',
        'normal': 'Echo Request (type 8) → Echo Reply (type 0) for ping. TTL Exceeded (type 11) for traceroute.',
        'anomalies': [
            'ICMP flood: high-rate Echo Requests (DoS indicator)',
            'Destination Unreachable: routing failure or firewall rejection',
            'TTL Exceeded: traceroute or misconfigured routing loop',
            'Redirect (type 5): unexpected routing change',
        ],
    },
    'TCP': {
        'rfc': 'RFC 793', 'full': 'Transmission Control Protocol',
        'purpose': 'Reliable, ordered, connection-oriented byte-stream transport.',
        'normal': '3-way handshake: SYN → SYN+ACK → ACK. Data transfer. FIN → FIN+ACK → ACK for teardown.',
        'anomalies': [
            'SYN flood: many SYNs without SYN-ACK replies (DDoS)',
            'RST storm: many TCP resets (service rejection or attack)',
            'Half-open connections: SYN sent but never completed',
            'Zero window: receiver buffer full (performance problem)',
            'Port scan: one source connecting to many ports rapidly',
        ],
    },
    'UDP': {
        'rfc': 'RFC 768', 'full': 'User Datagram Protocol',
        'purpose': 'Connectionless, unreliable datagram transport — low overhead.',
        'normal': 'Single packet delivery, no handshake. Used for DNS, DHCP, VoIP, streaming.',
        'anomalies': [
            'UDP flood: high-rate UDP traffic (amplification attack)',
            'DNS tunneling: DNS queries with unusually long names or high entropy',
            'Unexpected ports: traffic on high-numbered ports may indicate covert channels',
        ],
    },
    'DNS': {
        'rfc': 'RFC 1035', 'full': 'Domain Name System',
        'purpose': 'Resolves domain names to IP addresses.',
        'normal': 'Query on port 53 UDP, response follows. TTL in answer records controls caching.',
        'anomalies': [
            'NXDOMAIN storm: many queries for non-existent domains (DGA malware)',
            'High-entropy names: long random-looking subdomains (DNS tunneling)',
            'Multiple DNS servers: may indicate rogue DNS or misconfiguration',
            'DNS over TCP: truncated responses or zone transfer attempts',
        ],
    },
    'DHCP': {
        'rfc': 'RFC 2131', 'full': 'Dynamic Host Configuration Protocol',
        'purpose': 'Automatically assigns IP addresses and network configuration to clients.',
        'normal': 'DORA: Discover → Offer → Request → ACK. Lease renewal via unicast Request.',
        'anomalies': [
            'DHCP starvation: rapid Discover requests exhausting IP pool',
            'Rogue DHCP server: unexpected Offer from unknown server',
            'DHCP NAK: server rejecting request (lease conflict or wrong subnet)',
            'Multiple servers: risk of conflicting address assignments',
        ],
    },
    'SNMP': {
        'rfc': 'RFC 3411', 'full': 'Simple Network Management Protocol',
        'purpose': 'Monitors and manages network devices.',
        'normal': 'GetRequest/GetResponse for polling. Trap/InformRequest for unsolicited events.',
        'anomalies': [
            'Default community strings (public/private): security risk',
            'SNMPv1/v2c: community string transmitted in plaintext',
            'Trap storm: many traps indicate device instability',
            'SetRequest: device configuration change attempt',
        ],
    },
    'LLDP': {
        'rfc': 'IEEE 802.1AB', 'full': 'Link Layer Discovery Protocol',
        'purpose': 'Advertises device identity, port, and capabilities to directly connected neighbors.',
        'normal': 'Sent every 30s to 01:80:c2:00:00:0e (LLDP multicast). Not forwarded beyond the local segment.',
        'anomalies': [
            'Rapid LLDP: topology changes or device instability',
            'Multiple LLDP sources on same port: possible loop or hub',
        ],
    },
    'STP': {
        'rfc': 'IEEE 802.1D', 'full': 'Spanning Tree Protocol',
        'purpose': 'Prevents Layer 2 broadcast loops by blocking redundant paths.',
        'normal': 'BPDUs every 2s from root bridge. TCN when topology changes.',
        'anomalies': [
            'Topology Change Notification (TCN): port state change — may cause MAC table flush',
            'Root bridge change: network topology instability',
            'High BPDU rate: potential STP attack or loop',
        ],
    },
    'EAPoL': {
        'rfc': 'IEEE 802.1X', 'full': 'Extensible Authentication Protocol over LAN',
        'purpose': 'Port-based network access control — requires authentication before network access.',
        'normal': 'EAPOL-Start → EAP-Request → EAP-Response → RADIUS → EAP-Success/Failure.',
        'anomalies': [
            'EAPOL-Start without response: switch not configured for 802.1X',
            'EAP-Failure: authentication rejected (wrong credentials)',
            'Repeated EAPOL-Start: client retry loop',
        ],
    },
    'IPv4': {
        'rfc': 'RFC 791', 'full': 'Internet Protocol version 4',
        'purpose': 'Routes datagrams across networks using 32-bit addresses.',
        'normal': 'TTL decremented each hop. DF bit prevents fragmentation. Checksum validates header.',
        'anomalies': [
            'Low TTL: may indicate traceroute, routing loop, or misconfigured host',
            'Fragmentation: DF+offset > 0 is invalid; large fragment counts may indicate evasion',
            'IP spoofing: source IP changing for the same MAC',
        ],
    },
    'IPv6': {
        'rfc': 'RFC 8200', 'full': 'Internet Protocol version 6',
        'purpose': 'Routes datagrams using 128-bit addresses with mandatory IPsec support.',
        'normal': 'Link-local addresses (fe80::/10) for local segment. Neighbor Discovery replaces ARP.',
        'anomalies': [
            'Unexpected IPv6 on IPv4-only networks: potential evasion or misconfiguration',
            'ICMPv6 Router Advertisement flood: rogue RA attack',
        ],
    },
    'OSPF': {
        'rfc': 'RFC 5340', 'full': 'Open Shortest Path First',
        'purpose': 'Link-state routing protocol — builds topology map for shortest-path routing.',
        'normal': 'Hello packets establish adjacencies. LSAs distribute topology.',
        'anomalies': [
            'OSPF neighbor flap: adjacency instability',
            'Unexpected OSPF traffic: router misconfiguration or rogue router',
        ],
    },
    'BGP': {
        'rfc': 'RFC 4271', 'full': 'Border Gateway Protocol',
        'purpose': 'Exterior routing protocol — exchanges routing information between autonomous systems.',
        'normal': 'TCP port 179. OPEN → KEEPALIVE → UPDATE messages.',
        'anomalies': [
            'BGP session reset: peer connection instability',
            'Route flapping: BGP prefix instability',
            'Unexpected BGP peer: potential route hijacking',
        ],
    },
    'VRRP': {
        'rfc': 'RFC 5798', 'full': 'Virtual Router Redundancy Protocol',
        'purpose': 'Provides default gateway redundancy using a shared virtual IP address.',
        'normal': 'Master router sends advertisements. Backup takes over if master fails.',
        'anomalies': [
            'VRRP master conflict: two routers claiming master role',
            'VRRP advertisement flood: configuration error',
        ],
    },
}

# Protocols not in RFC_DB — best-effort descriptions
_GENERIC_DESCRIPTIONS: dict[str, str] = {
    'HTTP':  'Web traffic — HTTP GET/POST requests and responses (RFC 9110)',
    'HTTPS': 'Encrypted web traffic — TLS-secured HTTP (RFC 9110 + RFC 8446)',
    'SSH':   'Encrypted remote shell session (RFC 4253)',
    'FTP':   'File transfer control session (RFC 959)',
    'NTP':   'Network time synchronisation (RFC 5905)',
    'SIP':   'VoIP session initiation and control (RFC 3261)',
    'RTP':   'Real-time media streaming (RFC 3550)',
    'IGMP':  'Multicast group membership management (RFC 3376)',
}


# ── Small local helpers ────────────────────────────────────────────────────────

def _service_name(port: int) -> str:
    """Return a well-known service name for a port, or empty string."""
    _WELL_KNOWN = {
        20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 67: 'DHCP-Server', 68: 'DHCP-Client',
        69: 'TFTP', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
        161: 'SNMP', 162: 'SNMP-Trap', 179: 'BGP', 389: 'LDAP',
        443: 'HTTPS', 445: 'SMB', 514: 'Syslog', 587: 'SMTP-TLS',
        636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
        1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
        3389: 'RDP', 5060: 'SIP', 5061: 'SIPS',
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    }
    return _WELL_KNOWN.get(port, '')


def _human_bytes_local(n: int) -> str:
    """Convert bytes to a human-readable string."""
    if n < 1024:
        return f'{n}B'
    if n < 1024 ** 2:
        return f'{n / 1024:.1f}KB'
    return f'{n / 1024 ** 2:.1f}MB'


# ── Packet-level summary helpers ──────────────────────────────────────────────

def explain_packet(pkt: dict, verbose: bool = False) -> str:
    """
    Generate a rich, human-readable explanation for a single packet.
    Extends the existing pkt['summary'] with RFC context.

    Parameters
    ----------
    pkt : dict
        Parsed packet dict from _parse_one().
    verbose : bool
        If True, adds extra RFC background paragraphs and technical detail.
    """
    proto   = pkt.get('proto', '?')
    summary = pkt.get('summary', '')
    src_ip  = pkt.get('src_ip', '')
    dst_ip  = pkt.get('dst_ip', '')
    src_port = pkt.get('src_port')
    dst_port = pkt.get('dst_port')
    flags   = pkt.get('tcp_flags', '')
    ttl     = pkt.get('ttl')
    vlan    = pkt.get('vlan_id')

    parts = [summary] if summary else []

    # RFC context
    db = RFC_DB.get(proto, {})
    if db:
        parts.append(f'[{db["rfc"]}] {db["full"]}: {db["purpose"]}')

    # Protocol-specific explanations
    if proto == 'ARP':
        op = pkt.get('arp_op', '')
        if op == 'REQUEST':
            parts.append(f'Normal ARP discovery — {src_ip} is looking up the MAC for {dst_ip}.')
        elif op == 'REPLY':
            mac = pkt.get('arp_src_mac', '')
            parts.append(f'ARP reply — {dst_ip} now knows {src_ip} is at {mac}.')
        if src_ip == dst_ip:
            parts.append('⚠ Gratuitous ARP detected — sender is claiming ownership of its own IP. '
                         'This can indicate IP address update (HSRP/VRRP failover) or ARP spoofing.')

    elif proto == 'ICMP':
        icmp_type = pkt.get('icmp_type')
        icmp_code = pkt.get('icmp_code', 0)
        if icmp_type == 8:
            parts.append(f'Ping request from {src_ip} to {dst_ip} — testing reachability.')
        elif icmp_type == 0:
            parts.append(f'{dst_ip} is reachable — ping reply received.')
        elif icmp_type == 3:
            parts.append(f'Destination unreachable — packet to {dst_ip} was rejected. '
                         f'Code {icmp_code} indicates the specific reason.')
        elif icmp_type == 11:
            parts.append('TTL expired — this packet was discarded by a router. '
                         'Common in traceroute path discovery.')

    elif proto == 'TCP' or proto in {'HTTP', 'HTTPS', 'SSH', 'FTP', 'Telnet', 'SMTP'}:
        if 'SYN' in flags and 'ACK' not in flags:
            svc_name = _service_name(dst_port) if dst_port else ''
            svc_str  = f' ({svc_name})' if svc_name else ''
            parts.append(
                f'TCP handshake Step 1/3 — SYN: {src_ip}:{src_port} is requesting '
                f'a new connection to {dst_ip}:{dst_port}{svc_str}. '
                f'The client sends its Initial Sequence Number (ISN). (RFC 793 §3.4)'
            )
        elif 'SYN' in flags and 'ACK' in flags:
            parts.append(
                f'TCP handshake Step 2/3 — SYN+ACK: {src_ip} accepted the connection '
                f'from {dst_ip}. Server acknowledges client ISN and sends its own. '
                f'Handshake is 2/3 complete. (RFC 793 §3.4)'
            )
        elif 'ACK' in flags and not flags.replace('ACK', '').strip('-').strip():
            # Pure ACK — could be handshake step 3 or data ACK
            seq = pkt.get('seq')
            ack = pkt.get('ack_num')
            seq_str = f' (SEQ={seq}, ACK={ack})' if seq and ack else ''
            parts.append(
                f'TCP handshake Step 3/3 — ACK{seq_str}: {src_ip} acknowledged '
                f'the server reply. 3-way handshake complete — session is established.'
            )
        elif 'PSH' in flags and 'ACK' in flags:
            size = pkt.get('payload_len') or pkt.get('size', 0)
            size_str = f' ({size}B of data)' if size else ''
            parts.append(
                f'Data transfer{size_str}: {src_ip} is sending application data to '
                f'{dst_ip}:{dst_port}. PSH flag tells the receiver to flush this to '
                f'the application immediately.'
            )
        elif 'RST' in flags:
            parts.append(
                f'⚠ TCP Reset — connection was abruptly terminated by {src_ip}. '
                f'Possible causes: port not open, firewall rejection, application '
                f'crash, or idle connection timeout. (RFC 793)'
            )
        elif 'FIN' in flags:
            if 'ACK' in flags:
                parts.append(
                    f'TCP graceful close (FIN+ACK): {src_ip} is finishing its half '
                    f'of the connection. The other side must also send FIN to fully '
                    f'close. (RFC 793 §3.5)'
                )
            else:
                parts.append(
                    f'TCP FIN: {src_ip} has no more data to send and is beginning '
                    f'a graceful close. (RFC 793 §3.5)'
                )
        if ttl and ttl < 10:
            parts.append(f'⚠ Unusually low TTL={ttl} — packet is near its hop limit. '
                         f'May indicate a routing loop or traceroute probe.')
        if verbose:
            svc_db = RFC_DB.get(proto, {})
            if svc_db:
                parts.append(f'[{svc_db["rfc"]}] {svc_db["full"]}: {svc_db["purpose"]}')

    elif proto == 'DNS':
        qr = pkt.get('dns_qr', '')
        query = pkt.get('dns_query', '')
        answers = pkt.get('dns_answers', [])
        if qr == 'Query' and query:
            parts.append(f'DNS lookup for "{query}" — client needs to resolve this hostname.')
        elif qr == 'Response' and answers:
            parts.append(f'DNS resolved: {answers[0]}' if answers else 'DNS response received.')

    elif proto in ('DHCP', 'DHCP-Server', 'DHCP-Client'):
        msg = pkt.get('dhcp_msg_type', '')
        if msg:
            parts.append(f'DHCP {msg} — automatic IP configuration in progress (RFC 2131 DORA process).')

    elif proto in ('SNMP', 'SNMP-Trap'):
        if proto == 'SNMP-Trap':
            parts.append('⚠ SNMP Trap received — device is reporting an event or alarm unsolicited.')
        else:
            parts.append('SNMP polling — management system reading device metrics/status.')

    elif proto.startswith('ET-'):
        if _AI_EXPLAIN_AVAILABLE:
            parts.append(_explain_unknown(pkt))
        else:
            et = proto[3:]
            parts.append(
                f'Unknown EtherType {et} — no registered decoder. '
                f'May be vendor-proprietary or an Extreme Networks protocol. '
                f'Check Extreme Networks EXOS documentation or use Wireshark.'
            )

    elif proto not in RFC_DB and proto not in _GENERIC_DESCRIPTIONS:
        if _AI_EXPLAIN_AVAILABLE:
            parts.append(_explain_unknown(pkt))
        else:
            parts.append(
                f'Protocol "{proto}" is not in the verified knowledge base. '
                f'Analysis is based on port mapping and heuristics.'
            )

    # Generic description fallback
    if len(parts) == 1 and proto in _GENERIC_DESCRIPTIONS:
        parts.append(_GENERIC_DESCRIPTIONS[proto])

    # VLAN context
    if vlan:
        parts.append(f'VLAN {vlan} — traffic is isolated to this virtual network segment.')

    return '  '.join(parts)


# ── Capture-level summary generator ──────────────────────────────────────────

class PacketSummaryEngine:
    """
    Generates structured AI-ready summaries for a full packet capture.

    Input:  parsed packets list + analysis dict from analyse()
    Output: structured summary text for AI prompt injection
    """

    def __init__(self, packets: list, analysis: dict):
        self.packets  = packets
        self.analysis = analysis

    def generate_capture_summary(self) -> str:
        """
        Build a comprehensive capture summary suitable for injection
        into AI backend prompts.
        """
        a = self.analysis
        total     = a.get('total', len(self.packets))
        proto_cnt = a.get('proto_counts', {})
        src_ips   = a.get('src_ips', {})
        dst_ips   = a.get('dst_ips', {})
        anomalies = a.get('anomalies', [])
        flows     = a.get('flows', [])

        lines = [
            '## Capture Summary',
            '',
            f'- Total packets: {total}',
            f'- Total protocols: {len(proto_cnt)}',
            f'- Top source IPs: {", ".join(list(src_ips.keys())[:5]) or "none"}',
            f'- Top destination IPs: {", ".join(list(dst_ips.keys())[:5]) or "none"}',
            f'- Flows reconstructed: {len(flows)}',
            '',
            '## Protocol Distribution',
        ]
        for proto, count in sorted(proto_cnt.items(), key=lambda x: x[1], reverse=True)[:15]:
            pct = round(count / max(total, 1) * 100, 1)
            rfc = RFC_DB.get(proto, {}).get('rfc', '')
            rfc_str = f'  [{rfc}]' if rfc else ''
            lines.append(f'- {proto}: {count} pkts ({pct}%){rfc_str}')

        lines += ['', '## Key Statistics']

        # ARP
        arp_req   = a.get('arp_reqs_total', 0)
        arp_rep   = a.get('arp_reps_total', 0)
        arp_unans = len(a.get('arp_unanswered', {}))
        if arp_req or arp_rep:
            lines.append(f'- ARP: {arp_req} requests, {arp_rep} replies, {arp_unans} unanswered')

        # TCP
        tcp_syn    = a.get('tcp_syn', 0)
        tcp_synack = a.get('tcp_synack', 0)
        tcp_rst    = a.get('tcp_rst', 0)
        tcp_fin    = a.get('tcp_fin', 0)
        if tcp_syn:
            lines.append(f'- TCP: {tcp_syn} SYN, {tcp_synack} SYN+ACK, {tcp_rst} RST, {tcp_fin} FIN')

        # ICMP
        icmp_req = a.get('icmp_req', 0)
        icmp_rep = a.get('icmp_rep', 0)
        icmp_unr = a.get('icmp_unr', 0)
        if icmp_req or icmp_rep:
            lines.append(f'- ICMP: {icmp_req} echo requests, {icmp_rep} replies, {icmp_unr} unreachable')

        # Anomalies
        if anomalies:
            lines += ['', '## Detected Anomalies']
            for a_item in anomalies[:10]:
                lines.append(f'- {a_item}')

        # RFC context for top protocols
        top_protos = list(proto_cnt.keys())[:8]
        lines += ['', '## RFC Protocol Context']
        for proto in top_protos:
            db = RFC_DB.get(proto, {})
            if db:
                lines.append(f'**{proto} ({db["rfc"]})**: {db["purpose"]}')
                lines.append(f'  Normal: {db["normal"]}')

        return '\n'.join(lines)

    def generate_flow_summary(self, flow: dict, verbose: bool = False) -> str:
        """
        Generate a human-readable explanation for a single flow.

        Parameters
        ----------
        flow : dict
            FlowRecord.to_dict() from the flow engine.
        verbose : bool
            If True, calls ai_explain for a full multi-paragraph narrative.
        """
        # Delegate to the richer ai_explain module when available
        if verbose and _AI_EXPLAIN_AVAILABLE:
            from ai_explain import ConversationNarrator
            narrator = ConversationNarrator(self.packets, self.analysis)
            return narrator.narrate(flow)

        proto    = flow.get('app_proto') or flow.get('proto', '?')
        src_ip   = flow.get('src_ip', '')
        dst_ip   = flow.get('dst_ip', '')
        src_port = flow.get('src_port', 0)
        dst_port = flow.get('dst_port', 0)
        pkts     = flow.get('pkt_count', 0)
        dur_ms   = flow.get('duration_ms', 0)
        is_complete = flow.get('is_complete', False)
        is_one_way  = flow.get('is_one_way', False)
        has_errors  = flow.get('has_errors', False)
        tcp_state   = flow.get('tcp_state', '')
        retx        = flow.get('retransmissions', 0)
        dup_acks    = flow.get('dup_acks', 0)
        zero_win    = flow.get('zero_windows', 0)
        fwd_bytes   = flow.get('fwd_bytes', 0)
        rev_bytes   = flow.get('rev_bytes', 0)
        byte_total  = flow.get('byte_count', fwd_bytes + rev_bytes)

        # Opening sentence
        dur_str  = f', {dur_ms:.0f}ms' if dur_ms else ''
        byte_str = f', {_human_bytes_local(byte_total)}' if byte_total else ''
        parts = [
            flow.get('summary') or
            f'{proto} session: {src_ip}:{src_port} ↔ {dst_ip}:{dst_port} '
            f'({pkts} pkts{byte_str}{dur_str})'
        ]

        db = RFC_DB.get(proto, {})
        if db:
            parts.append(f'[{db["rfc"]}] {db["purpose"]}')

        # Session state
        if is_complete:
            parts.append(f'Session completed successfully.')
        elif tcp_state == 'half-open':
            parts.append(
                f'⚠ Half-open connection: SYN sent but no SYN+ACK received. '
                f'Possible causes: host down, firewall dropping connection, or port scan.'
            )
        elif tcp_state == 'reset':
            parts.append('⚠ Session reset abruptly (RST). Connection was not gracefully closed.')
        elif tcp_state == 'established':
            parts.append('Connection established — 3-way handshake completed.')
        elif is_one_way:
            parts.append(f'One-way flow: traffic only from {src_ip}. No response seen.')

        # TCP quality signals (new FlowRecord fields)
        quality: list[str] = []
        if retx > 0:
            quality.append(f'{retx} retransmission{"s" if retx > 1 else ""} (packet loss signal, RFC 793 §3.5)')
        if dup_acks >= 3:
            quality.append(f'{dup_acks} duplicate ACKs (fast retransmit trigger, RFC 5681)')
        if zero_win > 0:
            quality.append(f'{zero_win} zero-window event{"s" if zero_win > 1 else ""} (receiver buffer full)')
        if quality:
            parts.append('Quality signals: ' + ', '.join(quality) + '.')

        if has_errors:
            parts.append('Errors detected in this flow (ICMP unreachable, TCP RST, or similar).')

        if db.get('anomalies') and (has_errors or is_one_way or tcp_state in ('half-open', 'reset')):
            parts.append('Known anomaly patterns for this protocol:')
            for anom in db['anomalies'][:3]:
                parts.append(f'  • {anom}')

        return '  '.join(parts)


# ── AI prompt builder ────────────────────────────────────────────────────────

def build_ai_prompt(capture_summary: str,
                    question: str,
                    anomaly_summary: str = '',
                    include_rfc: bool = True) -> str:
    """
    Build an enriched AI prompt combining:
      - Capture context
      - Anomaly findings
      - RFC grounding material
      - User question

    This replaces the basic prompt construction in ask_ai() with richer context.
    """
    sections = []

    if include_rfc:
        sections.append(_rfc_grounding_context())

    sections.append('## Current Capture Analysis\n\n' + capture_summary)

    if anomaly_summary:
        sections.append('## Anomaly Findings\n\n' + anomaly_summary)

    sections.append(
        '## Analysis Guidelines\n\n'
        '- Reference RFC numbers when explaining protocol behaviour\n'
        '- For unknown protocols, explicitly state this is best-effort analysis\n'
        '- Use plain English — avoid jargon where possible\n'
        '- Prioritise actionable recommendations\n'
        '- For EXOS switches, provide specific CLI commands where relevant\n'
    )

    sections.append(f'## Question\n\n{question}')

    return '\n\n---\n\n'.join(sections)


def _rfc_grounding_context() -> str:
    """Generate a brief RFC grounding context for AI prompts."""
    key_protocols = ['ARP', 'TCP', 'UDP', 'ICMP', 'DNS', 'DHCP', 'SNMP', 'LLDP', 'STP', 'EAPoL']
    lines = ['## RFC Protocol Reference\n']
    for proto in key_protocols:
        db = RFC_DB.get(proto, {})
        if db:
            lines.append(f'**{proto} ({db["rfc"]})**: {db["purpose"]}')
    return '\n'.join(lines)


def anomaly_to_english(anomaly: dict, verbose: bool = False) -> str:
    """
    Convert a structured anomaly finding dict into a plain-English explanation.
    Works with findings from _rule_engine(), _ml_score(), and
    anomaly_rules.run_extended_rules().

    Parameters
    ----------
    anomaly : dict
        Finding dict. Expected keys: title, detail, evidence, severity,
        layer, protocol, rfc_ref, category.
    verbose : bool
        If True and ai_explain is available, produces a full multi-section
        explanation with root causes and EXOS remediation commands.
    """
    if verbose and _AI_EXPLAIN_AVAILABLE:
        return _explain_anomaly_verbose(anomaly, verbose=True)

    title    = anomaly.get('title', 'Unknown anomaly')
    detail   = anomaly.get('detail', '')
    evidence = anomaly.get('evidence', '')
    severity = anomaly.get('severity', 'info').upper()
    layer    = anomaly.get('layer', '')
    proto    = anomaly.get('protocol', '')
    rfc_ref  = anomaly.get('rfc_ref', '')
    category = anomaly.get('category', '').lower()

    severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡',
                      'LOW': '🔵', 'INFO': 'ℹ'}.get(severity, 'ℹ')
    parts = [f'{severity_emoji} [{severity}] {title}']

    if detail:
        parts.append(detail)
    if evidence:
        ev_str = (', '.join(f'{k}={v}' for k, v in list(evidence.items())[:4])
                  if isinstance(evidence, dict) else str(evidence))
        parts.append(f'Evidence: {ev_str}')

    # Category-specific remediation hints
    t = title.lower()
    if 'arp flood' in t or 'arp storm' in t:
        parts.append(
            'Action: Check for network loops (show stpd), '
            'identify the flooding source (show fdb), '
            'apply ARP rate limiting.'
        )
    elif 'arp conflict' in t or 'duplicate ip' in t:
        parts.append(
            'Action: Identify the conflicting devices (show arp), '
            'verify DHCP pool configuration, '
            'consider enabling Dynamic ARP Inspection.'
        )
    elif 'syn flood' in t or 'half-open' in t:
        parts.append(
            'Action: Apply SYN rate-limiting ACL (configure access-policy), '
            'verify server capacity.'
        )
    elif 'dns tunnel' in t or 'dns entropy' in t:
        parts.append(
            'Action: Investigate DNS query payloads for encoded data. '
            'Consider DNS filtering or blocking high-entropy queries.'
        )
    elif 'dhcp starvation' in t:
        parts.append(
            'Action: Check DHCP pool size (show dhcp-server), '
            'identify the exhausting client, '
            'implement DHCP snooping.'
        )
    elif 'snmp trap' in t or ('snmp' in t and 'storm' in t):
        parts.append(
            'Action: Identify the trapping device (show snmp traps), '
            'investigate the root condition, '
            'tune trap thresholds.'
        )
    elif 'zero window' in t:
        parts.append(
            'Action: Investigate receiver host performance. '
            'Check CPU/memory usage and network buffer tuning.'
        )
    elif 'retransmission' in t:
        parts.append(
            'Action: Check port error counters (show port rxerrors), '
            'verify duplex settings (show port info), '
            'investigate cabling.'
        )
    elif 'lldp' in t and ('topology' in t or 'rapid' in t):
        parts.append(
            'Action: Review LLDP neighbors (show lldp neighbors), '
            'check for port flapping or misconfigured LLDP intervals.'
        )
    elif 'vlan' in t:
        parts.append(
            'Action: Verify VLAN configuration (show vlan), '
            'check port tagging (show port info detail).'
        )
    elif 'unknown proto' in t or 'unregistered' in t:
        parts.append(
            'Action: Capture payload bytes, check vendor documentation, '
            'use Wireshark with custom dissectors for identification.'
        )
    elif 'broadcast storm' in t:
        parts.append(
            'Action: Check STP convergence (show stpd), '
            'identify the broadcast source (show fdb statistics), '
            'apply storm control.'
        )
    elif 'mac flap' in t or 'spoofing' in t:
        parts.append(
            'Action: Review MAC table (show fdb), '
            'identify conflicting ports, '
            'consider port security or 802.1X.'
        )

    # RFC context
    if rfc_ref:
        parts.append(f'Standard: {rfc_ref}')
    elif proto and proto in RFC_DB:
        db = RFC_DB[proto]
        matching = [a for a in db.get('anomalies', [])
                    if any(word in title.lower() for word in a.lower().split()[:3])]
        if matching:
            parts.append(f'RFC context ({db["rfc"]}): {matching[0]}')

    return '  '.join(parts)


def generate_exos_recommendations(anomalies: list, protocols: list) -> list[str]:
    """
    Generate EXOS-specific CLI recommendations based on detected anomalies and protocols.
    Returns list of recommendation strings with commands.
    """
    recs = []

    # Build lookup sets for quick matching
    titles = ' '.join(a.get('title', '') for a in anomalies).lower()
    proto_set = set(p.upper() for p in protocols)

    if 'arp' in titles or 'ARP' in proto_set:
        recs.append(
            'ARP traffic detected. To investigate on EXOS:\n'
            '  show arp                     # View ARP table\n'
            '  clear arp                    # Clear ARP cache if stale entries\n'
            '  show iparp                   # View IP ARP statistics'
        )

    if 'syn flood' in titles or 'half-open' in titles:
        recs.append(
            'SYN flood / half-open connections detected. EXOS mitigation:\n'
            '  configure access-policy      # Apply rate-limiting ACL\n'
            '  show access-list             # Review existing ACLs'
        )

    if 'snmp' in titles.lower() or 'SNMP' in proto_set or 'SNMP-Trap' in proto_set:
        recs.append(
            'SNMP traffic detected. EXOS SNMP management:\n'
            '  show snmp                    # View SNMP configuration\n'
            '  configure snmp add community # Update community strings\n'
            '  show snmpv3                  # Check SNMPv3 status'
        )

    if 'LLDP' in proto_set:
        recs.append(
            'LLDP neighbors detected. EXOS topology discovery:\n'
            '  show lldp neighbors          # View discovered neighbors\n'
            '  show lldp port all           # Per-port LLDP status'
        )

    if 'STP' in proto_set or 'topology change' in titles:
        recs.append(
            'STP topology changes detected. EXOS investigation:\n'
            '  show stpd detail             # STP domain status\n'
            '  show stpd ports              # Per-port STP state\n'
            '  configure stpd edge-safeguard # Protect edge ports'
        )

    if 'EAPoL' in proto_set or '802.1x' in titles:
        recs.append(
            '802.1X authentication traffic detected. EXOS NetLogin:\n'
            '  show netlogin                # Global 802.1X status\n'
            '  show netlogin port all       # Per-port authentication state\n'
            '  show netlogin session        # Active authenticated sessions'
        )

    if 'mac flap' in titles or 'spoofing' in titles:
        recs.append(
            'MAC instability detected. EXOS investigation:\n'
            '  show fdb                     # View MAC forwarding table\n'
            '  show fdb statistics          # MAC table statistics\n'
            '  show port info               # Port status and error counters'
        )

    if not recs:
        recs.append(
            'General EXOS packet investigation commands:\n'
            '  show port rxerrors           # Receive error counters\n'
            '  show port txerrors           # Transmit error counters\n'
            '  show port info               # Port link and configuration status\n'
            '  debug packet capture ports <port> on  # Live capture on switch port'
        )

    return recs
