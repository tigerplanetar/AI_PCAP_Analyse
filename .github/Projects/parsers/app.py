"""
parsers/app.py — Application Layer Protocol Parsers
=====================================================
Modular parsers for:  DNS · DHCP · SNMP

These parsers produce richer, more human-readable summaries than simple
port-based classification. They are designed to be called after the
L4 parser has set ctx.transport_proto, ctx.src_port, ctx.dst_port.

RFC references:
  DNS   — RFC 1035, RFC 3596 (AAAA)
  DHCP  — RFC 2131
  SNMP  — RFC 3411 (SNMPv3), RFC 1157 (v1), RFC 1441 (v2)
"""

from __future__ import annotations
import struct
from parsers.registry import BaseParser, ParseContext


# ── DNS Parser ────────────────────────────────────────────────────────────────

_DNS_QTYPES = {
    1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX',
    16: 'TXT', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 255: 'ANY',
    41: 'OPT', 43: 'DS', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY',
}

_DNS_RCODES = {
    0: 'No Error', 1: 'Format Error', 2: 'Server Failure',
    3: 'NXDOMAIN (Name does not exist)', 4: 'Not Implemented',
    5: 'Refused', 9: 'Not Authorized',
}


def _dns_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    """Decode a DNS domain name, handling compression pointers."""
    if depth > 10:
        return '<max-depth>', offset
    labels = []
    i = offset
    jumped = False
    orig_end = offset
    while i < len(data):
        length = data[i]
        if length == 0:
            i += 1
            if not jumped:
                orig_end = i
            break
        if (length & 0xC0) == 0xC0:
            if i + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[i + 1]
            if not jumped:
                orig_end = i + 2
            name, _ = _dns_name(data, ptr, depth + 1)
            labels.append(name)
            jumped = True
            break
        i += 1
        labels.append(data[i:i + length].decode('ascii', errors='replace'))
        i += length
    if not jumped:
        orig_end = i
    return '.'.join(labels) or '.', orig_end


class DNSParser(BaseParser):
    """RFC 1035 — Domain Name System."""
    priority = 80

    def can_parse(self, ctx: ParseContext) -> bool:
        return (ctx.transport_proto in ('TCP', 'UDP') and
                ctx.pkt.get('proto') in ('DNS', 'UDP', 'TCP') and
                (ctx.src_port == 53 or ctx.dst_port == 53) and
                len(ctx.raw) >= 12)

    def parse(self, ctx: ParseContext):
        d  = ctx.raw
        # For DNS over TCP there's a 2-byte length prefix
        if ctx.transport_proto == 'TCP' and len(d) >= 2:
            d = d[2:]
        if len(d) < 12:
            return 'DNS', 'DNS (too short)', [], ctx

        txid    = struct.unpack('!H', d[0:2])[0]
        flags   = struct.unpack('!H', d[2:4])[0]
        qdcount = struct.unpack('!H', d[4:6])[0]
        ancount = struct.unpack('!H', d[6:8])[0]
        nscount = struct.unpack('!H', d[8:10])[0]
        arcount = struct.unpack('!H', d[10:12])[0]

        is_response = bool(flags & 0x8000)
        opcode      = (flags >> 11) & 0xF
        rcode       = flags & 0xF
        tc          = bool(flags & 0x0200)   # truncated
        rd          = bool(flags & 0x0100)   # recursion desired
        ra          = bool(flags & 0x0080)   # recursion available

        rcode_str = _DNS_RCODES.get(rcode, f'RCODE-{rcode}')
        direction = 'Response' if is_response else 'Query'

        # Parse first question
        qname = ''; qtype_str = ''; qtype_id = 0
        try:
            pos = 12
            qname, pos = _dns_name(d, pos)
            if pos + 4 <= len(d):
                qtype_id = struct.unpack('!H', d[pos:pos+2])[0]
                qtype_str = _DNS_QTYPES.get(qtype_id, str(qtype_id))
        except Exception:
            pass

        # Parse answer RRs for responses
        answers = []
        if is_response and ancount > 0:
            try:
                pos = 12
                # Skip questions
                for _ in range(qdcount):
                    _, pos = _dns_name(d, pos)
                    pos += 4
                # Read answers
                for _ in range(min(ancount, 5)):
                    rr_name, pos = _dns_name(d, pos)
                    if pos + 10 > len(d):
                        break
                    rr_type = struct.unpack('!H', d[pos:pos+2])[0]
                    _rr_class = struct.unpack('!H', d[pos+2:pos+4])[0]
                    _rr_ttl   = struct.unpack('!I', d[pos+4:pos+8])[0]
                    rdlength  = struct.unpack('!H', d[pos+8:pos+10])[0]
                    pos += 10
                    rdata = d[pos:pos+rdlength]
                    pos  += rdlength
                    rr_type_str = _DNS_QTYPES.get(rr_type, str(rr_type))
                    if rr_type == 1 and len(rdata) == 4:
                        answers.append(f'{rr_name} → {".".join(str(b) for b in rdata)} (A)')
                    elif rr_type == 28 and len(rdata) == 16:
                        groups = [struct.unpack('!H', rdata[i*2:(i+1)*2])[0] for i in range(8)]
                        ipv6 = ':'.join(f'{g:04x}' for g in groups)
                        answers.append(f'{rr_name} → {ipv6} (AAAA)')
                    elif rr_type in (2, 5, 12):
                        try:
                            name, _ = _dns_name(d, pos - rdlength)
                            answers.append(f'{rr_name} → {name} ({rr_type_str})')
                        except Exception:
                            answers.append(f'{rr_name} → [{rr_type_str}]')
                    else:
                        answers.append(f'{rr_name} [{rr_type_str}]')
            except Exception:
                pass

        # Build summary
        if qname and not is_response:
            summary = f'DNS Query: {qname} ({qtype_str})'
        elif qname and is_response and answers:
            summary = f'DNS Response: {qname} → {answers[0]}'
        elif qname and is_response:
            summary = f'DNS Response: {qname} — {rcode_str}'
        else:
            summary = f'DNS {direction} (TXID=0x{txid:04x})'

        ctx.pkt.update({
            'proto': 'DNS', 'summary': summary,
            'dns_txid': txid, 'dns_qr': direction,
        })
        if qname:
            ctx.pkt['dns_query'] = qname
        if answers:
            ctx.pkt['dns_answers'] = answers

        fields = [
            self._field('Transaction ID',     f'0x{txid:04x}',                      'Request/response correlation'),
            self._field('Direction',          direction,                              'QR flag'),
            self._field('Opcode',             f'{opcode} ({"Standard Query" if opcode == 0 else f"Opcode-{opcode}"})', 'Query type'),
            self._field('Questions',          str(qdcount),                          'Number of question records'),
            self._field('Answer RRs',         str(ancount),                          'Number of answer records'),
            self._field('Authority RRs',      str(nscount),                          'Authoritative name servers'),
            self._field('Additional RRs',     str(arcount),                          'Additional records'),
            self._field('Recursion Desired',  'Yes' if rd else 'No',                 'Client requests recursive resolution'),
            self._field('Recursion Available','Yes' if ra else 'No',                 'Server supports recursion'),
            self._field('Truncated',          'Yes' if tc else 'No',                 'Response truncated — use TCP for full answer'),
        ]
        if rcode and is_response:
            fields.append(self._field('Response Code', f'{rcode} ({rcode_str})', 'DNS error'))
        if qname:
            fields.append(self._field('Query Name', qname,    f'Type: {qtype_str}'))
        for ans in answers[:3]:
            fields.append(self._field('Answer', ans, 'Resolved record'))
        if len(answers) > 3:
            fields.append(self._field('…and more', f'{len(answers) - 3} additional answers', ''))

        layer = self._layer('DNS — Domain Name System  (RFC 1035)', '#fbbf24', fields)
        return 'DNS', summary, [layer], ctx


# ── DHCP Parser ───────────────────────────────────────────────────────────────

_DHCP_MSG_TYPES = {
    1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline',
    5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform',
}

_DHCP_SUMMARIES = {
    1: 'Client searching for DHCP server',
    2: 'Server offering IP address lease',
    3: 'Client requesting offered IP address',
    4: 'Client declining offered address (conflict detected)',
    5: 'Lease confirmed — IP address assigned',
    6: 'Server rejected request — client must restart discovery',
    7: 'Client releasing IP address lease',
    8: 'Client requesting configuration (no IP needed)',
}


class DHCPParser(BaseParser):
    """RFC 2131 — Dynamic Host Configuration Protocol."""
    priority = 85

    def can_parse(self, ctx: ParseContext) -> bool:
        return (ctx.transport_proto == 'UDP' and
                ctx.pkt.get('proto') in ('DHCP-Server', 'DHCP-Client', 'UDP') and
                ctx.src_port in (67, 68) and ctx.dst_port in (67, 68) and
                len(ctx.raw) >= 240)

    def parse(self, ctx: ParseContext):
        d = ctx.raw
        op      = d[0]   # 1=BOOTREQUEST, 2=BOOTREPLY
        htype   = d[1]   # hardware type (1=Ethernet)
        hlen    = d[2]   # hardware address length
        hops    = d[3]   # relay agent hops
        xid     = struct.unpack('!I', d[4:8])[0]
        secs    = struct.unpack('!H', d[8:10])[0]
        flags   = struct.unpack('!H', d[10:12])[0]
        ciaddr  = '.'.join(str(b) for b in d[12:16])   # client IP (if known)
        yiaddr  = '.'.join(str(b) for b in d[16:20])   # offered IP
        siaddr  = '.'.join(str(b) for b in d[20:24])   # server IP
        giaddr  = '.'.join(str(b) for b in d[24:28])   # relay agent IP
        chaddr  = ':'.join(f'{b:02x}' for b in d[28:28+hlen]) if hlen <= 16 else ''

        # Parse options (cookie at offset 236)
        msg_type = 0; subnet_mask = ''; router = ''; lease_time = 0
        dns_servers: list[str] = []; domain_name = ''; hostname = ''
        if len(d) >= 240 and d[236:240] == b'\x63\x82\x53\x63':
            pos = 240
            try:
                while pos < len(d):
                    opt = d[pos]; pos += 1
                    if opt == 255: break
                    if opt == 0: continue
                    if pos >= len(d): break
                    opt_len = d[pos]; pos += 1
                    val = d[pos:pos + opt_len]; pos += opt_len
                    if opt == 53 and opt_len == 1:
                        msg_type = val[0]
                    elif opt == 1 and opt_len == 4:
                        subnet_mask = '.'.join(str(b) for b in val)
                    elif opt == 3 and opt_len >= 4:
                        router = '.'.join(str(b) for b in val[:4])
                    elif opt == 51 and opt_len == 4:
                        lease_time = struct.unpack('!I', val)[0]
                    elif opt == 6 and opt_len >= 4:
                        for i in range(0, min(opt_len, 8), 4):
                            dns_servers.append('.'.join(str(b) for b in val[i:i+4]))
                    elif opt == 15:
                        domain_name = val.decode('ascii', errors='replace')
                    elif opt == 12:
                        hostname = val.decode('ascii', errors='replace')
            except Exception:
                pass

        msg_name = _DHCP_MSG_TYPES.get(msg_type, f'Type-{msg_type}')
        msg_desc = _DHCP_SUMMARIES.get(msg_type, '')
        op_str   = 'BOOTREQUEST' if op == 1 else 'BOOTREPLY'

        is_zero = lambda ip: ip in ('0.0.0.0', '')

        summary = f'DHCP {msg_name}: {msg_desc}' if msg_desc else f'DHCP {op_str} (xid=0x{xid:08x})'
        ctx.pkt.update({'proto': 'DHCP', 'summary': summary, 'dhcp_msg_type': f'DHCP {msg_name}'})

        fields = [
            self._field('Message Type',    f'{msg_type} ({msg_name})',   msg_desc),
            self._field('Operation',       op_str,                        '1=Request 2=Reply'),
            self._field('Transaction ID',  f'0x{xid:08x}',               'Client-generated correlation ID'),
            self._field('Seconds Elapsed', str(secs),                    'Time since client started process'),
            self._field('Broadcast Flag',  'Yes' if flags & 0x8000 else 'No', 'Request broadcast reply'),
            self._field('Client IP',       ciaddr if not is_zero(ciaddr) else '(none)', 'Renewing clients set this'),
            self._field('Offered IP',      yiaddr if not is_zero(yiaddr) else '(pending)', 'IP being assigned'),
            self._field('Server IP',       siaddr if not is_zero(siaddr) else '(discover)', 'DHCP server'),
            self._field('Relay IP',        giaddr if not is_zero(giaddr) else '(direct)', 'DHCP relay agent'),
            self._field('Client MAC',      chaddr,                        'MAC of requesting device'),
        ]
        if subnet_mask:
            fields.append(self._field('Subnet Mask',  subnet_mask,             'Option 1'))
        if router:
            fields.append(self._field('Default Gateway', router,               'Option 3'))
        if dns_servers:
            fields.append(self._field('DNS Servers',  ', '.join(dns_servers),  'Option 6'))
        if lease_time:
            hours, rem = divmod(lease_time, 3600)
            mins, secs_ = divmod(rem, 60)
            fields.append(self._field('Lease Time',   f'{lease_time}s ({hours}h {mins}m {secs_}s)', 'Option 51'))
        if domain_name:
            fields.append(self._field('Domain Name',  domain_name,             'Option 15'))
        if hostname:
            fields.append(self._field('Hostname',     hostname,                'Option 12'))
        if hops > 0:
            fields.append(self._field('Relay Hops',   str(hops),               'Packet traversed DHCP relay agents'))

        layer = self._layer('DHCP — Dynamic Host Configuration Protocol  (RFC 2131)', '#4ade80', fields)
        return 'DHCP', summary, [layer], ctx


# ── SNMP Parser ───────────────────────────────────────────────────────────────

_SNMP_PDU = {
    0: 'GetRequest', 1: 'GetNextRequest', 2: 'GetResponse', 3: 'SetRequest',
    4: 'Trap-v1', 5: 'GetBulkRequest', 6: 'InformRequest', 7: 'SNMPv2-Trap',
}


class SNMPParser(BaseParser):
    """RFC 3411 / RFC 1157 — Simple Network Management Protocol."""
    priority = 85

    def can_parse(self, ctx: ParseContext) -> bool:
        return (ctx.transport_proto == 'UDP' and
                (ctx.src_port in (161, 162) or ctx.dst_port in (161, 162)) and
                len(ctx.raw) >= 10 and ctx.raw[0] == 0x30)

    def parse(self, ctx: ParseContext):
        d = ctx.raw
        try:
            pos = 1
            # Skip SEQUENCE length
            if d[pos] & 0x80:
                pos += 1 + (d[pos] & 0x7F)
            else:
                pos += 1
            if d[pos] != 0x02 or d[pos+1] != 0x01:
                raise ValueError('Not SNMP')
            ver = d[pos+2]; pos += 3
            if d[pos] != 0x04:
                raise ValueError('No community')
            clen = d[pos+1]; pos += 2
            community = d[pos:pos+clen].decode('ascii', errors='replace')
            pos += clen
            if not (0xA0 <= d[pos] <= 0xA7):
                raise ValueError('No PDU tag')
            pdu_tag  = d[pos] - 0xA0
            pdu_name = _SNMP_PDU.get(pdu_tag, f'PDU-{pdu_tag}')
            ver_name = {0: 'v1', 1: 'v2c', 3: 'v3'}.get(ver, f'v{ver}')
            is_trap  = pdu_tag in (4, 7)
            proto = 'SNMP-Trap' if is_trap else 'SNMP'

            src, dst = ctx.pkt.get('src_ip', '?'), ctx.pkt.get('dst_ip', '?')
            sp, dp   = ctx.src_port, ctx.dst_port
            summary  = f'{proto} {ver_name} {pdu_name}  {src}:{sp} → {dst}:{dp}  community="{community}"'

            ctx.pkt.update({'proto': proto, 'summary': summary})

            fields = [
                self._field('SNMP Version',  ver_name,                   'v1=RFC 1157, v2c=RFC 1441, v3=RFC 3411'),
                self._field('Community',     community,                  f'{"⚠ Plaintext in v1/v2c — no encryption" if ver < 3 else "v3 uses USM authentication"}'),
                self._field('PDU Type',      f'{pdu_tag} ({pdu_name})',  'SNMP operation'),
                self._field('Direction',     f'{src} → {dst}',          f'Port {sp} → {dp}'),
            ]
            if is_trap:
                fields.append(self._field('Trap Type', 'SNMP Trap / InformRequest', 'Unsolicited event notification from agent'))
            if ver < 3 and community.lower() in ('public', 'private'):
                fields.append(self._field('⚠ Security Warning',
                    f'Community "{community}" is a well-known default — change immediately',
                    'Default community strings are a security risk'))

            layer = self._layer(f'SNMP — Simple Network Management Protocol  ({ver_name})', '#34d399', fields)
            return proto, summary, [layer], ctx

        except Exception:
            return ctx.pkt.get('proto', 'SNMP'), ctx.pkt.get('summary', 'SNMP'), [], ctx
