"""
parsers/unknown.py — Unknown / Unrecognised Protocol Handler
=============================================================
Ensures every packet gets a meaningful summary and layer entry,
even when the protocol cannot be identified.

Design goals:
  - Never leave summary blank
  - Provide maximum context from available bytes
  - Attempt heuristic identification using well-known signatures
  - Flag vendor-specific / proprietary EtherTypes with known names
  - Behave as a last-resort fallback in the ParserRegistry
"""

from __future__ import annotations
import struct
from parsers.registry import BaseParser, ParseContext


# ── Well-known EtherType names (beyond what the main script covers) ───────────
_KNOWN_ETHERTYPES: dict[int, str] = {
    0x0800: 'IPv4',          0x0806: 'ARP',           0x0842: 'Wake-on-LAN',
    0x22F3: 'TRILL',         0x22EA: 'L2-ISIS',       0x6003: 'DECnet Phase IV',
    0x8035: 'RARP',          0x809B: 'AppleTalk',     0x80F3: 'AppleTalk ARP',
    0x8100: 'VLAN (802.1Q)', 0x8137: 'IPX',           0x86DD: 'IPv6',
    0x8808: 'MAC Control',   0x880B: 'PPP',           0x8847: 'MPLS Unicast',
    0x8848: 'MPLS Multicast',0x8863: 'PPPoE Discovery',0x8864: 'PPPoE Session',
    0x888E: 'EAPoL (802.1X)',0x88A8: 'Provider Bridging (802.1ad)',
    0x88B5: 'IEEE 802.1 Test', 0x88B6: 'IEEE 802.1 OAM',
    0x88CC: 'LLDP',          0x88E7: 'PBB (802.1ah)', 0x88F7: 'PTP (IEEE 1588)',
    0x8902: 'IEEE 802.3 OAM',0x8906: 'FCoE',          0x8914: 'FCoE Init',
    0x8915: 'RoCE',          0x9000: 'Loop (Ethernet Loopback)',
    0x9100: 'Double-tagged VLAN (QinQ)',
    0xCAFE: 'Cisco PACE',
}

# Well-known vendor OUIs (first 3 bytes of MAC, to note vendor)
_VENDOR_OUIS: dict[str, str] = {
    '00:00:0c': 'Cisco',         '00:1a:a1': 'Cisco',
    '00:0d:65': 'Cisco',         '00:04:27': 'Extreme Networks',
    '00:e0:2b': 'Extreme Networks', '00:19:30': 'Extreme Networks',
    '00:04:96': 'Extreme Networks', '08:00:20': 'Sun Microsystems',
    '00:50:56': 'VMware',         '00:0c:29': 'VMware',
    '52:54:00': 'QEMU/KVM',      '08:00:27': 'VirtualBox',
    'aa:bb:cc': 'Test/Lab',
}


def _oui_vendor(mac: str) -> str:
    if not mac or len(mac) < 8:
        return ''
    oui = mac[:8].lower()
    return _VENDOR_OUIS.get(oui, '')


# ── Heuristic payload signatures ─────────────────────────────────────────────
def _heuristic_identify(data: bytes, eth_type: int) -> str:
    """
    Attempt best-effort protocol identification from payload bytes.
    Returns a human-readable description or empty string.
    """
    if len(data) < 4:
        return ''

    # Check for well-known EtherType first
    if eth_type in _KNOWN_ETHERTYPES:
        return f'{_KNOWN_ETHERTYPES[eth_type]} — no decoder registered'

    # Heuristic patterns
    if data[:2] == b'\x03\x00':
        return 'Possible LLC / 802.2 frame'
    if data[:4] == b'\x00\x00\x00\x00':
        return 'All-zero payload — possible keep-alive or padding'
    if data[0] == 0x01 and data[1] in (0x00, 0x01, 0x02):
        return 'Possible STP/RSTP BPDU (LLC-encapsulated)'
    if data[:3] == b'OUI' or (eth_type >= 0x0600 and eth_type <= 0x0700):
        return 'Possible vendor-proprietary frame'
    if eth_type >= 0x88B5 and eth_type <= 0x88B7:
        return 'IEEE 802.1 experimental / vendor-specific protocol'
    if eth_type in range(0xFF00, 0xFFFF):
        return 'Cisco PVST / vendor-specific'
    if data[:4] == b'\x03\x0f\x00\x00':
        return 'Possible Extreme EXOS proprietary frame'
    if len(data) >= 2 and data[0] == 0x30:
        return 'Possible ASN.1/BER encoded data (SNMP/LDAP/X.509)'
    if len(data) >= 4 and data[0:2] in (b'\x16\x03', b'\x15\x03', b'\x14\x03'):
        return 'TLS record detected'
    if len(data) >= 8 and data[0:4] == b'RTSP':
        return 'RTSP media control protocol'

    return f'EtherType 0x{eth_type:04x} — no matching signature found'


def _payload_preview(data: bytes, max_bytes: int = 16) -> str:
    """Return a hex+ASCII preview of raw bytes."""
    chunk = data[:max_bytes]
    hex_part = ' '.join(f'{b:02x}' for b in chunk)
    asc_part = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in chunk)
    more = '…' if len(data) > max_bytes else ''
    return f'{hex_part}  |{asc_part}|{more}'


class UnknownProtocolParser(BaseParser):
    """
    Fallback parser for any unrecognised EtherType or protocol.
    Guarantees every packet has a non-empty summary and layer.
    """
    priority = 999   # always last

    def can_parse(self, ctx: ParseContext) -> bool:
        return True   # accepts everything

    def parse(self, ctx: ParseContext):
        d        = ctx.raw
        et       = ctx.eth_type
        src_mac  = ctx.pkt.get('src_mac', ctx.src_mac)
        dst_mac  = ctx.pkt.get('dst_mac', ctx.dst_mac)

        et_name  = _KNOWN_ETHERTYPES.get(et, '')
        hint     = _heuristic_identify(d, et)
        preview  = _payload_preview(d) if d else '(no payload)'
        src_vendor = _oui_vendor(src_mac)
        dst_vendor = _oui_vendor(dst_mac)

        et_label = f'ET-0x{et:04x}'

        if et_name:
            summary = f'Unknown EtherType 0x{et:04x} ({et_name})'
        elif hint:
            summary = f'Unknown EtherType 0x{et:04x} — {hint}'
        else:
            summary = f'Unknown EtherType 0x{et:04x} ({len(d)} bytes)'

        ctx.pkt.update({'proto': et_label, 'summary': summary})

        fields = [
            self._field('EtherType',   f'0x{et:04x}',   et_name or 'Unrecognised EtherType'),
            self._field('Source MAC',  src_mac,          f'Vendor: {src_vendor}' if src_vendor else 'Unknown vendor'),
            self._field('Dest MAC',    dst_mac,          f'Vendor: {dst_vendor}' if dst_vendor else 'Unknown vendor'),
            self._field('Payload',     f'{len(d)} bytes', 'Raw frame payload size'),
            self._field('Preview',     preview,           'First bytes of payload (hex + ASCII)'),
        ]
        if hint:
            fields.append(self._field('Heuristic',    hint,     'Best-effort protocol guess'))
        if et_name:
            fields.append(self._field('EtherType Name', et_name, 'Registered EtherType — parser not yet implemented'))
        if src_vendor:
            fields.append(self._field('Source Vendor', src_vendor, 'OUI lookup'))
        if not et_name and not hint:
            fields.append(self._field('Next Step',
                'Review with Wireshark or check switch logs for context',
                'AI analysis may provide additional clues'))

        # Ensure proto and summary are set even if called on a pkt with previous state
        if not ctx.pkt.get('summary'):
            ctx.pkt['summary'] = summary

        layer = self._layer(
            f'Unknown / Proprietary  (EtherType 0x{et:04x})', '#475569', fields
        )
        return et_label, summary, [layer], ctx


# ── Standalone helper: enrich existing pkt dict ───────────────────────────────

def enrich_unknown_packet(pkt: dict) -> dict:
    """
    Called on packets that already went through _parse_one() but ended up
    with proto='?' or empty summary.  Fills in best-effort values.
    """
    if pkt.get('summary') and pkt.get('proto') != '?':
        return pkt

    et = 0
    # Try to recover EtherType from Ethernet layer
    for layer in pkt.get('layers', []):
        for f in layer.get('fields', []):
            if f.get('n') == 'EtherType':
                try:
                    et = int(f['v'], 16)
                except (ValueError, TypeError):
                    pass

    src_mac = pkt.get('src_mac', '')
    dst_mac = pkt.get('dst_mac', '')
    data = bytes(pkt.get('hex_data', []))

    hint = _heuristic_identify(data, et) if et else ''
    preview = _payload_preview(data) if data else ''

    if not pkt.get('summary'):
        if hint:
            pkt['summary'] = f'Unknown EtherType 0x{et:04x} — {hint}'
        elif et:
            pkt['summary'] = f'Unknown EtherType 0x{et:04x} ({pkt.get("frame_len", 0)} bytes)'
        else:
            pkt['summary'] = f'Unknown traffic — {pkt.get("frame_len", 0)} bytes'

    if pkt.get('proto') in ('?', '', None):
        pkt['proto'] = f'ET-0x{et:04x}' if et else 'Unknown'

    return pkt
