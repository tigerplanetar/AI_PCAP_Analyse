"""
parsers/tcp.py — TCP Segment Parser  (RFC 793)
===============================================
Standalone parser for Transmission Control Protocol segments.

Public API
----------
    from parsers.tcp import parse_tcp

    layers = parse_tcp(payload, pkt, src_ip='10.0.0.1', dst_ip='10.0.0.2')

Design notes
------------
- Call this when IPv4 protocol number == 6 (or equivalent context).
- App-layer protocol classification is performed via port mapping
  (_classify_app from constants.py) matching the logic in _parse_one().
- Payload validation (_has_app_payload) prevents misclassifying pure
  ACKs as HTTP/HTTPS when no actual application data is present.
- TCP options parsing handles MSS, window scale, SACK, and timestamps
  (RFC 7323) for informational display.
- Returns None on malformed/short input, never raises.
- Appends one layer dict to pkt['layers'].

TCP segment layout (minimum 20 bytes):
  Offset  Bits  Field
  0       16    Source Port
  2       16    Destination Port
  4       32    Sequence Number
  8       32    Acknowledgment Number
  12      4     Data Offset (header length in 32-bit words)
  12      3     Reserved (must be 0)
  13      9     Control Bits (URG ACK PSH RST SYN FIN)
  14      16    Window Size
  16      16    Checksum
  18      16    Urgent Pointer
  20+           Options + Padding (if Data Offset > 5)

RFC 793  — Transmission Control Protocol
RFC 7323 — TCP Extensions for High Performance (options)
RFC 6298 — Computing TCP's Retransmission Timer
"""

from __future__ import annotations
import struct

from parsers.constants import (
    SERVICES, RFC_REF, TCP_FLAGS_MAP,
    _field, _layer,
    _tcp_flags_str, _tcp_state_desc,
    _classify_app, _has_app_payload,
)


def _parse_tcp_options(option_bytes: bytes) -> list[dict]:
    """
    Parse TCP options (RFC 793 §3.1, RFC 7323).

    Returns a list of _field() dicts for inclusion in the TCP layer.
    Stops on End-of-Option (0) or exhausts the buffer.  Never raises.
    """
    fields = []
    i = 0
    while i < len(option_bytes):
        kind = option_bytes[i]
        if kind == 0:           # End of Options
            break
        if kind == 1:           # No-Operation (padding)
            i += 1
            continue
        if i + 1 >= len(option_bytes):
            break
        length = option_bytes[i + 1]
        if length < 2 or i + length > len(option_bytes):
            break

        data = option_bytes[i + 2: i + length]

        if kind == 2 and length == 4:
            mss = struct.unpack('!H', data)[0]
            fields.append(_field('TCP Option: MSS', f'{mss} bytes', 'Maximum Segment Size — RFC 793'))
        elif kind == 3 and length == 3:
            fields.append(_field('TCP Option: Window Scale', f'×{2 ** data[0]}', f'Shift count={data[0]} — RFC 7323'))
        elif kind == 4 and length == 2:
            fields.append(_field('TCP Option: SACK Permitted', 'Yes', 'Selective ACK enabled — RFC 2018'))
        elif kind == 8 and length == 10:
            ts_val, ts_ecr = struct.unpack('!II', data)
            fields.append(_field('TCP Option: Timestamp', f'val={ts_val}  ecr={ts_ecr}', 'RTT measurement — RFC 7323'))
        i += length

    return fields


def parse_tcp(
    payload: bytes,
    pkt: dict,
    src_ip: str = '',
    dst_ip: str = '',
) -> list[dict] | None:
    """
    Parse a TCP segment.

    The caller must have confirmed IPv4 protocol == 6 (or equivalent).

    Parameters
    ----------
    payload : bytes
        Bytes starting at the first byte of the TCP header (source port).
        Must be at least 20 bytes.
    pkt : dict
        Accumulating packet dict.  Will be mutated in-place.
    src_ip, dst_ip : str
        IP addresses from the enclosing IPv4 header (for the summary).

    Returns
    -------
    List containing the TCP layer dict on success, or None if the
    payload is shorter than 20 bytes.

    Side-effects
    ------------
    - Updates pkt: proto, src_port, dst_port, tcp_flags, tcp_seq,
      tcp_ack, tcp_window, service, tcp_state, summary.
    - Appends the TCP layer dict to pkt['layers'].
    """
    if len(payload) < 20:
        return None

    sp    = struct.unpack('!H', payload[0:2])[0]
    dp    = struct.unpack('!H', payload[2:4])[0]
    seq   = struct.unpack('!I', payload[4:8])[0]
    ack   = struct.unpack('!I', payload[8:12])[0]
    doff  = (payload[12] >> 4) * 4
    flagb = payload[13]
    win   = struct.unpack('!H', payload[14:16])[0]
    ck    = struct.unpack('!H', payload[16:18])[0]
    urg   = struct.unpack('!H', payload[18:20])[0]

    # TCP payload (after header + options)
    tcp_payload = payload[doff:] if doff <= len(payload) else b''

    svc       = SERVICES.get(dp) or SERVICES.get(sp, '')
    app_proto = _classify_app('TCP', dp, sp) or 'TCP'

    # Validate that the payload actually contains the detected app protocol.
    # Avoids labelling pure ACKs (no data) as HTTP or HTTPS.
    if app_proto != 'TCP' and not _has_app_payload(app_proto, tcp_payload):
        app_proto = 'TCP'

    fs    = _tcp_flags_str(flagb)
    fn    = ' | '.join(desc for bit, name, desc in TCP_FLAGS_MAP if flagb & bit) or 'none'
    state = _tcp_state_desc(flagb)

    summary = f'{app_proto} {src_ip}:{sp} → {dst_ip}:{dp}  [{fs}]'
    if svc:
        summary += f' {svc}'

    pkt.update({
        'proto':      app_proto,
        'src_port':   sp,
        'dst_port':   dp,
        'tcp_flags':  fs,
        'tcp_seq':    seq,
        'tcp_ack':    ack,
        'tcp_window': win,
        'service':    svc,
        'tcp_state':  state,
        'summary':    summary,
    })

    # Core TCP fields
    fields = [
        _field('Source Port',      str(sp),
               f'{"Well-known service" if sp < 1024 else "Ephemeral (client)"} port'),
        _field('Destination Port', f'{dp}{f" ({svc})" if svc else ""}',
               f'{"Well-known service" if dp < 1024 else "Ephemeral (client)"} port'),
        _field('Sequence Number',  str(seq),            'Byte position in the sender\'s data stream'),
        _field('Acknowledgment',   str(ack),            'Next byte the sender expects to receive'),
        _field('Data Offset',      f'{doff} bytes',     'TCP header size (includes options)'),
        _field('Flags',            fs,                  fn),
        _field('Connection State', state,               'Human-readable TCP state interpretation'),
        _field('Window Size',      f'{win} bytes',      'Receiver\'s current buffer capacity (flow control)'),
        _field('Checksum',         f'0x{ck:04x}',       'Error detection over header + data'),
        _field('Urgent Pointer',   str(urg),            'Byte offset to urgent data (valid only if URG set)'),
        _field('Service',          svc or 'Unknown',   RFC_REF.get(svc, '')),
    ]

    # Append parsed TCP options if present
    if doff > 20 and doff <= len(payload):
        option_fields = _parse_tcp_options(payload[20:doff])
        fields.extend(option_fields)

    layer = _layer('TCP — Transmission Control Protocol  (RFC 793)', '#3b82f6', fields)
    pkt.setdefault('layers', []).append(layer)
    return [layer]
