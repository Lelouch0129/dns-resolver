import struct

from dns_packet import parse_message


def validate_query(data):
    """Validate one standard DNS question and basic EDNS(0)."""
    if len(data) < 12:
        raise ValueError("Short DNS header")

    ident, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data, 0)
    if flags & 0x8000 or flags & 0x7800 or qd != 1:
        raise ValueError("Invalid DNS query header")
    if an != 0 or ns != 0:
        raise ValueError("Unexpected answer or authority records")

    message = parse_message(data)
    additional = message["additional"]
    opt_records = [rr for rr in additional if rr.rtype == 41]

    if len(opt_records) > 1:
        raise ValueError("Multiple OPT records")
    if len(additional) != len(opt_records):
        raise ValueError("Unsupported additional records in query")

    udp_size = 512
    if opt_records:
        opt = opt_records[0]
        if opt.name != "." or (opt.ttl >> 16) & 0xff:
            raise ValueError("Invalid EDNS version or OPT name")
        # Additional EDNS options, such as DNS COOKIE, are length-encoded.
        offset = 0
        while offset < len(opt.rdata):
            if offset + 4 > len(opt.rdata):
                raise ValueError("Incomplete EDNS option")
            _, length = struct.unpack_from("!HH", opt.rdata, offset)
            offset += 4 + length
            if offset > len(opt.rdata):
                raise ValueError("Invalid EDNS option length")
        udp_size = max(512, opt.rclass)

    name, qtype, qclass = message["questions"][0]
    return {
        "id": ident,
        "flags": flags,
        "name": name,
        "qtype": qtype,
        "qclass": qclass,
        "udp_size": udp_size,
        "edns": bool(opt_records),
    }
