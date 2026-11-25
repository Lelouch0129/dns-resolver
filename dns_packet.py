
import socket
import struct
from dataclasses import dataclass

@dataclass
class ResourceRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: bytes
    value: str | None = None

def read_name(packet, offset):
    """Decode DNS names, including compression pointers."""
    labels = []
    visited = set()
    return_offset = None
    wire_length = 1

    while True:
        if offset >= len(packet) or offset in visited:
            raise ValueError("Invalid DNS name offset or compression loop")

        visited.add(offset)
        size = packet[offset]

        # first two bits: 11
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("Truncated compression pointer")

            pointer = ((size & 0x3F) << 8) | packet[offset + 1]

            if pointer >= offset:
                raise ValueError("Invalid forward compression pointer")

            if return_offset is None:
                return_offset = offset + 2

            offset = pointer
            continue

        if size & 0xC0:
            raise ValueError("Invalid DNS label type")

        offset += 1

        if size == 0:
            break

        if size > 63 or offset + size > len(packet):
            raise ValueError("Invalid or truncated DNS label")

        wire_length += size + 1

        if wire_length > 255:
            raise ValueError("DNS name exceeds 255 bytes")

        label = packet[offset:offset + size]
        labels.append(label.decode("ascii", errors="replace"))
        offset += size

    name = ".".join(labels) + "." if labels else "."
    next_offset = return_offset if return_offset is not None else offset

    return name, next_offset


def read_rr(packet, offset):
    """Decode one DNS Resource Record."""
    name, offset = read_name(packet, offset)

    if offset + 10 > len(packet):
        raise ValueError("Truncated resource record header")

    rtype, rclass, ttl, rdlength = struct.unpack_from(
        "!HHIH", packet, offset
    )

    rdata_start = offset + 10
    end = rdata_start + rdlength

    if end > len(packet):
        raise ValueError("Truncated RDATA")

    raw = packet[rdata_start:end]
    value = None

    if rtype == 1 and rdlength == 4:
        # A: IPv4 address.
        value = socket.inet_ntoa(raw)

    elif rtype in (2, 5, 12):
        # NS, CNAME, PTR: DNS-encoded names.
        value, name_end = read_name(packet, rdata_start)

        if name_end != end:
            raise ValueError("Invalid compressed name in RDATA")

    return ResourceRecord(
        name, rtype, rclass, ttl, raw, value
    ), end


def parse_message(packet):
    """Parse DNS Header, Questions and all RR sections."""
    if len(packet) < 12:
        raise ValueError("Truncated DNS header")

    ident, flags, qd, an, ns, ar = struct.unpack_from(
        "!HHHHHH", packet, 0
    )

    offset = 12
    questions = []

    for _ in range(qd):
        name, offset = read_name(packet, offset)

        if offset + 4 > len(packet):
            raise ValueError("Truncated DNS question")

        qtype, qclass = struct.unpack_from(
            "!HH", packet, offset
        )
        offset += 4

        questions.append((name, qtype, qclass))

    sections = []

    for count in (an, ns, ar):
        records = []
        for _ in range(count):
            rr, offset = read_rr(packet, offset)
            records.append(rr)

        sections.append(records)

    if offset != len(packet):
        raise ValueError("Unexpected bytes after DNS message")

    return {
        "id": ident,
        "flags": flags,
        "questions": questions,
        "answers": sections[0],
        "authority": sections[1],
        "additional": sections[2],
    }
