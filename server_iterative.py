import socket
import struct
import sys

from dns_cache import DNSCache
from dns_packet import read_name
from dns_query import validate_query
from iterative_resolver import encode_name, resolve


MAX_UDP_SIZE = 4096


def question_bytes(info):
    return encode_name(info["name"]) + struct.pack(
        "!HH", info["qtype"], info["qclass"]
    )


def opt_bytes(udp_size):
    return b"\x00" + struct.pack("!HHIH", 41, udp_size, 0, 0)


def make_short_response(info, rcode=0, truncated=False):
    """Build a small DNS response without copying compressed records."""
    flags = 0x8000 | 0x0080 | (info["flags"] & 0x0100) | rcode
    if truncated:
        flags |= 0x0200
    ar = 1 if info["edns"] else 0
    result = struct.pack(
        "!HHHHHH", info["id"], flags, 1, 0, 0, ar
    ) + question_bytes(info)
    if info["edns"]:
        result += opt_bytes(MAX_UDP_SIZE)
    return result


def trailing_opt_start(packet):
    """Locate a final OPT RR without changing DNS name compression offsets."""
    _, _, qd, an, ns, ar = struct.unpack_from("!HHHHHH", packet, 0)
    offset = 12
    for _ in range(qd):
        _, offset = read_name(packet, offset)
        if offset + 4 > len(packet):
            raise ValueError("Truncated DNS question")
        offset += 4

    last_opt = None
    for i in range(an + ns + ar):
        start = offset
        _, offset = read_name(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError("Truncated DNS record")
        rtype, _, _, rdlength = struct.unpack_from("!HHIH", packet, offset)
        offset += 10 + rdlength
        if offset > len(packet):
            raise ValueError("Truncated DNS record data")
        if rtype == 41:
            if i != an + ns + ar - 1 or last_opt is not None:
                raise ValueError("OPT is not the final record")
            last_opt = start

    if offset != len(packet):
        raise ValueError("Unexpected trailing DNS bytes")
    return last_opt


def prepare_response(upstream, info):
    """Reuse the original DNS wire response, preserving compression pointers."""
    response = bytearray(upstream)
    if len(response) < 12:
        raise ValueError("Short upstream response")

    opt_start = trailing_opt_start(response)
    if opt_start is not None:
        response = response[:opt_start]
        ar = struct.unpack_from("!H", response, 10)[0]
        struct.pack_into("!H", response, 10, ar - 1)

    flags = struct.unpack_from("!H", response, 2)[0]
    flags &= ~(0x0400 | 0x0100 | 0x0080 | 0x0020 | 0x0200)
    flags |= 0x0080 | (info["flags"] & 0x0100)
    struct.pack_into("!H", response, 0, info["id"])
    struct.pack_into("!H", response, 2, flags)

    if info["edns"]:
        response += opt_bytes(MAX_UDP_SIZE)
        ar = struct.unpack_from("!H", response, 10)[0]
        struct.pack_into("!H", response, 10, ar + 1)

    udp_limit = min(info["udp_size"], MAX_UDP_SIZE)
    if len(response) > udp_limit:
        return make_short_response(info, truncated=True)
    return bytes(response)


def main():
    if len(sys.argv) > 2:
        print("Usage: python3 server_iterative.py [port]")
        sys.exit(1)
    try:
        port = int(sys.argv[1]) if len(sys.argv) == 2 else 53
    except ValueError:
        sys.exit("Port must be an integer")
    if not 1 <= port <= 65535:
        sys.exit("Invalid port")

    cache = DNSCache()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("0.0.0.0", port))
        print(f"Iterative DNS Resolver listening on UDP {port}", flush=True)
        try:
            while True:
                query, client = server.recvfrom(65535)
                try:
                    info = validate_query(query)
                except (ValueError, struct.error) as error:
                    print(f"Dropped invalid query: {error}", flush=True)
                    continue

                name, qtype, qclass = (
                    info["name"], info["qtype"], info["qclass"]
                )
                try:
                    upstream = cache.get(name, qtype, qclass)
                    if upstream is None:
                        print(f"CACHE MISS: {name} TYPE={qtype}", flush=True)
                        _, upstream = resolve(name, qtype, qclass)
                        cache.put(name, qtype, qclass, upstream)
                    else:
                        print(f"CACHE HIT: {name} TYPE={qtype}", flush=True)
                    response = prepare_response(upstream, info)
                except (ValueError, RuntimeError, OSError, struct.error) as error:
                    print(f"Resolution failed: {error}", flush=True)
                    response = make_short_response(info, rcode=2)
                server.sendto(response, client)
                print(f"Sent {len(response)} bytes to {client}", flush=True)
        except KeyboardInterrupt:
            print("Server stopped")


if __name__ == "__main__":
    main()
