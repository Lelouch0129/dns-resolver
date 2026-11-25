
import random
import socket
import struct
import sys

from dns_packet import parse_message


# Root DNS servers
ROOT_SERVERS = [
    "170.247.170.2",   #B-root
    "198.41.0.4",      #A-root
    "192.33.4.12",     #C-root
]

DNS_PORT = 53
TIMEOUT = 3
MAX_HOPS = 20
MAX_DEPTH = 5


def encode_name(name):
    """Encode a domain name using DNS wire format."""
    name = name.rstrip(".")

    if not name:
        return b"\x00"

    result = bytearray()

    for label in name.split("."):
        try:
            encoded = label.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("Non-ASCII DNS name") from None

        if not 1 <= len(encoded) <= 63:
            raise ValueError("Invalid DNS label length")

        result.append(len(encoded))
        result.extend(encoded)

    result.append(0)

    if len(result) > 255:
        raise ValueError("DNS name exceeds 255 bytes")

    return bytes(result)


def build_query(name, qtype=1, qclass=1):
    """Build an iterative DNS query with RD=0."""
    transaction_id = random.randint(0, 65535)

    # Flags=0: standard query, recursion desired=0
    header = struct.pack(
        "!HHHHHH",
        transaction_id, 0, 1, 0, 0, 1
    )

    question = (
        encode_name(name)
        + struct.pack("!HH", qtype, qclass)
    )

    opt_record = (
        b"\x00"
        + struct.pack("!HHIH", 41, 1232, 0, 0)
    )

    return transaction_id, header + question + opt_record


def recv_exact(sock, length):
    """Receive exactly the requested number of bytes."""
    data = bytearray()

    while len(data) < length:
        chunk = sock.recv(length - len(data))

        if not chunk:
            raise OSError("TCP connection closed unexpectedly")

        data.extend(chunk)

    return bytes(data)


def query_server_tcp(server_ip, query):
    """Retry a truncated DNS query over TCP."""
    with socket.create_connection(
        (server_ip, DNS_PORT),
        timeout=TIMEOUT
    ) as sock:

        sock.settimeout(TIMEOUT)

        sock.sendall(
            struct.pack("!H", len(query)) + query
        )

        response_length = struct.unpack(
            "!H", recv_exact(sock, 2)
        )[0]

        if response_length < 12:
            raise ValueError("Short TCP DNS response")

        return recv_exact(sock, response_length)


def query_server(server_ip, name, qtype, qclass):
    """Send one UDP query to a DNS server."""
    transaction_id, query = build_query(
        name, qtype, qclass
    )

    with socket.socket(
        socket.AF_INET, socket.SOCK_DGRAM
    ) as sock:

        sock.settimeout(TIMEOUT)
        sock.connect((server_ip, DNS_PORT))
        sock.send(query)

        response = sock.recv(65535)

    if len(response) < 12:
        raise ValueError("Short DNS response")

    response_id, flags = struct.unpack_from(
        "!HH", response, 0
    )

    if response_id != transaction_id:
        raise ValueError("Transaction ID mismatch")

    if not flags & 0x8000:
        raise ValueError("Not a DNS response")

    if flags & 0x0200:
        print("  UDP response truncated; retrying with TCP")

        response = query_server_tcp(server_ip, query)

        if len(response) < 12:
            raise ValueError("Short TCP DNS response")

        response_id, flags = struct.unpack_from(
            "!HH", response, 0
        )

        if response_id != transaction_id:
            raise ValueError("TCP transaction ID mismatch")

        if not flags & 0x8000:
            raise ValueError("Invalid TCP DNS response")

        if flags & 0x0200:
            raise ValueError("Truncated TCP DNS response")

    if flags & 0x0080:
        raise ValueError("Unexpected recursive DNS server")

    message = parse_message(response)

    expected_name = name.rstrip(".").lower() + "."
    expected_question = (expected_name, qtype, qclass)

    questions = [
        (n.lower(), t, c)
        for n, t, c in message["questions"]
    ]

    if questions != [expected_question]:
        raise ValueError("DNS question mismatch")

    return message, response


def get_glue_addresses(message):
    """Extract IPv4 glue addresses for delegated NS names."""
    ns_names = {
        rr.value.lower()
        for rr in message["authority"]
        if rr.rtype == 2 and rr.value
    }

    addresses = []

    for rr in message["additional"]:
        if (
            rr.rtype == 1
            and rr.rclass == 1
            and rr.value
            and rr.name.lower() in ns_names
        ):
            if rr.value not in addresses:
                addresses.append(rr.value)

    return addresses


def get_ns_names(message):
    """Extract NS hostnames from the Authority section."""
    return [
        rr.value
        for rr in message["authority"]
        if rr.rtype == 2 and rr.value
    ]


def resolve(name, qtype=1, qclass=1, depth=0):
    """Resolve a DNS query iteratively starting at Root."""
    if depth >= MAX_DEPTH:
        raise RuntimeError("Maximum NS lookup depth exceeded")

    name = name.rstrip(".") + "." if name != "." else "."
    servers = list(ROOT_SERVERS)
    visited_referrals = set()

    for hop in range(MAX_HOPS):
        message = None
        response = None
        responding_server = None

        # Try available servers at the current DNS level
        for server_ip in servers:
            try:
                print(
                    f"[Hop {hop + 1}] "
                    f"Querying {server_ip} for {name}",
                    flush=True
                )

                message, response = query_server(
                    server_ip, name, qtype, qclass
                )

                rcode = message["flags"] & 0x000F

                if rcode not in (0, 3):
                    raise ValueError(f"DNS RCODE={rcode}")

                responding_server = server_ip
                break

            except (
                socket.timeout,
                OSError,
                ValueError
            ) as error:
                print(f"  Server failed: {error}")
                continue

        if message is None:
            raise RuntimeError(
                "All DNS servers at this level failed"
            )

        print(
            f"  Answers: {len(message['answers'])}, "
            f"Authority: {len(message['authority'])}, "
            f"Additional: {len(message['additional'])}"
        )

        flags = message["flags"]
        rcode = flags & 0x000F
        authoritative = bool(flags & 0x0400)

        # Accept final answers from servers
        if authoritative and (
            message["answers"] or rcode == 3
        ):
            print(
                f"  Authoritative answer from "
                f"{responding_server}"
            )
            return message, response

        # Authoritative NODATA response
        if authoritative and any(
            rr.rtype == 6
            for rr in message["authority"]
        ):
            print("  Authoritative response with no answers")
            return message, response

        # Follow NS referrals
        ns_names = get_ns_names(message)

        if not ns_names:
            raise RuntimeError(
                "No answer or usable NS referral"
            )

        referral_key = tuple(
            sorted(n.lower() for n in ns_names)
        )

        if referral_key in visited_referrals:
            raise RuntimeError("DNS referral loop detected")

        visited_referrals.add(referral_key)

        next_servers = get_glue_addresses(message)

        # When glue is missing, resolve NS hostname separately
        if not next_servers:
            print("  No glue; resolving NS hostname")

            for ns_name in ns_names:
                try:
                    ns_result, _ = resolve(
                        ns_name, 1, 1, depth + 1
                    )

                    for rr in ns_result["answers"]:
                        if (
                            rr.rtype == 1
                            and rr.rclass == 1
                            and rr.value
                            and rr.name.lower()
                                == ns_name.lower()
                        ):
                            if rr.value not in next_servers:
                                next_servers.append(rr.value)

                except RuntimeError as error:
                    print(f"  NS lookup failed: {error}")

                if next_servers:
                    break

        if not next_servers:
            raise RuntimeError(
                "No IPv4 address available for next NS"
            )

        print(f"  Next servers: {next_servers}")
        servers = next_servers

    raise RuntimeError("Maximum DNS hops exceeded")


def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print(
            "Usage: python3 iterative_resolver.py "
            "<domain> [type]"
        )
        sys.exit(1)

    domain = sys.argv[1]

    record_types = {
        "A": 1,
        "NS": 2,
        "CNAME": 5,
        "SOA": 6,
        "PTR": 12,
        "MX": 15,
        "TXT": 16,
        "AAAA": 28,
    }

    record_type = (
        sys.argv[2].upper()
        if len(sys.argv) == 3 else "A"
    )

    if record_type in record_types:
        qtype = record_types[record_type]
    else:
        qtype = int(record_type)

    if not 0 <= qtype <= 65535:
        raise ValueError("Invalid DNS TYPE")

    message, response = resolve(domain, qtype)

    print("\n===== DNS RESULT =====")
    print("RCODE:", message["flags"] & 0x000F)
    print("Response size:", len(response), "bytes")

    for rr in message["answers"]:
        print(
            f"{rr.name} TYPE={rr.rtype} "
            f"CLASS={rr.rclass} TTL={rr.ttl} "
            f"VALUE={rr.value if rr.value else '<raw RDATA>'}"
        )

if __name__ == "__main__":
    main()
