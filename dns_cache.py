
import struct
import time
from dataclasses import dataclass

from dns_packet import parse_message, read_name


@dataclass
class CacheEntry:
    response: bytes
    ttl_fields: list
    expires_at: float


class DNSCache:
    def __init__(self, clock=None):
        self.entries = {}
        self.clock = clock if clock is not None else time.monotonic

    def make_key(self, name, qtype, qclass):
        return (name.rstrip(".").lower() + ".", qtype, qclass)

    def find_ttl_fields(self, response):
        """Find TTL fields in all resource record sections."""
        if len(response) < 12:
            raise ValueError("Invalid DNS header")

        _, _, qd, an, ns, ar = struct.unpack_from(
            "!HHHHHH", response, 0
        )

        offset = 12

        for _ in range(qd):
            _, offset = read_name(response, offset)

            if offset + 4 > len(response):
                raise ValueError("Invalid DNS question")

            offset += 4

        ttl_fields = []

        for _ in range(an + ns + ar):
            _, offset = read_name(response, offset)

            if offset + 10 > len(response):
                raise ValueError("Invalid resource record")

            rtype, _, ttl, rdlength = struct.unpack_from(
                "!HHIH", response, offset
            )

            # OPT (TYPE 41) use this field differently
            # It is not a normal DNS cache TTL
            if rtype != 41:
                ttl_fields.append((offset + 4, ttl))

            offset += 10 + rdlength

            if offset > len(response):
                raise ValueError("Invalid RDATA length")

        if offset != len(response):
            raise ValueError("Unexpected trailing DNS data")

        return ttl_fields

    def put(self, name, qtype, qclass, response):
        """Store a positive DNS response until its TTL expires."""
        message = parse_message(response)

        rcode = message["flags"] & 0x000F

        # Do not cache errors, negative answers or zero answers
        if rcode != 0 or not message["answers"]:
            return False

        ttl_fields = self.find_ttl_fields(response)

        if not ttl_fields:
            return False

        # A complete response is reusable only while every included cacheable record remains valid
        minimum_ttl = min(ttl for _, ttl in ttl_fields)

        if minimum_ttl == 0:
            return False

        key = self.make_key(name, qtype, qclass)
        self.entries[key] = CacheEntry(
            response=bytes(response),
            ttl_fields=ttl_fields,
            expires_at=self.clock() + minimum_ttl
        )

        return True

    def get(self, name, qtype, qclass):
        """Return an unexpired response with updated TTL values."""
        key = self.make_key(name, qtype, qclass)
        entry = self.entries.get(key)

        if entry is None:
            return None

        now = self.clock()

        if now >= entry.expires_at:
            del self.entries[key]
            return None

        elapsed = max(0, now - (
            entry.expires_at -
            min(ttl for _, ttl in entry.ttl_fields)
        ))

        response = bytearray(entry.response)

        for position, original_ttl in entry.ttl_fields:
            remaining = max(0, int(original_ttl - elapsed))
            struct.pack_into("!I", response, position, remaining)

        return bytes(response)
