
import socket
import struct

from dns_cache import DNSCache
from dns_packet import parse_message
from iterative_resolver import resolve


def test_basic_cache():
    """Test cache hit, TTL aging and expiration."""
    fake_time = [1000.0]
    cache = DNSCache(clock=lambda: fake_time[0])

    question = (
        b"\x07example\x03com\x00"
        + struct.pack("!HH", 1, 1)
    )

    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 300, 4)
        + socket.inet_aton("192.0.2.1")
    )

    header = struct.pack(
        "!HHHHHH", 12345, 0x8180, 1, 1, 0, 0
    )

    response = header + question + answer

    assert cache.get("example.com", 1, 1) is None
    print("TEST 1: Cache Miss PASS")

    assert cache.put("example.com", 1, 1, response)

    cached = cache.get("example.com", 1, 1)
    assert cached is not None

    message = parse_message(cached)
    assert message["answers"][0].ttl == 300
    print("TEST 2: Cache Hit PASS")

    fake_time[0] += 100

    cached = cache.get("example.com", 1, 1)
    message = parse_message(cached)

    assert message["answers"][0].ttl == 200
    print("TEST 3: TTL Aging PASS")

    fake_time[0] += 201

    assert cache.get("example.com", 1, 1) is None
    print("TEST 4: TTL Expiration PASS")


def test_real_dns():
    """Check that a second lookup can reuse the cached answer."""
    cache = DNSCache()
    name = "example.com"

    print("\nFirst lookup:")
    cached = cache.get(name, 1, 1)

    if cached is None:
        print("CACHE MISS")
        _, response = resolve(name, 1, 1)
        stored = cache.put(name, 1, 1, response)
        assert stored

    print("\nSecond lookup:")
    cached = cache.get(name, 1, 1)

    assert cached is not None
    message = parse_message(cached)

    print("CACHE HIT")

    for rr in message["answers"]:
        print(rr.name, rr.value, "TTL =", rr.ttl)

    print("REAL DNS CACHE TEST: PASS")


if __name__ == "__main__":
    test_basic_cache()
    test_real_dns()
