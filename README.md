# DNS Resolver

This is my DNS resolver project for the Computer Networks course at Columbia University. It is written in Python and uses iterative DNS queries to resolve domain names.

The resolver starts from a root DNS server and follows referrals until it gets an answer. It also caches responses based on their TTL, supports EDNS(0) for larger UDP responses, and drops invalid DNS packets.

## Files

- `server_iterative.py` - Runs the UDP DNS server
- `iterative_resolver.py` - Handles iterative DNS queries
- `dns_packet.py` - Parses DNS packets
- `dns_query.py` - Checks incoming DNS queries
- `dns_cache.py` - Stores cached DNS responses
- `test_cache.py` - Tests caching and TTL behavior
- `test_invalid.py` - Tests invalid DNS packets

## How to Run

Python 3 is required. No external DNS libraries are needed.

Start the server with:

```bash
python3 server_iterative.py 10051
```

If no port is specified, the server uses port 53.

You can test it with `dig`:

```bash
dig @127.0.0.1 -p 10051 example.com A
dig @127.0.0.1 -p 10051 google.com MX
dig @127.0.0.1 -p 10051 columbia.edu TXT +bufsize=4096 +ignore
```

To run the Python tests:

```bash
python3 test_cache.py
python3 test_invalid.py
```

The real DNS test needs a network that allows direct queries to DNS servers.
