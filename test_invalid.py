
import struct

from dns_packet import read_name, parse_message


def expect_invalid(description, test):
    try:
        test()
    except ValueError:
        print(f"PASS: {description}")
        return

    raise AssertionError(
        f"Invalid packet was accepted: {description}"
    )


def make_query(name):
    header = struct.pack(
        "!HHHHHH", 1234, 0x0100, 1, 0, 0, 0
    )
    question = name + struct.pack("!HH", 1, 1)
    return header + question


def main():
    expect_invalid(
        "Truncated DNS header",
        lambda: parse_message(b"\x00" * 11)
    )

    expect_invalid(
        "Compression pointer loop",
        lambda: read_name(b"\xc0\x00", 0)
    )

    expect_invalid(
        "Truncated compression pointer",
        lambda: read_name(b"\xc0", 0)
    )

    expect_invalid(
        "Invalid label type",
        lambda: read_name(b"\x40", 0)
    )

    expect_invalid(
        "Truncated label",
        lambda: read_name(b"\x07abc", 0)
    )

    overlong_name = (
        b"\x3f" + b"a" * 63
        + b"\x3f" + b"b" * 63
        + b"\x3f" + b"c" * 63
        + b"\x3e" + b"d" * 62
        + b"\x00"
    )

    expect_invalid(
        "DNS name exceeds 255 bytes",
        lambda: parse_message(make_query(overlong_name))
    )

    expect_invalid(
        "Incomplete DNS question",
        lambda: parse_message(
            struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0)
            + b"\x00\x00"
        )
    )

    expect_invalid(
        "Unexpected trailing bytes",
        lambda: parse_message(
            struct.pack("!HHHHHH", 1, 0, 0, 0, 0, 0)
            + b"\xff"
        )
    )

    print("\nINVALID DNS PACKET TESTS: ALL PASS")


if __name__ == "__main__":
    main()
