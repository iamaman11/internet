#!/usr/bin/env python3
"""Physical SOCKS5 UDP ASSOCIATE probe. Run INSIDE warp-egress; never run in CI."""
import os
import socket
import struct
import sys

PROXY = ("127.0.0.1", 11080)
DNS = ("1.1.1.1", 53)
NAME = "example.com"


def exact(sock, count):
    data = b""
    while len(data) < count:
        piece = sock.recv(count - len(data))
        if not piece:
            raise RuntimeError("SOCKS5_EOF")
        data += piece
    return data


def probe():
    with socket.create_connection(PROXY, timeout=7) as control:
        control.settimeout(8)
        control.sendall(b"\x05\x01\x00")
        if exact(control, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS5_NEGOTIATION_FAILED")
        # UDP ASSOCIATE, 0.0.0.0:0
        control.sendall(b"\x05\x03\x00\x01" + b"\x00" * 6)
        head = exact(control, 4)
        if head[:3] != b"\x05\x00\x00":
            raise RuntimeError(f"SOCKS5_UDP_ASSOCIATE_REJECTED_{head[1]}")
        if head[3] == 1:
            relay = socket.inet_ntop(socket.AF_INET, exact(control, 4))
        elif head[3] == 4:
            relay = socket.inet_ntop(socket.AF_INET6, exact(control, 16))
        elif head[3] == 3:
            relay = exact(control, exact(control, 1)[0]).decode("ascii")
        else:
            raise RuntimeError("SOCKS5_INVALID_RELAY_ADDRESS")
        port = struct.unpack("!H", exact(control, 2))[0]
        if relay == "0.0.0.0":
            relay = PROXY[0]
        tid = os.urandom(2)
        question = b"".join(bytes([len(s)]) + s.encode("ascii") for s in NAME.split(".")) + b"\x00"
        query = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question + b"\x00\x01\x00\x01"
        prefix = b"\x00\x00\x00\x01" + socket.inet_aton(DNS[0]) + struct.pack("!H", DNS[1])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(8)
            udp.sendto(prefix + query, (relay, port))
            response, _ = udp.recvfrom(2048)
        if len(response) < 10 or response[:3] != b"\x00\x00\x00":
            raise RuntimeError("SOCKS5_INVALID_UDP_DATAGRAM")
        if response[3] != 1 or response[4:8] != socket.inet_aton(DNS[0]):
            raise RuntimeError("SOCKS5_UNEXPECTED_UDP_SOURCE")
        answer = response[10:]
        if len(answer) < 12 or answer[:2] != tid or not (answer[2] & 0x80):
            raise RuntimeError("DNS_RESPONSE_NOT_MATCHED")
        if (answer[3] & 0x0F) != 0 or struct.unpack("!H", answer[6:8])[0] < 1:
            raise RuntimeError("DNS_RESPONSE_NO_ANSWER")
        print("SOCKS5_UDP_ASSOCIATE=PASS")
        print("UDP_DNS_RESPONSE=PASS")
        print("REMOTE_DNS=1.1.1.1:53")


if __name__ == "__main__":
    try:
        probe()
    except (OSError, ValueError, RuntimeError) as error:
        print(f"SOCKS5_UDP_PROBE_FAILED: {error}", file=sys.stderr)
        raise SystemExit(1)
