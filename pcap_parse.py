#!/usr/bin/env python3
"""Minimal pcap parser: no tshark/scapy needed.
Lists conversations, dumps cleartext HTTP requests, and extracts TLS SNI per client.
Usage: python pcap_parse.py capture.pcap
"""
import struct, sys, collections


def parse_pcap(path):
    f = open(path, "rb").read()
    magic = struct.unpack("<I", f[:4])[0]
    endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    linktype = struct.unpack(endian + "I", f[20:24])[0]
    o, pkts = 24, []
    while o + 16 <= len(f):
        ts, us, cl, ol = struct.unpack(endian + "IIII", f[o:o + 16])
        o += 16
        pkts.append((ts, f[o:o + cl]))
        o += cl
    return linktype, pkts


def sni(payload):
    """Pull the server name from a TLS ClientHello, or None."""
    try:
        if payload[0] != 22 or payload[5] != 1:
            return None
        o = 43
        o += 1 + payload[o]                                   # session id
        o += 2 + struct.unpack(">H", payload[o:o + 2])[0]     # cipher suites
        o += 1 + payload[o]                                   # compression
        end = o + 2 + struct.unpack(">H", payload[o:o + 2])[0]
        o += 2
        while o < end:
            t, l = struct.unpack(">HH", payload[o:o + 4])
            if t == 0:                                        # server_name
                return payload[o + 9:o + 4 + l].decode()
            o += 4 + l
    except Exception:
        return None


def main(path):
    linktype, pkts = parse_pcap(path)
    conv = collections.Counter()
    snis = collections.defaultdict(collections.Counter)
    for ts, d in pkts:
        if linktype == 1:                                     # ethernet
            et = struct.unpack(">H", d[12:14])[0]
            p = d[14:]
        else:
            et, p = 0x800, d
        if et != 0x800:
            continue
        ihl = (p[0] & 15) * 4
        proto = p[9]
        src = ".".join(map(str, p[12:16]))
        dst = ".".join(map(str, p[16:20]))
        l4 = p[ihl:]
        if proto not in (6, 17):
            continue
        sp, dp = struct.unpack(">HH", l4[:4])
        conv[(src, dst, dp)] += 1
        if proto == 6:
            body = l4[(l4[12] >> 4) * 4:]
            if dp == 80 and body[:4] in (b"GET ", b"POST", b"HEAD", b"PUT "):
                line = body.split(b"\r\n")[0].decode("latin1")
                host = ""
                for ln in body.split(b"\r\n"):
                    if ln.lower().startswith(b"host:"):
                        host = ln.decode("latin1")
                print("HTTP", ts, src, line, "|", host)
            if 443 in (sp, dp):
                n = sni(body)
                if n:
                    snis[src][n] += 1

    print("\n== top conversations ==")
    for k, v in conv.most_common(20):
        print(v, k)
    print("\n== TLS SNI per client ==")
    for client, c in snis.items():
        print(client, dict(c))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python pcap_parse.py capture.pcap")
    main(sys.argv[1])
