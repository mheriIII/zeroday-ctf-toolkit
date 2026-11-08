#!/usr/bin/env python3
"""Crack a Traditional-PKZIP (ZipCrypto) password from a wordlist.
Fast path: test each candidate against the 12-byte encryption header's check
byte before doing any real decryption, then verify by extracting.
Usage: python zipcrypto_crack.py secret.zip wordlist.txt [member]
"""
import sys, struct, zipfile

_CRC = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (0xEDB88320 ^ (_c >> 1)) if _c & 1 else _c >> 1
    _CRC.append(_c)


def crc32(c, b):
    return _CRC[(c ^ b) & 0xFF] ^ (c >> 8)


def check_byte(info, raw):
    """Expected last byte of the decrypted 12-byte header."""
    if info.flag_bits & 0x8:
        return (info._raw_time >> 8) & 0xFF
    return (info.CRC >> 24) & 0xFF


def enc_header(zip_path, info):
    with open(zip_path, "rb") as f:
        f.seek(info.header_offset)
        lh = f.read(30)
        n, m = struct.unpack("<HH", lh[26:30])
        f.seek(info.header_offset + 30 + n + m)
        return f.read(12)


def test(pw, enc, chk):
    k0, k1, k2 = 305419896, 591751049, 878082192
    for ch in pw:
        k0 = crc32(k0, ch)
        k1 = (k1 + (k0 & 0xFF)) & 0xFFFFFFFF
        k1 = (k1 * 134775813 + 1) & 0xFFFFFFFF
        k2 = crc32(k2, (k1 >> 24) & 0xFF)
    last = 0
    for c in enc:
        t = (k2 | 2) & 0xFFFF
        d = c ^ (((t * (t ^ 1)) >> 8) & 0xFF)
        last = d
        k0 = crc32(k0, d)
        k1 = (k1 + (k0 & 0xFF)) & 0xFFFFFFFF
        k1 = (k1 * 134775813 + 1) & 0xFFFFFFFF
        k2 = crc32(k2, (k1 >> 24) & 0xFF)
    return last == chk


def main(zip_path, wordlist, member=None):
    z = zipfile.ZipFile(zip_path)
    info = z.getinfo(member) if member else next(
        i for i in z.infolist() if i.flag_bits & 0x1)
    enc = enc_header(zip_path, info)
    chk = check_byte(info, enc)
    print(f"target member: {info.filename}  check byte: {chk:#x}")
    pwds = open(wordlist, "rb").read().split(b"\n")
    for pw in pwds:
        pw = pw.rstrip(b"\r")
        if not pw or not test(pw, enc, chk):
            continue
        try:                                      # confirm (check byte can collide)
            z.setpassword(pw)
            z.read(info.filename)
            print("PASSWORD FOUND:", pw.decode("latin1"))
            return
        except Exception:
            pass
    print("not found")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: python zipcrypto_crack.py secret.zip wordlist.txt [member]")
    main(*sys.argv[1:4])
