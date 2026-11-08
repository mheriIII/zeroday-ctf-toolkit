#!/usr/bin/env python3
"""Extract JPEG COM (comment) segments from a folder of images.
Many CTFs stash data as `index:base64` in each image's comment; this decodes
the ones with a real (>=0) index and reassembles them in order.
Usage: python jpeg_comments.py ./images
"""
import sys, os, glob, base64


def comment(path):
    b = open(path, "rb").read()
    i = 2
    while i < len(b) - 1:
        if b[i] != 0xFF:
            break
        m = b[i + 1]
        if m == 0xDA:                       # start of scan -> no more headers
            break
        if 0xD0 <= m <= 0xD9:
            i += 2
            continue
        ln = int.from_bytes(b[i + 2:i + 4], "big")
        if m == 0xFE:                       # COM
            return b[i + 4:i + 2 + ln]
        i += 2 + ln
    return None


def main(folder):
    parts = {}
    for f in sorted(glob.glob(os.path.join(folder, "*.jpg")) +
                    glob.glob(os.path.join(folder, "*.jpeg"))):
        seg = comment(f)
        if not seg or b":" not in seg:
            continue
        idx, b64 = seg.split(b":", 1)
        try:
            idx = int(idx)
        except ValueError:
            continue
        try:
            dec = base64.b64decode(b64).decode("latin1")
        except Exception:
            dec = "<" + b64.decode("latin1") + ">"
        print(f"{os.path.basename(f):>16}  idx={idx:<4} {dec!r}")
        if idx >= 0:
            parts[idx] = dec
    if parts:
        print("\nassembled:", "".join(parts[k] for k in sorted(parts)))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python jpeg_comments.py ./images")
    main(sys.argv[1])
