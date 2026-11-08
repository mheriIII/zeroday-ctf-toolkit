#!/usr/bin/env python3
"""Reassemble a multipart relay message from scratch objects + a dead-letter queue.

Each part was staged as objects/<id> and logged in relay.jsonl; parts that ran
out of retries sit in dlq.jsonl as base64. Workers leave failed-attempt leftovers
in scratch, so we pick the correct object per part by its logged sha256, and pull
any missing part from the DLQ.

Usage: python dlq_reassemble.py <message-id> relay.jsonl dlq.jsonl objects_dir out.bin
"""
import sys, json, os, hashlib, base64


def main(mid, relay_path, dlq_path, objects_dir, out_path):
    expected, parts = {}, {}
    for line in open(relay_path, encoding="utf-8"):
        d = json.loads(line)
        if d.get("messageId") != mid or "part" not in d:
            continue
        if d.get("status") == "ok":                     # the good attempt
            expected[d["part"]] = d["sha256"]
            parts[d["part"]] = ("object", d["object"])

    dlq = {}
    for line in open(dlq_path, encoding="utf-8"):
        d = json.loads(line)
        if d.get("messageId") == mid:
            dlq[d["part"]] = d

    total = max(list(parts) + list(dlq)) + 1
    blob = b""
    for p in range(total):
        if p in parts:
            data = open(os.path.join(objects_dir, parts[p][1]), "rb").read()
            tag = "object " + parts[p][1]
        elif p in dlq:
            data = base64.b64decode(dlq[p]["payload"])
            tag = "dlq"
        else:
            sys.exit(f"missing part {p}")
        want = expected.get(p) or dlq.get(p, {}).get("sha256")
        got = hashlib.sha256(data).hexdigest()
        ok = "ok" if want == got else "SHA MISMATCH"
        print(f"part {p:2}  {len(data):>6}B  {tag}  {ok}")
        blob += data

    open(out_path, "wb").write(blob)
    print(f"\nwrote {len(blob)} bytes -> {out_path}  (magic {blob[:4]!r})")


if __name__ == "__main__":
    if len(sys.argv) != 6:
        sys.exit("usage: python dlq_reassemble.py <message-id> relay.jsonl "
                 "dlq.jsonl objects_dir out.bin")
    main(*sys.argv[1:])
