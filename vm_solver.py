#!/usr/bin/env python3
"""Recover the access key from the Zero Day 'Vault' binary's custom VM.

The binary embeds a tiny accumulator VM whose program is a flat array of
(opcode, operand) int32 pairs at the start of .rdata. Opcodes:

    0x31 LOADK  acc = key[operand]
    0xa7 XORI   acc ^= operand
    0x52 XORM   acc ^= maint[operand]      (maint = maintenance.dat, 32 bytes)
    0xc4 ADDI   acc = (acc + operand) & 0xff
    0x19 CMP    flag = (acc == operand)
    0xe2 JNF    if not flag: pc = operand  (jump if last CMP failed)
    0x6d JMP    pc = operand
    0xf0 HALT   return (operand == 1)

Each executed block constrains one key byte, so we invert it to recover the
27-byte key. Verified by feeding the key back to the real binary.

Usage: python vm_solver.py Vault.exe maintenance.dat
"""
import sys, struct

OPS = {0x31: "LOADK", 0xA7: "XORI", 0x52: "XORM", 0xC4: "ADDI",
       0x19: "CMP", 0xE2: "JNF", 0x6D: "JMP", 0xF0: "HALT"}


def load_program(exe_path):
    """Pull the (op,arg) dword array from the start of .rdata."""
    f = open(exe_path, "rb").read()
    pe = struct.unpack("<I", f[0x3C:0x40])[0]
    opt = pe + 24
    nsec = struct.unpack("<H", f[pe + 6:pe + 8])[0]
    magic = struct.unpack("<H", f[opt:opt + 2])[0]
    so = opt + (240 if magic == 0x20B else 224)
    for i in range(nsec):
        s = f[so + i * 40:so + i * 40 + 40]
        if s[:8].rstrip(b"\x00") == b".rdata":
            raw = struct.unpack("<I", s[20:24])[0]
            size = struct.unpack("<I", s[16:20])[0]
            n = (size // 4)
            return list(struct.unpack("<%dI" % n, f[raw:raw + n * 4]))
    raise RuntimeError(".rdata not found")


def trace(dw):
    """Follow the real control flow (all CMPs satisfied) to list the blocks."""
    pc, path, cur, steps = 0, [], None, 0
    while True:
        op, arg = dw[pc], dw[pc + 1]
        pc += 2
        nm = OPS.get(op)
        if nm == "JMP":
            pc = arg
            continue
        if nm == "JNF":                 # correct run never takes the fail jump
            continue
        if nm == "HALT":
            break
        if nm == "LOADK":
            cur = {"idx": arg, "ops": []}
            path.append(cur)
        elif nm == "XORI":
            cur["ops"].append(("X", arg))
        elif nm == "XORM":
            cur["ops"].append(("M", arg))
        elif nm == "ADDI":
            cur["ops"].append(("A", arg))
        elif nm == "CMP":
            cur["cmp"] = arg
        steps += 1
        if steps > 5000:
            break
    return path


def solve(path, maint):
    key = [0] * 27
    for b in path:
        acc = b["cmp"]
        for t, v in reversed(b["ops"]):     # invert in reverse order
            if t == "X":
                acc ^= v
            elif t == "M":
                acc ^= maint[v]
            elif t == "A":
                acc = (acc - v) & 0xFF
        key[b["idx"]] = acc & 0xFF
    return bytes(key)


def main(exe_path, maint_path):
    maint = open(maint_path, "rb").read()
    if len(maint) != 32:
        sys.exit("maintenance file must be exactly 32 bytes")
    key = solve(trace(load_program(exe_path)), maint)
    printable = all(32 <= c < 127 for c in key)
    print("access key:", key.decode("latin1") if printable else key.hex())
    if printable:
        print("flag: hackutd{%s}" % key.decode())


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: python vm_solver.py Vault.exe maintenance.dat")
    main(sys.argv[1], sys.argv[2])
