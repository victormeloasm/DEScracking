#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import glob
import math

BLOCK = 8

PNG_SIG  = bytes.fromhex("89504e470d0a1a0a")
PNG_IHDR = bytes.fromhex("0000000d49484452")

def xor8(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def pick_input_file() -> str:
    if os.path.isfile("target.png.des"):
        return "target.png.des"
    des = sorted(glob.glob("*.des"))
    if des:
        return des[0]
    raise SystemExit("No input file found (expected target.png.des or *.des in current directory).")

def shannon_entropy(b: bytes) -> float:
    if not b:
        return 0.0
    freq = {}
    for x in b:
        freq[x] = freq.get(x, 0) + 1
    ent = 0.0
    n = len(b)
    for c in freq.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent  # bits/byte

def looks_ascii(b: bytes) -> bool:
    printable = sum(1 for x in b if 32 <= x <= 126)
    return printable >= int(0.75 * len(b))

def build_two_lines(data: bytes, iv_off: int, ct_off: int):
    n = len(data)
    if iv_off < 0 or ct_off < 0:
        return None
    if iv_off + 8 > n:
        return None
    if ct_off + 16 > n:
        return None

    ct = data[ct_off:]
    if len(ct) < 16:
        return None
    if (len(ct) % 8) != 0:
        return None

    iv = data[iv_off:iv_off+8]
    C1 = ct[0:8]
    C2 = ct[8:16]

    salt1 = xor8(PNG_SIG, iv)      # P1 XOR IV
    salt2 = xor8(PNG_IHDR, C1)     # P2 XOR C1

    line1 = f"{C1.hex()}:{salt1.hex()}"
    line2 = f"{C2.hex()}:{salt2.hex()}"
    return (line1, line2, iv.hex())

def score_candidate(data: bytes, iv_off: int, ct_off: int) -> int:
    s = 0
    iv = data[iv_off:iv_off+8]

    # Prefer small headers
    s += max(0, 2000 - ct_off)
    s += max(0, 500 - iv_off)

    # Prefer IV immediately before ciphertext (common layout)
    if iv_off == ct_off - 8:
        s += 2000

    # Prefer "random-looking" IV, penalize ASCII-ish
    s += int(shannon_entropy(iv) * 300)
    if looks_ascii(iv):
        s -= 1500

    # Strong hint: DES90 container
    if data.startswith(b"DES90") and iv_off == 5 and ct_off == 13:
        s += 10_000

    return s

def main():
    in_path = pick_input_file()
    data = open(in_path, "rb").read()

    if len(data) < 24:
        raise SystemExit("File too small to contain IV + 2 DES blocks.")

    # Fast path: known DES90 container
    if data.startswith(b"DES90") and len(data) >= 5 + 8 + 16:
        iv_off, ct_off = 5, 13
        built = build_two_lines(data, iv_off, ct_off)
        if built:
            line1, line2, iv_hex = built
            with open("alvo.hash", "w", encoding="utf-8") as f:
                f.write(line1 + "\n")
                f.write(line2 + "\n")
            print("✅ Generated alvo.hash (detected DES90 container)")
            print("Input file :", in_path)
            print("IV offset  :", iv_off)
            print("CT offset  :", ct_off)
            print("IV (hex)   :", iv_hex)
            print("Line 1     :", line1)
            print("Line 2     :", line2)
            print("Output     : alvo.hash")
            return

    # General case: unknown container
    # Try common CT offsets; IV often at 0 or right before CT, or after small header.
    ct_offsets = [8, 13, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 256, 512, 1024, 2048, 4096]
    iv_offsets = [0, 5, 8, 16, 24, 32, 64, 128, 256, 512, 1024, 2048]

    best = None  # (score, iv_off, ct_off, line1, line2, iv_hex)

    for ct_off in ct_offsets:
        rem = len(data) - ct_off
        if rem < 16 or (rem % 8) != 0:
            continue

        # Prefer IV right before CT, then fallback IV offsets list
        candidates = []
        if ct_off - 8 >= 0:
            candidates.append(ct_off - 8)
        candidates.extend(iv_offsets)

        seen = set()
        for iv_off in candidates:
            if iv_off in seen:
                continue
            seen.add(iv_off)

            built = build_two_lines(data, iv_off, ct_off)
            if not built:
                continue
            line1, line2, iv_hex = built
            sc = score_candidate(data, iv_off, ct_off)

            if best is None or sc > best[0]:
                best = (sc, iv_off, ct_off, line1, line2, iv_hex)

    if best is None:
        raise SystemExit("Could not find a plausible layout. Your container may have a trailer (CT not multiple of 8) or different mode.")

    sc, iv_off, ct_off, line1, line2, iv_hex = best

    with open("alvo.hash", "w", encoding="utf-8") as f:
        f.write(line1 + "\n")
        f.write(line2 + "\n")

    print("✅ Generated alvo.hash (best heuristic layout)")
    print("Input file :", in_path)
    print("IV offset  :", iv_off)
    print("CT offset  :", ct_off)
    print("IV (hex)   :", iv_hex)
    print("Line 1     :", line1)
    print("Line 2     :", line2)
    print("Output     : alvo.hash")

if __name__ == "__main__":
    main()
