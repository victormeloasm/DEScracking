#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

def derive_des_key_90s(password: str) -> bytes:
    # igual ao seu cipher
    return password.encode("latin-1", errors="ignore").ljust(8, b"\x00")[:8]

def toggle_lsb_mask(key8: bytes, mask: int) -> bytes:
    # mask: 8 bits, 1 bit por byte -> se bit i=1, XOR 0x01 no byte i
    b = bytearray(key8)
    for i in range(8):
        if (mask >> i) & 1:
            b[i] ^= 0x01
    return bytes(b)

def main():
    wrong_pw = sys.argv[1] if len(sys.argv) > 1 else "Oblhwhon"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "parity_256.txt"

    base_key = derive_des_key_90s(wrong_pw)

    # Gera 256 variações; dedup por string (pode repetir se sair byte não-imprimível)
    seen = set()
    out = []

    for mask in range(256):
        k = toggle_lsb_mask(base_key, mask)

        # converte key->“senha” (latin-1 1:1)
        pw = k.decode("latin-1", errors="ignore")

        if pw not in seen:
            seen.add(pw)
            out.append(pw)

    with open(out_path, "w", encoding="utf-8") as f:
        for pw in out:
            f.write(pw + "\n")

    print(f"OK: base = {wrong_pw!r}")
    print(f"Key base (hex) = {base_key.hex()}")
    print(f"Geradas {len(out)} strings únicas (de até 256).")
    print(f"Saída: {out_path}")

if __name__ == "__main__":
    main()
