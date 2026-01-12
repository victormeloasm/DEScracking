#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

def pkcs5_pad(data: bytes, block_size: int = 8) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def derive_des_key_90s(password: str) -> bytes:
    # "Anos 90": ASCII/Latin-1, pad com NUL até 8, corta em 8
    return password.encode("latin-1", errors="ignore").ljust(8, b"\x00")[:8]

def main():
    in_path = "target.png"
    out_path = "target.png.des"
    password = "Oblivion"

    try:
        from Crypto.Cipher import DES
    except ImportError:
        print("Erro: PyCryptodome não encontrado.")
        print("Instale com: python3 -m pip install pycryptodome")
        sys.exit(1)

    with open(in_path, "rb") as f:
        pt = f.read()

    key = derive_des_key_90s(password)
    iv = os.urandom(8)

    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pkcs5_pad(pt, 8))

    with open(out_path, "wb") as f:
        f.write(b"DES90")
        f.write(iv)
        f.write(ct)

    print("OK!")
    print(f"Entrada : {in_path}")
    print(f"Saída   : {out_path}")
    print(f"Senha   : {password}")
    print(f"Chave   : {key.hex()} (8 bytes)")
    print(f"IV      : {iv.hex()} (8 bytes)")
    print(f"Header  : DES90 (5 bytes) + IV (8) + CIPHERTEXT ({len(ct)} bytes)")

if __name__ == "__main__":
    main()
