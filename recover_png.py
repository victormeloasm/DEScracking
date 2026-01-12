#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

PNG_HDR = bytes.fromhex("89504e470d0a1a0a")

def derive_des_key_90s(password: str) -> bytes:
    return password.encode("latin-1", errors="ignore").ljust(8, b"\x00")[:8]

def pkcs5_unpad(data: bytes, block_size: int = 8) -> bytes | None:
    if not data or (len(data) % block_size) != 0:
        return None
    pad = data[-1]
    if pad < 1 or pad > block_size:
        return None
    if data[-pad:] != bytes([pad]) * pad:
        return None
    return data[:-pad]

def load_des90(path: str) -> tuple[bytes, bytes]:
    data = open(path, "rb").read()
    if data[:5] != b"DES90":
        raise ValueError("Header DES90 não encontrado (esperado: 5 bytes 'DES90').")
    iv = data[5:13]
    ct = data[13:]
    if len(iv) != 8 or len(ct) < 8 or (len(ct) % 8 != 0):
        raise ValueError("Arquivo inválido: IV=8 bytes e CT múltiplo de 8.")
    return iv, ct

def des_effective_56(key8: bytes) -> bytes:
    # remove o bit de paridade (LSB) de cada byte -> “chave efetiva”
    return bytes([b & 0xFE for b in key8])

def score_human(pw: str) -> int:
    # heurística simples: preferir letras (e 1ª letra maiúscula), evitar dígitos/estranhos
    s = 0
    if len(pw) == 8: s += 10
    if pw[:1].isupper() and pw[1:].islower(): s += 10
    s += sum(2 for c in pw if c.isalpha())
    s -= sum(3 for c in pw if c.isdigit())
    s -= sum(5 for c in pw if not (c.isalnum()))
    return s

def main():
    dict_path = sys.argv[1] if len(sys.argv) > 1 else "parity_256.txt"
    enc_path  = sys.argv[2] if len(sys.argv) > 2 else "target.png.des"
    out_path  = sys.argv[3] if len(sys.argv) > 3 else "target.recovered.png"

    try:
        from Crypto.Cipher import DES
    except ImportError:
        print("Erro: PyCryptodome não encontrado. Instale com: python3 -m pip install pycryptodome")
        sys.exit(1)

    iv, ct = load_des90(enc_path)

    found_pw = None
    found_key = None
    recovered = None

    # 1) achar qualquer senha que funcione
    for line in open(dict_path, "r", encoding="utf-8", errors="ignore"):
        pw = line.rstrip("\n")
        if not pw:
            continue
        key = derive_des_key_90s(pw)
        pt = DES.new(key, DES.MODE_CBC, iv=iv).decrypt(ct)

        if pt[:8] != PNG_HDR:
            continue

        unp = pkcs5_unpad(pt, 8)
        if unp is None or unp[:8] != PNG_HDR:
            continue

        found_pw = pw
        found_key = key
        recovered = unp
        break

    if found_pw is None:
        print("❌ Nenhuma senha do dicionário abriu o PNG.")
        sys.exit(2)

    open(out_path, "wb").write(recovered)

    eff = des_effective_56(found_key)

    # 2) listar todas as senhas equivalentes no seu txt (mesma chave efetiva)
    eq = []
    for line in open(dict_path, "r", encoding="utf-8", errors="ignore"):
        pw = line.rstrip("\n")
        if not pw:
            continue
        k = derive_des_key_90s(pw)
        if des_effective_56(k) == eff:
            eq.append(pw)

    eq_sorted = sorted(eq, key=score_human, reverse=True)

    print("✅ RECUPERADO!")
    print("Arquivo:", out_path)
    print("Senha encontrada (uma delas):", repr(found_pw))
    print("Chave (hex):", found_key.hex())
    print("Chave efetiva (56b, hex):", eff.hex())
    print()
    print(f"Senhas equivalentes (mesma chave efetiva) encontradas no txt: {len(eq_sorted)}")
    for pw in eq_sorted[:50]:
        print(" -", repr(pw))

    if eq_sorted:
        print()
        print("Sugestão (mais 'humana' pela heurística):", repr(eq_sorted[0]))

if __name__ == "__main__":
    main()
