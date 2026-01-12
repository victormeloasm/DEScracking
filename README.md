# PNG DES + CBC cracking
My way to crack DES and recovery a PNG

A seguir vai uma versão bem mais longa e detalhada, no estilo de tutorial técnico que você pode postar como artigo no LinkedIn ou colocar como README em um repositório. Eu mantive o texto bem explicativo, mas com linguagem de engenharia, e descrevendo exatamente o tipo de cadeia de ferramentas e raciocínio que você aplicou.

---

# Full Walkthrough

## Recovering a 1999 PNG from an Old HDD Encrypted with DES-CBC and PKCS#5 Padding

This is a detailed write-up of a real recovery I performed on a legacy file: a PNG image from 1999 stored on an old HDD, encrypted using DES in CBC mode with PKCS#5 padding. The recovered image is a personal photo of me and my little sister from that year.

The point of this write-up is not “DES is weak”, everyone knows that. The interesting part is the practical workflow required to actually recover the file correctly in the real world, especially when you are dealing with unknown container formats, legacy key handling quirks, and tool limitations.

---

## 1. The Situation

I had a file that was clearly an encrypted blob, but not packaged in a standard format like PGP, OpenSSL enc, or a modern archive.

At first glance, the recovery had four problems:

1. Identify the layout of the encrypted file
2. Extract or infer the IV used by CBC mode
3. Build a known plaintext target suitable for a GPU brute force
4. Correctly interpret the output of the cracking tool, since DES has key parity quirks

Even if you know DES is brute-forceable, you still need the “glue” to connect the ciphertext blob to a working cracking strategy.

---

## 2. Why PNG is a Gift in Known Plaintext Attacks

The key observation is that PNG files have a rigid and highly predictable structure at the beginning.

Every valid PNG starts with the 8 byte signature:

```
89 50 4E 47 0D 0A 1A 0A
```

Immediately after, the first chunk is IHDR and its header always begins with:

```
00 00 00 0D 49 48 44 52
```

So, without knowing anything else about the image, we know the first 16 bytes of plaintext with extremely high confidence.

That is perfect for DES because the block size is 8 bytes. It gives us two complete plaintext blocks:

P1 = PNG signature
P2 = IHDR header

---

## 3. CBC Mode Relationship and What Hashcat Needs

In CBC mode:

C1 = E(K, P1 XOR IV)
C2 = E(K, P2 XOR C1)

This is extremely useful, because if we know P1 and P2, we can build a DES known plaintext target.

What Hashcat effectively needs is a pair (ciphertext block, “salt”) where the salt represents the XOR input to the block cipher.

So we can define:

salt1 = P1 XOR IV
salt2 = P2 XOR C1

Then we feed Hashcat two digests:

Digest 1 is C1 and salt is salt1
Digest 2 is C2 and salt is salt2

This is the core bridge between a file format problem and a GPU cracking workload.

The only missing value is IV.

---

## 4. Reverse Engineering the Container and Extracting IV

The encrypted file was not a raw stream of IV||CT. It had extra bytes at the beginning. In my case, one of the formats used a 5 byte ASCII header:

```
DES90
```

So the layout was:

Header “DES90” (5 bytes)
IV (8 bytes)
Ciphertext (remaining bytes, multiple of 8)

Therefore:

IV offset was 5
Ciphertext offset was 13

However, this is not guaranteed for all legacy files. If you want a reusable recovery workflow, you need a tool that can discover this automatically.

So I built a Python extractor that tries plausible layouts and scores them.

### What the extractor does

Given a file:

1. It scans plausible ciphertext start offsets
   The remainder must be at least 16 bytes and block-aligned (multiple of 8)

2. It tests plausible IV offsets
   Typical patterns are:

   * IV right before ciphertext
   * IV near the beginning
   * IV after a small header

3. For each candidate pair (iv_off, ct_off), it constructs the two hash lines:
   line1 = C1 : (P1 XOR IV)
   line2 = C2 : (P2 XOR C1)

4. It ranks candidates using heuristics:

   * If the file contains DES90 and matches expected offsets, high score
   * IV should not look like ASCII header
   * IV tends to have higher entropy than structured header text
   * Prefer short headers and typical alignment patterns

This produced a deterministic answer in my case: the correct IV offset and the correct ciphertext offset.

The extractor then writes the final `alvo.hash` automatically.

---

## 5. Hashcat, Kernel Behavior, and Why It “Cracked Wrong”

Once I generated the `alvo.hash` file, I ran Hashcat in mode:

* 14000 which corresponds to DES in a known plaintext configuration

Hashcat successfully recovered something that looked like a password.

But the recovered password was not the original human password I had used.

At first glance that looks like a catastrophic bug. It is not.

It is a DES property.

---

## 6. The DES Key Parity Trap

### Why 256 passwords can decrypt the same file

DES keys are 64 bits, but only 56 bits are effective. The remaining bits are parity bits, one per byte.

Many libraries ignore the parity or normalize it internally. In practice, it creates a weird equivalence class behavior:

Multiple 8 byte strings map to the same effective 56-bit key used by the cipher.

This means:

* A cracking tool might output a candidate password that is not the original password string
* That candidate can still decrypt the ciphertext correctly
* There are often 256 parity variations that lead to the same effective key

So, even though the decryption works, you might still not have the “true” password.

This is one of those legacy crypto details that can waste hours if you do not know it.

---

## 7. My Fix: Generate a 256 Candidate Wordlist

To resolve this correctly, I wrote another Python tool:

Input: the recovered 8 byte candidate from Hashcat
Output: all parity-variant candidates that map to the same effective DES key

This produces a 256 entry wordlist.

Then I tested those candidates and looked for the one that corresponds to the real password I expected.

This step also confirmed that the “wrong” password output by Hashcat was not wrong cryptographically. It was simply another representative of the same DES effective key.

---

## 8. Decrypting and Reconstructing the PNG

Finally, I wrote the recovery script:

1. Read encrypted file
2. Extract IV and ciphertext according to the discovered offsets
3. Derive DES key bytes from the candidate password string
4. Decrypt DES-CBC
5. Remove PKCS#5 padding
6. Validate the PNG structure
7. Write output PNG

Validation is important. A wrong decryption might still produce some bytes that start with the PNG signature by coincidence if you are doing messy extraction. The script verifies that:

* the first 8 bytes match the PNG signature
* the IHDR chunk header exists at the right location
* basic structure makes sense before writing final output

At the end, the recovered PNG opened correctly and matched the expected image.

---

## 9. What This Demonstrates in Practice

This recovery chain demonstrates several real lessons:

1. Weak cryptography is not the full story
   You still need to connect ciphertext to a correct attack model.

2. Known plaintext is powerful when file formats are structured
   PNG is almost a perfect target because of its fixed header.

3. Tools can be correct even when they look wrong
   Hashcat output looked “incorrect” until DES parity equivalence was accounted for.

4. Real recovery requires tooling glue
   Small Python scripts were necessary to:

   * extract IV from unknown format
   * generate hash targets
   * handle parity variants
   * validate and reconstruct the file

This is the difference between theory and successfully recovering real data.







