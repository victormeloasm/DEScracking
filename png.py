#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import binascii
import zlib
from pathlib import Path
from datetime import datetime

PNG_SIG = b"\x89PNG\r\n\x1a\n"

CHUNK_DESC = {
    b'IHDR': "Image header (required, first chunk)",
    b'PLTE': "Palette (required for color type 3; optional for 2/6)",
    b'IDAT': "Image data (zlib/DEFLATE compressed stream, may be multiple chunks)",
    b'IEND': "End of file (required, last chunk)",
    b'tEXt': "Text (Latin-1: keyword\\0text)",
    b'zTXt': "Compressed text",
    b'iTXt': "International text (UTF-8, may be compressed)",
    b'gAMA': "Gamma",
    b'cHRM': "Chromaticity",
    b'sRGB': "sRGB rendering intent",
    b'pHYs': "Pixel dimensions / density",
    b'tIME': "Last modification time",
    b'tRNS': "Transparency information",
    b'bKGD': "Suggested background color",
    b'sBIT': "Significant bits",
    b'hIST': "Palette histogram",
    b'iCCP': "Embedded ICC profile (compressed)",
}

COLOR_TYPE = {
    0: "Grayscale",
    2: "Truecolor (RGB)",
    3: "Indexed-color (palette)",
    4: "Grayscale + Alpha",
    6: "Truecolor + Alpha (RGBA)",
}

INTERLACE = {0: "None", 1: "Adam7"}
FILTER_METHOD = {0: "Adaptive filtering (only valid PNG value)"}  # PNG defines 0
COMP_METHOD = {0: "DEFLATE (zlib)"}  # PNG defines 0


def u32(b: bytes) -> int:
    return struct.unpack(">I", b)[0]


def read_chunks(data: bytes):
    """
    Yield (offset, length, ctype, cdata, crc_read, crc_calc) for chunks up to IEND.
    """
    if not data.startswith(PNG_SIG):
        raise ValueError("Invalid PNG signature (expected 89 50 4E 47 0D 0A 1A 0A).")

    pos = len(PNG_SIG)
    n = len(data)

    while pos + 12 <= n:
        length = u32(data[pos:pos + 4])
        ctype = data[pos + 4:pos + 8]
        start_data = pos + 8
        end_data = start_data + length
        crc_pos = end_data
        end_chunk = crc_pos + 4

        if end_chunk > n:
            raise ValueError(f"Truncated chunk {ctype!r}: length={length} at pos={pos}")

        cdata = data[start_data:end_data]
        crc_read = u32(data[crc_pos:crc_pos + 4])

        crc_calc = binascii.crc32(ctype)
        crc_calc = binascii.crc32(cdata, crc_calc) & 0xffffffff

        yield (pos, length, ctype, cdata, crc_read, crc_calc)

        pos = end_chunk
        if ctype == b'IEND':
            break


def chunk_properties(ctype: bytes):
    """
    PNG chunk type properties based on ASCII case bits.
    See PNG spec: critical/ancillary, public/private, reserved, safe-to-copy.
    """
    # lowercase bit = 0x20 in ASCII
    ancillary = bool(ctype[0] & 0x20)
    private = bool(ctype[1] & 0x20)
    reserved_bit_set = bool(ctype[2] & 0x20)  # should be False
    safe_to_copy = bool(ctype[3] & 0x20)

    return {
        "class": "ancillary" if ancillary else "critical",
        "scope": "private" if private else "public",
        "reserved_ok": (not reserved_bit_set),
        "copying": "safe-to-copy" if safe_to_copy else "unsafe-to-copy",
    }


def parse_ihdr(cdata: bytes):
    if len(cdata) != 13:
        raise ValueError(f"IHDR must be 13 bytes, got {len(cdata)} bytes.")
    w, h, bd, ct, cm, fm, im = struct.unpack(">IIBBBBB", cdata)
    return {
        "width": w,
        "height": h,
        "bit_depth": bd,
        "color_type": ct,
        "color_type_str": COLOR_TYPE.get(ct, f"Unknown({ct})"),
        "compression_method": cm,
        "compression_str": COMP_METHOD.get(cm, f"Unknown({cm})"),
        "filter_method": fm,
        "filter_str": FILTER_METHOD.get(fm, f"Unknown({fm})"),
        "interlace_method": im,
        "interlace_str": INTERLACE.get(im, f"Unknown({im})"),
    }


def parse_gama(cdata: bytes):
    if len(cdata) != 4:
        return None
    g = u32(cdata)
    return g / 100000.0


def parse_phys(cdata: bytes):
    if len(cdata) != 9:
        return None
    ppux = u32(cdata[0:4])
    ppuy = u32(cdata[4:8])
    unit = cdata[8]
    unit_str = "meter" if unit == 1 else "unknown"
    return {"ppux": ppux, "ppuy": ppuy, "unit": unit, "unit_str": unit_str}


def parse_time(cdata: bytes):
    if len(cdata) != 7:
        return None
    year = struct.unpack(">H", cdata[0:2])[0]
    month, day, hour, minute, second = cdata[2], cdata[3], cdata[4], cdata[5], cdata[6]
    try:
        return datetime(year, month, day, hour, minute, second).isoformat()
    except Exception:
        return f"{year:04d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d} (invalid date fields)"


def summarize_idat(chunks):
    idat = b"".join(cdata for (_, _, ctype, cdata, _, _) in chunks if ctype == b"IDAT")
    if not idat:
        return None

    info = {"idat_total_bytes": len(idat)}

    if len(idat) >= 2:
        cmf, flg = idat[0], idat[1]
        info["zlib_cmf"] = cmf
        info["zlib_flg"] = flg
        info["zlib_cm"] = cmf & 0x0F
        info["zlib_cinfo"] = (cmf >> 4) & 0x0F
        info["zlib_header_ok_mod31"] = (((cmf << 8) + flg) % 31 == 0)
        info["zlib_fdict"] = (flg >> 5) & 1
        info["zlib_flevel"] = (flg >> 6) & 3

    # Safe inflate preview (limit output to 1 MiB)
    try:
        d = zlib.decompressobj()
        out = d.decompress(idat, 1024 * 1024)
        info["inflate_preview_ok"] = True
        info["inflate_preview_bytes"] = len(out)
    except Exception as e:
        info["inflate_preview_ok"] = False
        info["inflate_error"] = repr(e)

    return info


def text_preview(cdata: bytes, limit: int = 200) -> str:
    # Try to decode safely; otherwise provide hex preview.
    raw = cdata[:limit]
    try:
        s = raw.decode("utf-8", errors="replace")
        # Show both decoded and hex for clarity (still limited).
        return f"decoded_preview={s!r} | hex_preview={raw.hex()}"
    except Exception:
        return f"hex_preview={raw.hex()}"


def analyze_png(png_path: Path) -> str:
    data = png_path.read_bytes()
    lines = []

    lines.append(f"PNG REPORT")
    lines.append(f"File: {png_path} ({len(data)} bytes)")
    lines.append(f"Signature OK: {data.startswith(PNG_SIG)}")
    if not data.startswith(PNG_SIG):
        lines.append("ERROR: Not a valid PNG signature. Stopping.")
        return "\n".join(lines)

    chunks = list(read_chunks(data))
    lines.append(f"Chunks parsed (up to IEND): {len(chunks)}")
    lines.append("")

    seen = set()
    crc_bad = 0
    ihdr_info = None

    for i, (pos, length, ctype, cdata, crc_read, crc_calc) in enumerate(chunks, 1):
        seen.add(ctype)
        ok_crc = (crc_read == crc_calc)
        if not ok_crc:
            crc_bad += 1

        ctype_str = ctype.decode("ascii", errors="replace")
        desc = CHUNK_DESC.get(ctype, "Unknown/less common chunk")
        props = chunk_properties(ctype)

        lines.append(f"[{i:02d}] Offset={pos}  Type={ctype_str}  Length={length}  CRC={'OK' if ok_crc else 'BAD'}")
        lines.append(f"     Meaning: {desc}")
        lines.append(f"     Properties: {props['class']}, {props['scope']}, reserved_ok={props['reserved_ok']}, {props['copying']}")

        if ctype == b'IHDR':
            ihdr_info = parse_ihdr(cdata)
            lines.append(
                "     IHDR: "
                f"{ihdr_info['width']}x{ihdr_info['height']}, "
                f"bit_depth={ihdr_info['bit_depth']}, "
                f"color_type={ihdr_info['color_type']} ({ihdr_info['color_type_str']}), "
                f"compression={ihdr_info['compression_method']} ({ihdr_info['compression_str']}), "
                f"filter={ihdr_info['filter_method']} ({ihdr_info['filter_str']}), "
                f"interlace={ihdr_info['interlace_method']} ({ihdr_info['interlace_str']})"
            )

        elif ctype == b'gAMA':
            g = parse_gama(cdata)
            if g is not None:
                lines.append(f"     gAMA: gamma={g}")

        elif ctype == b'pHYs':
            p = parse_phys(cdata)
            if p is not None:
                lines.append(f"     pHYs: ppux={p['ppux']} ppuy={p['ppuy']} unit={p['unit']} ({p['unit_str']})")

        elif ctype == b'tIME':
            t = parse_time(cdata)
            if t is not None:
                lines.append(f"     tIME: {t}")

        elif ctype in (b'tEXt', b'zTXt', b'iTXt'):
            lines.append(f"     Text preview: {text_preview(cdata)}")

        lines.append("")

    lines.append("SUMMARY")
    lines.append(f"- Bad CRC chunks: {crc_bad}")
    lines.append(f"- Has IHDR: {ihdr_info is not None}")
    lines.append(f"- Has PLTE: {b'PLTE' in seen}")
    lines.append(f"- Has tRNS: {b'tRNS' in seen}")
    lines.append(f"- IDAT chunk count: {sum(1 for c in chunks if c[2] == b'IDAT')}")
    lines.append(f"- Ends with IEND: {bool(chunks and chunks[-1][2] == b'IEND')}")
    if ihdr_info:
        lines.append(f"- Color type: {ihdr_info['color_type']} ({ihdr_info['color_type_str']})")
        lines.append(f"- Dimensions: {ihdr_info['width']}x{ihdr_info['height']}")
        lines.append(f"- Bit depth: {ihdr_info['bit_depth']}")
        lines.append(f"- Interlace: {ihdr_info['interlace_method']} ({ihdr_info['interlace_str']})")

    idat_info = summarize_idat(chunks)
    if idat_info:
        lines.append("")
        lines.append("IDAT / ZLIB DIAGNOSTICS (non-destructive preview)")
        for k, v in idat_info.items():
            lines.append(f"- {k}: {v}")

    lines.append("")
    lines.append("NOTES")
    lines.append("- PNG structure is highly standardized: signature + typed chunks + CRC.")
    lines.append("- The pixel data is stored in IDAT as a zlib/DEFLATE stream and uses per-scanline filtering.")
    lines.append("- This report is meant for file validation, forensics, and debugging (not for attacking encryption).")

    return "\n".join(lines)


def main():
    png_file = Path("target.png")
    report_file = Path("png_report.txt")

    if not png_file.exists():
        raise FileNotFoundError("target.png not found in the current directory.")

    report = analyze_png(png_file)
    report_file.write_text(report, encoding="utf-8")

    print(f"OK: Wrote report to {report_file.resolve()}")


if __name__ == "__main__":
    main()

