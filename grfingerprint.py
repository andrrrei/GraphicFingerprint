import argparse
import base64
import binascii
import hashlib
import os
import sys
from dataclasses import dataclass
from typing import List, Tuple


PALETTE = " .o+=*BOX@%&#/^"
GAMMA = 1.8


@dataclass
class InputInfo:
    source: str
    key_type: str | None
    digest: bytes


def parse_hex_fingerprint(s: str) -> bytes:
    s = s.strip().lower().replace(":", "").replace(" ", "")
    if not s:
        raise ValueError("Empty fingerprint")
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise ValueError(f"Invalid hex fingerprint: {e}") from e


def read_openssh_pubkey(path: str) -> Tuple[str, bytes]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        line = f.readline().strip()

    parts = line.split()
    if len(parts) < 2:
        raise ValueError("Not a valid OpenSSH public key line")

    key_type = parts[0]
    key_b64 = parts[1]
    try:
        blob = base64.b64decode(key_b64.encode("ascii"), validate=True)
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}") from e

    return key_type, blob


def compute_fingerprint(blob_or_bytes: bytes, algo: str) -> bytes:
    algo = algo.lower()
    if algo == "md5":
        return hashlib.md5(blob_or_bytes).digest()
    if algo == "sha256":
        return hashlib.sha256(blob_or_bytes).digest()
    if algo == "sha1":
        return hashlib.sha1(blob_or_bytes).digest()
    raise ValueError(f"Unsupported hash: {algo}")


def drunken_bishop(
    digest: bytes, width: int, height: int
) -> Tuple[List[List[int]], Tuple[int, int], Tuple[int, int]]:
    if width < 3 or height < 3:
        raise ValueError("Unsupported field size (min 3x3)")

    max_count = len(PALETTE) - 1

    field = [[0 for _ in range(width)] for _ in range(height)]
    x = width // 2
    y = height // 2
    start = (x, y)

    for byte in digest:
        b = byte
        for _ in range(4):
            dx = 1 if (b & 0x01) else -1
            dy = 1 if (b & 0x02) else -1
            x = min(max(x + dx, 0), width - 1)
            y = min(max(y + dy, 0), height - 1)
            field[y][x] = min(field[y][x] + 1, max_count)
            b >>= 2

    end = (x, y)
    return field, start, end


def symmetrize_field(field: List[List[int]], mode: str, merge: str = "sum"):

    if mode == "none":
        return field

    h = len(field)
    w = len(field[0]) if h else 0

    def get(x, y):
        return field[y][x]

    out = [[0 for _ in range(w)] for _ in range(h)]

    for y in range(h):
        for x in range(w):
            vals = [get(x, y)]
            if mode in ("x", "xy"):
                vals.append(get(w - 1 - x, y))
            if mode in ("y", "xy"):
                vals.append(get(x, h - 1 - y))
            if mode == "xy":
                vals.append(get(w - 1 - x, h - 1 - y))

            out[y][x] = sum(vals) if merge == "sum" else max(vals)

    return out


def render_ascii(
    field: List[List[int]],
    start: Tuple[int, int],
    end: Tuple[int, int],
    title: str = "",
    border: bool = True,
) -> str:
    height = len(field)
    width = len(field[0]) if height else 0

    max_count = max(max(row) for row in field) or 1
    gamma = GAMMA

    def map_symbol(count: int) -> str:
        if count == 0:
            return " "
        norm = count / max_count
        level = int((norm**gamma) * (len(PALETTE) - 1))
        level = min(level, len(PALETTE) - 1)
        return PALETTE[level]

    lines: List[str] = []

    if title:
        lines.append(title)

    if border:
        lines.append("+" + "-" * width + "+")

    sx, sy = start
    ex, ey = end

    for y in range(height):
        row_chars = []
        for x in range(width):
            if (x, y) == (sx, sy):
                ch = "S"
            elif (x, y) == (ex, ey):
                ch = "E"
            else:
                row_chars.append(map_symbol(field[y][x]))
                continue
            row_chars.append(ch)

        line = "".join(row_chars)
        if border:
            lines.append("|" + line + "|")
        else:
            lines.append(line)

    if border:
        lines.append("+" + "-" * width + "+")
    return "\n".join(lines)


def detect_input_kind(value: str) -> str:
    return "pubkey" if os.path.isfile(value) else "hex"


def build_input_info(args) -> InputInfo:
    if args.fingerprint is not None:
        digest = parse_hex_fingerprint(args.fingerprint)
        return InputInfo(source="hex", key_type=None, digest=digest)

    if args.pubkey is not None:
        kt, blob = read_openssh_pubkey(args.pubkey)
        digest = compute_fingerprint(blob, args.hash)
        return InputInfo(source="pubkey", key_type=kt, digest=digest)

    kind = detect_input_kind(args.input)
    if kind == "pubkey":
        kt, blob = read_openssh_pubkey(args.input)
        digest = compute_fingerprint(blob, args.hash)
        return InputInfo(source="pubkey", key_type=kt, digest=digest)
    else:
        digest = parse_hex_fingerprint(args.input)
        return InputInfo(source="hex", key_type=None, digest=digest)


def main(argv: List[str]) -> int:
    p = argparse.ArgumentParser()

    g = p.add_mutually_exclusive_group()
    g.add_argument("-f", "--fingerprint")
    g.add_argument("-k", "--pubkey")

    p.add_argument(
        "input",
        nargs="?",
    )

    p.add_argument(
        "--hash",
        choices=["sha256", "md5", "sha1"],
        default="sha256",
    )
    p.add_argument("--width", type=int, default=17)
    p.add_argument("--height", type=int, default=9)
    p.add_argument("--no-border", action="store_true")
    p.add_argument(
        "--show-digest",
        action="store_true",
    )
    p.add_argument(
        "--sym",
        choices=["none", "x", "y", "xy"],
        default="none",
    )
    p.add_argument(
        "--sym-auto",
        action="store_true",
    )

    args = p.parse_args(argv)

    if args.fingerprint is None and args.pubkey is None and args.input is None:
        p.error("provide --fingerprint HEX or --pubkey PATH or positional input")

    try:
        info = build_input_info(args)
        field, start, end = drunken_bishop(info.digest, args.width, args.height)

        mode = args.sym
        if args.sym_auto:
            m = info.digest[0] & 0x03
            mode = ["none", "x", "y", "xy"][m]

        field = symmetrize_field(field, mode)

        title = ""
        if info.source == "pubkey":
            kt = info.key_type or "pubkey"
            title = f"{kt} {args.hash.upper()}"
        else:
            title = f"HEX ({len(info.digest)} bytes)"

        out = render_ascii(field, start, end, title=title, border=not args.no_border)
        print(out)

        if args.show_digest and info.source == "pubkey":
            print()
            print("digest(hex):", binascii.hexlify(info.digest).decode("ascii"))

        return 0

    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
