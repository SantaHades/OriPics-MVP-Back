"""
Reference implementation of v2 hash algorithm for cross-validating the TypeScript
oripics-stamp/v2.ts library. Pixel layout: RGBA8 row-major (height * width * 4).
"""
import hashlib
import json
import sys
from pathlib import Path

PAYLOAD_LENGTH = 71
PAYLOAD_BITS = PAYLOAD_LENGTH * 8


def select_embed_mode(width: int, height: int) -> str:
    cap = 2 * (width + height) - 4
    if cap >= PAYLOAD_BITS:
        return "b_only"
    if cap * 3 >= PAYLOAD_BITS:
        return "rgb_lsb"
    raise ValueError("image_too_small")


def get_border_coordinates(width: int, height: int):
    coords = []
    for x in range(width):
        coords.append((0, x))
    for x in range(width):
        coords.append((height - 1, x))
    for y in range(1, height - 1):
        coords.append((y, 0))
    for y in range(1, height - 1):
        coords.append((y, width - 1))
    return coords


def pixel_offset(width: int, y: int, x: int) -> int:
    return (y * width + x) * 4


def u32be(n: int) -> bytes:
    return n.to_bytes(4, "big")


def compute_inner_hash(pixels: bytes, width: int, height: int) -> bytes:
    inner_w = width - 2
    inner_h = height - 2
    if inner_w <= 0 or inner_h <= 0:
        raise ValueError("image_too_small")
    parts = [u32be(width), u32be(height)]
    for y in range(1, height - 1):
        row_start = (y * width + 1) * 4
        row_len = inner_w * 4
        parts.append(pixels[row_start:row_start + row_len])
    return hashlib.sha256(b"".join(parts)).digest()


def compute_border_hash(pixels: bytes, width: int, height: int, mode: str) -> bytes:
    coords = get_border_coordinates(width, height)
    border = bytearray()
    for (y, x) in coords:
        off = pixel_offset(width, y, x)
        border.extend(pixels[off:off + 4])

    if mode == "b_only":
        for i in range(PAYLOAD_BITS):
            border[i * 4 + 2] &= 0xFE
    elif mode == "rgb_lsb":
        used = (PAYLOAD_BITS + 2) // 3
        for i in range(used):
            base = i * 4
            border[base] &= 0xFE
            border[base + 1] &= 0xFE
            border[base + 2] &= 0xFE
    else:
        raise ValueError(f"unknown mode: {mode}")

    return hashlib.sha256(u32be(width) + u32be(height) + bytes(border)).digest()


def make_fixture_pixels(width: int, height: int, seed: int) -> bytes:
    """Deterministic pseudorandom pixel pattern for cross-language testing."""
    out = bytearray(width * height * 4)
    s = seed & 0xFFFFFFFF
    for i in range(len(out)):
        s = (s * 1103515245 + 12345) & 0xFFFFFFFF
        out[i] = (s >> 16) & 0xFF
    for i in range(3, len(out), 4):
        out[i] = 0xFF
    return bytes(out)


def emit_fixtures():
    fixtures = []
    for width, height, seed in [(50, 50, 1), (100, 100, 2), (143, 143, 3), (400, 400, 4), (1024, 768, 5)]:
        pixels = make_fixture_pixels(width, height, seed)
        mode = select_embed_mode(width, height)
        inner = compute_inner_hash(pixels, width, height).hex()
        border = compute_border_hash(pixels, width, height, mode).hex()
        first_pixel_bytes = pixels[:16].hex()
        fixtures.append({
            "width": width,
            "height": height,
            "seed": seed,
            "mode": mode,
            "first_16_bytes": first_pixel_bytes,
            "inner_hash": inner,
            "border_hash": border,
        })
    return fixtures


if __name__ == "__main__":
    fixtures = emit_fixtures()
    print(json.dumps(fixtures, indent=2))
    out_path = Path(__file__).with_name("v2_fixtures.json")
    out_path.write_text(json.dumps(fixtures, indent=2))
    print(f"\n[wrote] {out_path}")
