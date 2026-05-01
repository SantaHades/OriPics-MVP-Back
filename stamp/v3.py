import hmac
import hashlib
import struct

from .common import (
    MAGIC_BYTES,
    OFFSET_MAGIC,
    OFFSET_VERSION,
    OFFSET_SALT_ID,
    OFFSET_LENGTH,
    OFFSET_TIMESTAMP,
    OFFSET_WIDTH,
    OFFSET_HEIGHT,
    OFFSET_LAT,
    OFFSET_LNG,
    OFFSET_FINAL_HASH_V3,
    META_LENGTH_V3,
    PAYLOAD_LENGTH_V3,
    HASH_LENGTH,
    TIMESTAMP_LENGTH,
    UPLOAD_TYPE_PREFIXES,
)
from .v2 import make_timestamp  # 타임스탬프 로직 재사용

VERSION = 3


def build_meta_bytes_v3(salt_id: int, timestamp_str: str, width: int, height: int, lat_e6: int, lng_e6: int) -> bytes:
    if len(timestamp_str) != TIMESTAMP_LENGTH:
        raise ValueError(f"Timestamp must be {TIMESTAMP_LENGTH} chars, got {len(timestamp_str)}")
    if not (0 < salt_id < 2**16):
        raise ValueError(f"salt_id out of range: {salt_id}")
    if not (0 < width < 2**32) or not (0 < height < 2**32):
        raise ValueError(f"width/height out of range: {width}x{height}")
    if not (-90_000_000 <= lat_e6 <= 90_000_000):
        raise ValueError(f"lat_e6 out of range: {lat_e6}")
    if not (-180_000_000 <= lng_e6 <= 180_000_000):
        raise ValueError(f"lng_e6 out of range: {lng_e6}")

    meta = bytearray(META_LENGTH_V3)
    meta[OFFSET_MAGIC:OFFSET_MAGIC + 8] = MAGIC_BYTES
    meta[OFFSET_VERSION:OFFSET_VERSION + 2] = VERSION.to_bytes(2, "big")
    meta[OFFSET_SALT_ID:OFFSET_SALT_ID + 2] = salt_id.to_bytes(2, "big")
    meta[OFFSET_LENGTH:OFFSET_LENGTH + 4] = PAYLOAD_LENGTH_V3.to_bytes(4, "big")
    meta[OFFSET_TIMESTAMP:OFFSET_TIMESTAMP + TIMESTAMP_LENGTH] = timestamp_str.encode("ascii")
    meta[OFFSET_WIDTH:OFFSET_WIDTH + 4] = width.to_bytes(4, "big")
    meta[OFFSET_HEIGHT:OFFSET_HEIGHT + 4] = height.to_bytes(4, "big")
    struct.pack_into(">i", meta, OFFSET_LAT, lat_e6)
    struct.pack_into(">i", meta, OFFSET_LNG, lng_e6)
    return bytes(meta)


def parse_meta_bytes_v3(meta: bytes) -> dict:
    if len(meta) != META_LENGTH_V3:
        raise ValueError(f"meta must be {META_LENGTH_V3} bytes, got {len(meta)}")
    if meta[OFFSET_MAGIC:OFFSET_MAGIC + 8] != MAGIC_BYTES:
        raise ValueError("magic_mismatch")

    version = int.from_bytes(meta[OFFSET_VERSION:OFFSET_VERSION + 2], "big")
    if version != VERSION:
        raise ValueError(f"unsupported_version: {version}")

    salt_id = int.from_bytes(meta[OFFSET_SALT_ID:OFFSET_SALT_ID + 2], "big")
    length = int.from_bytes(meta[OFFSET_LENGTH:OFFSET_LENGTH + 4], "big")
    if length != PAYLOAD_LENGTH_V3:
        raise ValueError(f"length_mismatch: {length}")

    timestamp_str = meta[OFFSET_TIMESTAMP:OFFSET_TIMESTAMP + TIMESTAMP_LENGTH].decode("ascii")
    width = int.from_bytes(meta[OFFSET_WIDTH:OFFSET_WIDTH + 4], "big")
    height = int.from_bytes(meta[OFFSET_HEIGHT:OFFSET_HEIGHT + 4], "big")
    lat_e6 = struct.unpack_from(">i", meta, OFFSET_LAT)[0]
    lng_e6 = struct.unpack_from(">i", meta, OFFSET_LNG)[0]

    return {
        "version": version,
        "salt_id": salt_id,
        "length": length,
        "timestamp": timestamp_str,
        "width": width,
        "height": height,
        "lat_e6": lat_e6,
        "lng_e6": lng_e6,
    }


def compute_final_hash_v3(salt: bytes, meta_bytes: bytes, inner_hash: bytes, border_hash: bytes) -> bytes:
    if len(meta_bytes) != META_LENGTH_V3:
        raise ValueError(f"meta_bytes must be {META_LENGTH_V3} bytes")
    if len(inner_hash) != HASH_LENGTH or len(border_hash) != HASH_LENGTH:
        raise ValueError(f"inner_hash/border_hash must be {HASH_LENGTH} bytes")
    msg = meta_bytes + inner_hash + border_hash
    return hmac.new(salt, msg, hashlib.sha256).digest()


def verify_final_hash_v3(salt: bytes, meta_bytes: bytes, inner_hash: bytes, border_hash: bytes, extracted_final_hash: bytes) -> bool:
    expected = compute_final_hash_v3(salt, meta_bytes, inner_hash, border_hash)
    return hmac.compare_digest(expected, extracted_final_hash)
