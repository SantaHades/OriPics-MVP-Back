import hashlib
import numpy as np

MAGIC_BYTES = b"ORIP"
DATA_LENGTH = 63  # 4(magic) + 4(len) + 15(timestamp) + 4(width) + 4(height) + 32(hash)

def get_border_coordinates(height, width):
    """
    Returns a list of (y, x) tuples for the Top and Left borders.
    Top border: y=0, x from 0 to width-1
    Left border: x=0, y from 1 to height-1
    """
    coords = []
    for x in range(width):
        coords.append((0, x))
    for y in range(1, height):
        coords.append((y, 0))
    return coords

def compute_inner_hash(image_array):
    """
    Computes SHA-256 hash of the 'inner' image (excluding top, bottom, left, right borders 1px each).
    """
    inner_image = image_array[1:-1, 1:-1]
    # Ensure C-contiguous bytes to hash deterministically
    inner_bytes = np.ascontiguousarray(inner_image).tobytes()
    return hashlib.sha256(inner_bytes).digest()

def embed_data(image_array, timestamp_str: str, width: int, height: int):
    """
    Embeds metadata and inner image hash into the B channel LSBs of the top/left border.
    timestamp_str must be exactly 15 characters (YYMMDDHHmmssSSS).
    Returns the modified image_array.
    """
    if len(timestamp_str) != 15:
        raise ValueError(f"Timestamp must be 15 chars, got {len(timestamp_str)}")
        
    inner_hash = compute_inner_hash(image_array)
    
    # Pack pre-payload
    pre_payload = bytearray(MAGIC_BYTES)
    pre_payload += DATA_LENGTH.to_bytes(4, byteorder='big')
    pre_payload += timestamp_str.encode('ascii')
    pre_payload += width.to_bytes(4, byteorder='big')
    pre_payload += height.to_bytes(4, byteorder='big')
    pre_payload += inner_hash
    
    # Calculate final hash over the entire pre-payload
    final_hash = hashlib.sha256(pre_payload).digest()
    
    # The actual payload embedded
    payload = bytearray(MAGIC_BYTES)
    payload += DATA_LENGTH.to_bytes(4, byteorder='big')
    payload += timestamp_str.encode('ascii')
    payload += width.to_bytes(4, byteorder='big')
    payload += height.to_bytes(4, byteorder='big')
    payload += final_hash
    
    assert len(payload) == DATA_LENGTH, f"Payload length mismatch: {len(payload)}"
    
    # Convert payload to bits
    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    
    coords = get_border_coordinates(height, width)
    if len(bits) > len(coords):
        raise ValueError("Image is too small to hold the steganography data on its top/left borders.")
        
    img_copy = image_array.copy()
    
    # Embed in Blue channel (index 2), assuming image_array is at least RGB
    for i, bit in enumerate(bits):
        y, x = coords[i]
        pixel_val = img_copy[y, x, 2]
        # Clear LSB and set to `bit`
        img_copy[y, x, 2] = (pixel_val & ~1) | bit
        
    return img_copy

def extract_data(image_array):
    """
    Extracts embedded data from the B channel LSBs of the top/left border.
    Returns a dict { match: bool, timestamp: str, width: int, height: int } or None if no magic found.
    """
    height, width, _ = image_array.shape
    coords = get_border_coordinates(height, width)
    
    if len(coords) < DATA_LENGTH * 8:
        return None # Image too small
        
    # Read first 8 bytes (64 bits) to check Magic and Length
    first_64_bits = []
    for i in range(64):
        y, x = coords[i]
        b_bit = image_array[y, x, 2] & 1
        first_64_bits.append(b_bit)
        
    first_8_bytes = np.packbits(first_64_bits).tobytes()
    magic = first_8_bytes[:4]
    
    if magic != MAGIC_BYTES:
        return None  # No valid signature
        
    length = int.from_bytes(first_8_bytes[4:8], byteorder='big')
    if length != DATA_LENGTH:
        return None  # Tampered or invalid length
        
    # Read all payload bits
    total_bits_to_read = DATA_LENGTH * 8
    payload_bits = []
    for i in range(total_bits_to_read):
        y, x = coords[i]
        b_bit = image_array[y, x, 2] & 1
        payload_bits.append(b_bit)
        
    payload_bytes = np.packbits(payload_bits).tobytes()
    
    timestamp_str = payload_bytes[8:23].decode('ascii')
    orig_w = int.from_bytes(payload_bytes[23:27], byteorder='big')
    orig_h = int.from_bytes(payload_bytes[27:31], byteorder='big')
    extracted_final_hash = payload_bytes[31:63]
    
    # Reconstruct pre-payload to validate
    current_inner_hash = compute_inner_hash(image_array)
    pre_payload = payload_bytes[:31] + current_inner_hash
    expected_final_hash = hashlib.sha256(pre_payload).digest()
    
    match = (extracted_final_hash == expected_final_hash)
    
    return {
        "match": match,
        "timestamp": timestamp_str,
        "width": orig_w,
        "height": orig_h,
    }
