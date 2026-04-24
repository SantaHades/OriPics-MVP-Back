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

def get_masked_border_bytes(image_array, coords, bits_count):
    """
    Returns bytes of the 4 borders (Top, Bottom, Left, Right) 
    with bits at `coords[:bits_count]` masked (B-channel LSB set to 0).
    """
    h, w, _ = image_array.shape
    # Work on a copy of the border pixels to avoid full image copy if possible, 
    # but for simplicity and correctness, we'll use a targeted masking approach.
    
    # 1. Identify all border pixels
    # Top: y=0, Bottom: y=h-1, Left: x=0, Right: x=w-1
    # To be deterministic, we extract them in a fixed order.
    
    # Apply masking to a copy of the required pixels
    # For efficiency, we only need to mask the Top/Left bits used for storage
    temp_borders = {
        "top": image_array[0, :, :].copy(),
        "bottom": image_array[h-1, :, :].copy(),
        "left": image_array[1:h-1, 0, :].copy(),
        "right": image_array[1:h-1, w-1, :].copy()
    }
    
    # Masking logic
    for i in range(bits_count):
        y, x = coords[i]
        if y == 0: # Top border
            temp_borders["top"][x, 2] &= 0xFE
        elif x == 0: # Left border
            # Note: temp_borders["left"] starts from y=1
            temp_borders["left"][y-1, 2] &= 0xFE
            
    return (temp_borders["top"].tobytes() + 
            temp_borders["bottom"].tobytes() + 
            temp_borders["left"].tobytes() + 
            temp_borders["right"].tobytes())

def embed_data(image_array, timestamp_str: str, width: int, height: int):
    """
    Embeds metadata and hashes into the B channel LSBs of the top/left border.
    Covers 100% of pixels by including inner hash and border bytes.
    """
    if len(timestamp_str) != 15:
        raise ValueError(f"Timestamp must be 15 chars, got {len(timestamp_str)}")
        
    coords = get_border_coordinates(height, width)
    bits_count = DATA_LENGTH * 8
    if bits_count > len(coords):
        raise ValueError("Image is too small...")

    inner_hash = compute_inner_hash(image_array)
    
    # 1. Pack pre-payload (Metadata + Inner Hash)
    pre_payload = bytearray(MAGIC_BYTES)
    pre_payload += DATA_LENGTH.to_bytes(4, byteorder='big')
    pre_payload += timestamp_str.encode('ascii')
    pre_payload += width.to_bytes(4, byteorder='big')
    pre_payload += height.to_bytes(4, byteorder='big')
    pre_payload += inner_hash
    
    # 2. Get masked border data to cover the "outside" of the inner hash
    border_bytes = get_masked_border_bytes(image_array, coords, bits_count)
    
    # 3. Calculate final hash over Metadata + Inner Hash + Border Data + salt
    final_hash = hashlib.sha256(pre_payload + border_bytes + b"scipiro").digest()
    
    # The actual payload embedded
    payload = bytearray(MAGIC_BYTES)
    payload += DATA_LENGTH.to_bytes(4, byteorder='big')
    payload += timestamp_str.encode('ascii')
    payload += width.to_bytes(4, byteorder='big')
    payload += height.to_bytes(4, byteorder='big')
    payload += final_hash
    
    # Convert payload to bits
    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    
    img_copy = image_array.copy()
    for i, bit in enumerate(bits):
        y, x = coords[i]
        pixel_val = img_copy[y, x, 2]
        img_copy[y, x, 2] = (pixel_val & 0xFE) | bit
        
    return img_copy

def extract_data(image_array):
    """
    Extracts embedded data and validates 100% pixel integrity.
    """
    height, width, _ = image_array.shape
    coords = get_border_coordinates(height, width)
    bits_count = DATA_LENGTH * 8
    
    if len(coords) < bits_count:
        return None
        
    # Read payload bits
    payload_bits = []
    for i in range(bits_count):
        y, x = coords[i]
        b_bit = image_array[y, x, 2] & 1
        payload_bits.append(b_bit)
        
    payload_bytes = np.packbits(payload_bits).tobytes()
    
    # Validate Magic
    if payload_bytes[:4] != MAGIC_BYTES:
        return None
    if int.from_bytes(payload_bytes[4:8], byteorder='big') != DATA_LENGTH:
        return None
        
    timestamp_str = payload_bytes[8:23].decode('ascii')
    orig_w = int.from_bytes(payload_bytes[23:27], byteorder='big')
    orig_h = int.from_bytes(payload_bytes[27:31], byteorder='big')
    extracted_final_hash = payload_bytes[31:63]
    
    # Validation
    current_inner_hash = compute_inner_hash(image_array)
    # Reconstruct pre-payload
    pre_payload = payload_bytes[:31] + current_inner_hash
    # Get masked border bytes of the CURRENT image
    border_bytes = get_masked_border_bytes(image_array, coords, bits_count)
    
    expected_final_hash = hashlib.sha256(pre_payload + border_bytes + b"scipiro").digest()
    
    match = (extracted_final_hash == expected_final_hash)
    
    return {
        "match": match,
        "timestamp": timestamp_str,
        "width": orig_w,
        "height": orig_h,
    }
