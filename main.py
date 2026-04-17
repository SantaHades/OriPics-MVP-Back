import base64
import datetime
from io import BytesIO

import numpy as np
from PIL import Image
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from steganography import embed_data, extract_data, compute_inner_hash

app = FastAPI(title="OriPics MVP Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/process")
async def process_image(file: UploadFile = File(...)):
    if file.content_type not in ["image/png"]:
        raise HTTPException(status_code=400, detail="Only PNG images are supported.")
        
    try:
        content = await file.read()
        image = Image.open(BytesIO(content)).convert("RGBA")
        image_array = np.array(image)
        height, width, _ = image_array.shape
        
        # 1. Check if already stamped
        existing_data = extract_data(image_array)
        if existing_data is not None:
            # It was already stamped
            return {
                "status": "verified",
                "match": existing_data["match"],
                "metadata": {
                    "timestamp": existing_data["timestamp"],
                    "width": existing_data["width"],
                    "height": existing_data["height"]
                }
            }
            
        # 2. Not stamped, so we stamp it
        # Format timestamp to 15 chars: YYMMDDHHmmssSSS
        now = datetime.datetime.now(datetime.timezone.utc)  # UTC (World Standard Time)
        # SSS requires manual extraction of microseconds
        timestamp_str = now.strftime("%y%m%d%H%M%S") + f"{now.microsecond // 1000:03d}"
        
        stamped_array = embed_data(image_array, timestamp_str, width, height)
        
        # Calculate the hash to return to user (for info purposes, not embedded directly as hex)
        # We compute inner hash again to return as hex just for the UI
        inner_hash = compute_inner_hash(stamped_array).hex()
        
        # Convert back to PIL Image
        # If original was RGB, convert back? We converted to RGBA to be safe.
        stamped_image = Image.fromarray(stamped_array, mode="RGBA")
        
        output_buffer = BytesIO()
        stamped_image.save(output_buffer, format="PNG")
        output_buffer.seek(0)
        
        base64_encoded = base64.b64encode(output_buffer.read()).decode("utf-8")
        base64_png = f"data:image/png;base64,{base64_encoded}"
        
        return {
            "status": "stamped",
            "image": base64_png,
            "metadata": {
                "timestamp": timestamp_str,
                "width": width,
                "height": height,
                "hash": inner_hash
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
