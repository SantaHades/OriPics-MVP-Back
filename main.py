import base64
import datetime
import uuid
import json
import os
import time
import asyncio
from io import BytesIO
from pathlib import Path

import numpy as np
from PIL import Image
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from steganography import embed_data, extract_data, compute_inner_hash

app = FastAPI(title="OriPics MVP Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://oripics-mvp.vercel.app", # 여기에 실제 Vercel 주소를 추가하세요.
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Persistence & Storage Setup ---
# Default to current script directory for local development
CURRENT_DIR = Path(__file__).parent
# Check for Hugging Face persistent storage mount point
HF_DATA_DIR = Path("/data")

if HF_DATA_DIR.exists():
    BASE_STORAGE_DIR = HF_DATA_DIR
else:
    BASE_STORAGE_DIR = CURRENT_DIR

STORAGE_DIR = BASE_STORAGE_DIR / "oripics_link"
DATA_DIR = BASE_STORAGE_DIR / "data"
COUNTER_FILE = DATA_DIR / "counter.json"

STORAGE_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

class DailyCounter:
    def __init__(self):
        self.load()

    def load(self):
        if COUNTER_FILE.exists():
            with open(COUNTER_FILE, "r") as f:
                data = json.load(f)
                if data.get("date") == self._get_today():
                    self.count = data.get("count", 0)
                    return
        self.count = 0

    def save(self):
        with open(COUNTER_FILE, "w") as f:
            json.dump({"date": self._get_today(), "count": self.count}, f)

    def _get_today(self):
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

    def get_next(self):
        self.load() # Refresh in case date changed
        self.count += 1
        self.save()
        return self.count

daily_counter = DailyCounter()

# In-memory cache for 3-minute temporary storage
# session_id -> { image_bytes, metadata, expiry }
temp_stamped_cache = {}

async def cleanup_task():
    """Background task to cleanup temp cache (3 mins) and old links (7 days)"""
    while True:
        # 1. Cleanup temp cache (3 mins)
        now = time.time()
        expired_sessions = [sid for sid, data in temp_stamped_cache.items() if data['expiry'] < now]
        for sid in expired_sessions:
            del temp_stamped_cache[sid]
        
        # 2. Cleanup old links (7 days)
        # We walk through the directory structure oripics_link/YY/MMDD/HHmm/
        seven_days_ago = now - (7 * 24 * 3600)
        for root, dirs, files in os.walk(STORAGE_DIR, topdown=False):
            for name in files:
                file_path = Path(root) / name
                if file_path.stat().st_mtime < seven_days_ago:
                    try:
                        file_path.unlink()
                    except: pass
            # Clean empty dirs
            if not os.listdir(root) and root != str(STORAGE_DIR):
                try: os.rmdir(root)
                except: pass
        
        await asyncio.sleep(60) # Run every minute

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(cleanup_task())

class LinkCreateRequest(BaseModel):
    session_id: str

# --- API Endpoints ---
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
        
        # Store in temp cache for 3 mins
        session_id = str(uuid.uuid4())
        temp_stamped_cache[session_id] = {
            "image_data": output_buffer.getvalue(),
            "metadata": {
                "timestamp": timestamp_str,
                "width": width,
                "height": height,
                "hash": inner_hash
            },
            "expiry": time.time() + 180 # 3 minutes
        }
        
        return {
            "status": "stamped",
            "image": base64_png,
            "session_id": session_id,
            "metadata": {
                "timestamp": timestamp_str,
                "width": width,
                "height": height,
                "hash": inner_hash
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/links/create")
async def create_link(req: LinkCreateRequest):
    if req.session_id not in temp_stamped_cache:
        raise HTTPException(status_code=404, detail="Session expired or not found. Please re-stamp within 3 minutes.")
    
    data = temp_stamped_cache[req.session_id]
    img_bytes = data["image_data"]
    meta = data["metadata"]
    
    # Generate ID: yymmdd-hhmmss-SSS + Counter
    now = datetime.datetime.now(datetime.timezone.utc)
    # The user example was 260418... SSS needs to be millisecond
    ts_part = now.strftime("%y%m%d-%H%M%S")
    ms_part = f"{now.microsecond // 1000:03d}"
    count = daily_counter.get_next()
    link_id = f"{ts_part}-{ms_part}{count}"
    
    # Path: oripics_link/YY/MMDD/HHmm/ID.png
    yy = now.strftime("%y")
    mmdd = now.strftime("%m%d")
    hhmm = now.strftime("%H%M")
    
    save_dir = STORAGE_DIR / yy / mmdd / hhmm
    save_dir.mkdir(parents=True, exist_ok=True)
    file_path = save_dir / f"{link_id}.png"
    
    with open(file_path, "wb") as f:
        f.write(img_bytes)
        
    # Clean up temp cache early as it's now permanent
    del temp_stamped_cache[req.session_id]
    
    return {
        "link_id": link_id,
        "metadata": meta
    }

@app.get("/api/links/{link_id}")
async def get_link_data(link_id: str):
    # Find the file in the directory structure
    # Since link_id starts with YYMMDD, we can narrow it down
    # Format: 260418-175959-7371
    try:
        yy = link_id[0:2]
        mmdd = link_id[2:6]
        # We don't have hhmm in the ID exactly, but we can search for it
        # Actually, if we just search for the filename ID.png within STORAGE_DIR/yy/mmdd/
        search_root = STORAGE_DIR / yy / mmdd
        if not search_root.exists():
            raise HTTPException(status_code=404, detail="Link not found (Date mismatch)")
            
        target_file = None
        for root, dirs, files in os.walk(search_root):
            if f"{link_id}.png" in files:
                target_file = Path(root) / f"{link_id}.png"
                break
        
        if not target_file:
            raise HTTPException(status_code=404, detail="Link not found")
            
        with open(target_file, "rb") as f:
            content = f.read()
            
        # Re-extract transparency to get metadata if needed, 
        # but the user just wants to view the page. 
        # We return base64 and basic info.
        image = Image.open(BytesIO(content))
        image_array = np.array(image)
        extract = extract_data(image_array)
        
        base64_encoded = base64.b64encode(content).decode("utf-8")
        
        return {
            "image": f"data:image/png;base64,{base64_encoded}",
            "metadata": {
                "timestamp": extract["timestamp"],
                "width": extract["width"],
                "height": extract["height"]
            }
        }
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))
