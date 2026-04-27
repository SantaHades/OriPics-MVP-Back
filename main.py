import base64
import datetime
import uuid
import json
import os
import time
import asyncio
from io import BytesIO
from pathlib import Path

# Load .env for local development
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import numpy as np
from PIL import Image, ImageOps
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from supabase import create_client

from steganography import embed_data, extract_data, compute_inner_hash

# --- App Setup ---
app = FastAPI(title="OriPics MVP Backend")

@app.get("/")
async def root():
    return {"status": "running", "message": "OriPics Backend is active"}

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://ori-pics-mvp-front.vercel.app",
        "https://ori.pics",
        "https://www.ori.pics",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Supabase Storage Setup ---
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")
BUCKET_NAME = "oripics-proofs"

supabase_client = None
if SUPABASE_URL and SUPABASE_SERVICE_KEY:
    supabase_client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    print(f"[Supabase] Connected to {SUPABASE_URL}")
else:
    print("[Supabase] WARNING: Missing SUPABASE_URL or SUPABASE_SERVICE_KEY. Falling back to local storage.")

# --- Fallback: Local Storage (for development) ---
CURRENT_DIR = Path(__file__).parent
HF_DATA_DIR = Path("/data")

if HF_DATA_DIR.exists():
    BASE_STORAGE_DIR = HF_DATA_DIR
elif os.environ.get("SPACE_ID"):
    BASE_STORAGE_DIR = Path("/tmp")
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
        self.load()
        self.count += 1
        self.save()
        return self.count

daily_counter = DailyCounter()

# In-memory cache for 3-minute temporary storage
temp_stamped_cache = {}

async def cleanup_task():
    """Background task to cleanup temp cache (3 mins) and old Supabase files (7 days)"""
    while True:
        # 1. Cleanup temp cache (3 mins)
        now = time.time()
        expired_sessions = [sid for sid, data in temp_stamped_cache.items() if data['expiry'] < now]
        for sid in expired_sessions:
            del temp_stamped_cache[sid]
        
        # 2. Cleanup old files (7 days) - Supabase Storage
        if supabase_client:
            try:
                seven_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)
                # List files and delete old ones
                result = supabase_client.storage.from_(BUCKET_NAME).list()
                if result:
                    for folder in result:
                        if folder.get("name"):
                            # List files in date folders
                            sub_files = supabase_client.storage.from_(BUCKET_NAME).list(folder["name"])
                            if sub_files:
                                for f in sub_files:
                                    if f.get("created_at"):
                                        created = datetime.datetime.fromisoformat(f["created_at"].replace("Z", "+00:00"))
                                        if created < seven_days_ago:
                                            file_path = f"{folder['name']}/{f['name']}"
                                            supabase_client.storage.from_(BUCKET_NAME).remove([file_path])
                                            print(f"[Cleanup] Deleted expired file: {file_path}")
            except Exception as e:
                print(f"[Cleanup] Supabase cleanup error: {e}")
        else:
            # Fallback: local filesystem cleanup
            seven_days_ago = now - (7 * 24 * 3600)
            for root, dirs, files in os.walk(STORAGE_DIR, topdown=False):
                for name in files:
                    file_path = Path(root) / name
                    if file_path.stat().st_mtime < seven_days_ago:
                        try:
                            file_path.unlink()
                        except: pass
                if not os.listdir(root) and root != str(STORAGE_DIR):
                    try: os.rmdir(root)
                    except: pass
        
        await asyncio.sleep(3600)  # Run every hour (Supabase doesn't need minute-level checks)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(cleanup_task())

class LinkCreateRequest(BaseModel):
    session_id: str
    upload_type: str = "F"

# --- API Endpoints ---
@app.post("/api/process")
async def process_image(file: UploadFile = File(...), upload_type: str = "F"):
    SUPPORTED_TYPES = ["image/png", "image/jpeg", "image/jpg", "image/webp", "image/bmp", "image/tiff", "image/gif"]
    if file.content_type not in SUPPORTED_TYPES:
        raise HTTPException(status_code=400, detail=f"Unsupported image format. Supported: PNG, JPG, WebP, BMP, TIFF, GIF")
        
    try:
        content = await file.read()
        image = Image.open(BytesIO(content))
        image = ImageOps.exif_transpose(image).convert("RGBA")
        image_array = np.array(image)
        height, width, _ = image_array.shape
        
        # 1. Check if already stamped
        existing_data = extract_data(image_array)
        if existing_data is not None:
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
        now = datetime.datetime.now(datetime.timezone.utc)
        # Prefix (1) + yymmddHHMMSS (12) + ms/10 (2) = 15 chars
        prefix = upload_type if upload_type in ["F", "P", "C"] else "F"
        timestamp_str = prefix + now.strftime("%y%m%d%H%M%S") + f"{now.microsecond // 10000:02d}"
        
        stamped_array = embed_data(image_array, timestamp_str, width, height)
        inner_hash = compute_inner_hash(stamped_array).hex()
        
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
            "expiry": time.time() + 180
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
    
    # Generate ID with prefix from metadata
    now = datetime.datetime.now(datetime.timezone.utc)
    prefix = meta["timestamp"][0] if meta["timestamp"][0] in ["F", "P", "C"] else "F"
    ts_part = now.strftime("%y%m%d-%H%M%S")
    ms_part = f"{now.microsecond // 1000:03d}"
    count = daily_counter.get_next()
    link_id = f"{prefix}{ts_part}-{ms_part}{count}"
    
    # Save to Supabase Storage or local fallback
    yy = now.strftime("%y")
    mmdd = now.strftime("%m%d")
    storage_path = f"{yy}{mmdd}/{link_id}.png"
    
    if supabase_client:
        try:
            supabase_client.storage.from_(BUCKET_NAME).upload(
                path=storage_path,
                file=img_bytes,
                file_options={"content-type": "image/png"}
            )
            print(f"[Supabase] Uploaded: {storage_path}")
        except Exception as e:
            print(f"[Supabase] Upload error: {e}")
            raise HTTPException(status_code=500, detail=f"Storage upload failed: {str(e)}")
    else:
        # Fallback: local file storage
        hhmm = now.strftime("%H%M")
        save_dir = STORAGE_DIR / yy / mmdd / hhmm
        save_dir.mkdir(parents=True, exist_ok=True)
        file_path = save_dir / f"{link_id}.png"
        with open(file_path, "wb") as f:
            f.write(img_bytes)
    
    # Clean up temp cache
    del temp_stamped_cache[req.session_id]
    
    return {
        "link_id": link_id,
        "metadata": meta
    }

@app.get("/api/links/{link_id}")
async def get_link_data(link_id: str):
    try:
        # Handle optional prefix (F/P/C)
        if link_id[0].isalpha():
            yy = link_id[1:3]
            mmdd = link_id[3:7]
        else:
            yy = link_id[0:2]
            mmdd = link_id[2:6]
            
        storage_path = f"{yy}{mmdd}/{link_id}.png"
        
        content = None
        
        # Try Supabase Storage first
        if supabase_client:
            try:
                result = supabase_client.storage.from_(BUCKET_NAME).download(storage_path)
                if result:
                    content = result
            except Exception as e:
                print(f"[Supabase] Download error for {storage_path}: {e}")
        
        # Fallback: local file storage
        if content is None:
            search_root = STORAGE_DIR / yy / mmdd
            if not search_root.exists():
                raise HTTPException(status_code=404, detail="Link not found")
                
            target_file = None
            for root, dirs, files in os.walk(search_root):
                if f"{link_id}.png" in files:
                    target_file = Path(root) / f"{link_id}.png"
                    break
            
            if not target_file:
                raise HTTPException(status_code=404, detail="Link not found")
                
            with open(target_file, "rb") as f:
                content = f.read()
        
        # Extract metadata from image
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
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))
