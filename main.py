import base64
import datetime
import json
import os
import time
import asyncio
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import jwt
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from supabase import create_client

from stamp import v2 as stamp_v2
from stamp.common import META_LENGTH, UPLOAD_TYPE_PREFIXES

app = FastAPI(title="OriPics MVP Backend v2")

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

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")
BUCKET_NAME = "oripics-proofs"
JWT_SECRET = os.environ.get("ORIPICS_JWT_SECRET", "")
CURRENT_SALT_ID = int(os.environ.get("ORIPICS_CURRENT_SALT_ID", "1"))
CURRENT_VERSION = int(os.environ.get("ORIPICS_CURRENT_VERSION", "2"))

JWT_TTL_SECONDS = 300
SIGNED_UPLOAD_TTL_SECONDS = 60

supabase_client = None
if SUPABASE_URL and SUPABASE_SERVICE_KEY:
    supabase_client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    print(f"[Supabase] Connected to {SUPABASE_URL}")
else:
    print("[Supabase] WARNING: missing SUPABASE_URL or SUPABASE_SERVICE_KEY")

if not JWT_SECRET:
    print("[Config] WARNING: ORIPICS_JWT_SECRET is not set")


def get_salt(salt_id: int) -> bytes:
    env_key = f"ORIPICS_SALT_V2_{salt_id:03d}"
    salt_hex = os.environ.get(env_key)
    if not salt_hex:
        raise HTTPException(status_code=400, detail=f"unknown_salt_id:{salt_id}")
    try:
        return bytes.fromhex(salt_hex)
    except ValueError:
        raise HTTPException(status_code=500, detail="malformed_salt")


CURRENT_DIR = Path(__file__).parent
HF_DATA_DIR = Path("/data")

if HF_DATA_DIR.exists():
    BASE_STORAGE_DIR = HF_DATA_DIR
elif os.environ.get("SPACE_ID"):
    BASE_STORAGE_DIR = Path("/tmp")
else:
    BASE_STORAGE_DIR = CURRENT_DIR

DATA_DIR = BASE_STORAGE_DIR / "data"
COUNTER_FILE = DATA_DIR / "counter.json"
DATA_DIR.mkdir(parents=True, exist_ok=True)


class DailyCounter:
    def __init__(self):
        self.count = 0
        self.load()

    def _today(self):
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")

    def load(self):
        if COUNTER_FILE.exists():
            try:
                with open(COUNTER_FILE, "r") as f:
                    data = json.load(f)
                    if data.get("date") == self._today():
                        self.count = data.get("count", 0)
                        return
            except Exception:
                pass
        self.count = 0

    def save(self):
        try:
            with open(COUNTER_FILE, "w") as f:
                json.dump({"date": self._today(), "count": self.count}, f)
        except Exception as e:
            print(f"[Counter] save error: {e}")

    def next(self) -> int:
        self.load()
        self.count += 1
        self.save()
        return self.count


daily_counter = DailyCounter()


HEX32_REGEX = r"^[0-9a-fA-F]{64}$"


class SignRequest(BaseModel):
    inner_hash: str = Field(pattern=HEX32_REGEX)
    border_hash: str = Field(pattern=HEX32_REGEX)
    width: int = Field(gt=0, lt=2**32)
    height: int = Field(gt=0, lt=2**32)
    upload_type: str = "F"

    @field_validator("upload_type")
    @classmethod
    def validate_upload_type(cls, v: str) -> str:
        return v if v in UPLOAD_TYPE_PREFIXES else "F"


class ConfirmRequest(BaseModel):
    jwt_token: str


class VerifyRequest(BaseModel):
    meta_hex: str
    inner_hash: str = Field(pattern=HEX32_REGEX)
    border_hash: str = Field(pattern=HEX32_REGEX)
    extracted_final_hash: str = Field(pattern=HEX32_REGEX)

    @field_validator("meta_hex")
    @classmethod
    def validate_meta_hex(cls, v: str) -> str:
        if len(v) != META_LENGTH * 2:
            raise ValueError(f"meta_hex must be {META_LENGTH * 2} hex chars")
        bytes.fromhex(v)
        return v.lower()


def make_link_id(prefix: str) -> tuple[str, datetime.datetime]:
    now = datetime.datetime.now(datetime.timezone.utc)
    if prefix not in UPLOAD_TYPE_PREFIXES:
        prefix = "F"
    ts_part = now.strftime("%y%m%d-%H%M%S")
    ms_part = f"{now.microsecond // 1000:03d}"
    count = daily_counter.next()
    return f"{prefix}{ts_part}-{ms_part}{count}", now


def storage_path_for(link_id: str, dt: datetime.datetime) -> str:
    yy = dt.strftime("%y")
    mmdd = dt.strftime("%m%d")
    return f"{yy}{mmdd}/{link_id}.png"


def issue_jwt(link_id: str, storage_path: str, timestamp_str: str) -> str:
    now = int(time.time())
    payload = {
        "iat": now,
        "exp": now + JWT_TTL_SECONDS,
        "aud": "links/confirm",
        "link_id": link_id,
        "storage_path": storage_path,
        "timestamp": timestamp_str,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"], audience="links/confirm")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="jwt_expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="jwt_invalid")


@app.get("/")
async def root():
    return {"status": "running", "service": "OriPics Backend v2"}


@app.post("/api/sign")
async def sign(req: SignRequest):
    if not supabase_client:
        raise HTTPException(status_code=503, detail="storage_unavailable")

    salt_id = CURRENT_SALT_ID
    salt = get_salt(salt_id)

    timestamp_str = stamp_v2.make_timestamp(req.upload_type)
    meta_bytes = stamp_v2.build_meta_bytes(salt_id, timestamp_str, req.width, req.height)
    final_hash = stamp_v2.compute_final_hash(
        salt,
        meta_bytes,
        bytes.fromhex(req.inner_hash),
        bytes.fromhex(req.border_hash),
    )

    link_id, now = make_link_id(req.upload_type)
    path = storage_path_for(link_id, now)

    try:
        signed = supabase_client.storage.from_(BUCKET_NAME).create_signed_upload_url(path)
        signed_upload_url = signed.get("signed_url") if isinstance(signed, dict) else getattr(signed, "signed_url", None)
        upload_token = signed.get("token") if isinstance(signed, dict) else getattr(signed, "token", None)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"signed_url_error:{e}")

    token = issue_jwt(link_id, path, timestamp_str)

    return {
        "version": CURRENT_VERSION,
        "salt_id": salt_id,
        "timestamp": timestamp_str,
        "meta_hex": meta_bytes.hex(),
        "final_hash": final_hash.hex(),
        "link_id": link_id,
        "storage_path": path,
        "signed_upload_url": signed_upload_url,
        "upload_token": upload_token,
        "jwt": token,
        "jwt_ttl": JWT_TTL_SECONDS,
    }


@app.post("/api/links/confirm")
async def confirm(req: ConfirmRequest):
    if not supabase_client:
        raise HTTPException(status_code=503, detail="storage_unavailable")

    claims = decode_jwt(req.jwt_token)
    link_id = claims["link_id"]
    storage_path = claims["storage_path"]

    try:
        listing = supabase_client.storage.from_(BUCKET_NAME).list(
            path=str(Path(storage_path).parent),
            options={"search": Path(storage_path).name},
        )
        exists = any(item.get("name") == Path(storage_path).name for item in (listing or []))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"storage_check_error:{e}")

    if not exists:
        raise HTTPException(status_code=404, detail="upload_not_found")

    return {
        "link_id": link_id,
        "timestamp": claims["timestamp"],
        "storage_path": storage_path,
    }


@app.post("/api/verify")
async def verify(req: VerifyRequest):
    meta_bytes = bytes.fromhex(req.meta_hex)
    try:
        parsed = stamp_v2.parse_meta_bytes(meta_bytes)
    except ValueError as e:
        return {"match": False, "reason": str(e)}

    try:
        salt = get_salt(parsed["salt_id"])
    except HTTPException as e:
        return {"match": False, "reason": e.detail}

    match = stamp_v2.verify_final_hash(
        salt,
        meta_bytes,
        bytes.fromhex(req.inner_hash),
        bytes.fromhex(req.border_hash),
        bytes.fromhex(req.extracted_final_hash),
    )

    return {
        "match": match,
        "version": parsed["version"],
        "metadata": {
            "timestamp": parsed["timestamp"],
            "width": parsed["width"],
            "height": parsed["height"],
        },
    }


@app.get("/api/links/{link_id}")
async def get_link(link_id: str):
    try:
        if link_id and link_id[0].isalpha():
            yy = link_id[1:3]
            mmdd = link_id[3:7]
        else:
            yy = link_id[0:2]
            mmdd = link_id[2:6]
    except Exception:
        raise HTTPException(status_code=400, detail="invalid_link_id")

    storage_path = f"{yy}{mmdd}/{link_id}.png"

    if not supabase_client:
        raise HTTPException(status_code=503, detail="storage_unavailable")

    try:
        content = supabase_client.storage.from_(BUCKET_NAME).download(storage_path)
    except Exception:
        raise HTTPException(status_code=404, detail="link_not_found")

    if not content:
        raise HTTPException(status_code=404, detail="link_not_found")

    base64_encoded = base64.b64encode(content).decode("utf-8")
    return {
        "image": f"data:image/png;base64,{base64_encoded}",
        "storage_path": storage_path,
    }


async def cleanup_task():
    while True:
        if supabase_client:
            try:
                seven_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)
                folders = supabase_client.storage.from_(BUCKET_NAME).list()
                if folders:
                    for folder in folders:
                        name = folder.get("name")
                        if not name:
                            continue
                        files = supabase_client.storage.from_(BUCKET_NAME).list(name)
                        if not files:
                            continue
                        for f in files:
                            created = f.get("created_at")
                            if not created:
                                continue
                            try:
                                created_dt = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
                            except ValueError:
                                continue
                            if created_dt < seven_days_ago:
                                supabase_client.storage.from_(BUCKET_NAME).remove([f"{name}/{f['name']}"])
                                print(f"[Cleanup] removed {name}/{f['name']}")
            except Exception as e:
                print(f"[Cleanup] error: {e}")
        await asyncio.sleep(3600)


@app.on_event("startup")
async def on_startup():
    asyncio.create_task(cleanup_task())
