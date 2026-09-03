"""
FastAPI Server for Bulk Email Verifier
Provides real-time batch verification with SSE streaming,
CSV upload/parsing, single test endpoint, and export functionality.
"""

import asyncio
import csv
import io
import os
import time
import uuid
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import verifier

app = FastAPI(title="Genuine Bulk Email Verifier", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Active jobs storage in-memory
# job_id -> { "status": "running"|"completed", "total": N, "processed": N, "alive": N, "dead": N, "risky": N, "disposable": N, "results": [], "events_queue": asyncio.Queue }
JOBS: Dict[str, Dict[str, Any]] = {}

class SingleVerifyRequest(BaseModel):
    email: str
    check_smtp: bool = True
    check_catch_all: bool = True

class StartBatchRequest(BaseModel):
    emails: List[str]
    original_rows: Optional[List[Dict[str, str]]] = None
    email_column: Optional[str] = None
    concurrency: int = 10
    check_smtp: bool = True
    check_catch_all: bool = True
    timeout: float = 5.0

@app.get("/api/health")
async def health_check():
    port25_open = verifier.check_port25_connectivity()
    return {
        "status": "healthy",
        "port25_open": port25_open,
        "message": "Port 25 is open - direct SMTP verification enabled!" if port25_open else "Port 25 restricted on local network - DNS/MX verification mode"
    }

@app.post("/api/verify-single")
async def verify_single(req: SingleVerifyRequest):
    if not req.email:
        raise HTTPException(status_code=400, detail="Email is required")
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: verifier.verify_single_email(
                email=req.email,
                check_smtp=req.check_smtp,
                check_catch_all=req.check_catch_all
            )
        )
        return result
    except Exception as e:
        return {
            "email": req.email,
            "status": "ERROR",
            "category": "DEAD",
            "reason": f"Verification error: {str(e)}",
            "duration_ms": 0,
            "mx_found": False,
            "mx_host": "",
            "smtp_code": 0,
            "is_catch_all": False
        }

@app.post("/api/upload-csv")
async def upload_csv(file: UploadFile = File(...)):
    """Parses any CSV format, auto-detects email column, and returns preview."""
    try:
        content_bytes = await file.read()
        # Decode utf-8 with fallback
        try:
            content_str = content_bytes.decode('utf-8')
        except UnicodeDecodeError:
            content_str = content_bytes.decode('latin-1', errors='ignore')
            
        headers, rows, detected_col = verifier.parse_csv_data(content_str)
        
        if not headers or not rows:
            raise HTTPException(status_code=400, detail="CSV file appears to be empty or corrupted.")
            
        return {
            "filename": file.filename,
            "total_rows": len(rows),
            "headers": headers,
            "detected_column": detected_col,
            "preview": rows[:5],
            "raw_rows": rows
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to process CSV: {str(e)}")

def process_batch_job(job_id: str, emails: List[str], original_rows: List[Dict[str, str]], email_col: str, concurrency: int, check_smtp: bool, check_catch_all: bool, timeout: float):
    job = JOBS[job_id]
    queue: asyncio.Queue = job["events_queue"]
    loop: asyncio.AbstractEventLoop = job["loop"]
    
    start_time = time.time()
    
    def on_verified(result: Dict[str, Any], row_idx: int):
        job["processed"] += 1
        cat = result.get("category", "DEAD")
        if cat == "ALIVE":
            job["alive"] += 1
        elif cat == "DEAD":
            job["dead"] += 1
        elif cat == "RISKY":
            job["risky"] += 1
        elif cat == "DISPOSABLE":
            job["disposable"] += 1

        # Merge verification data with original row
        merged = {}
        if original_rows and row_idx < len(original_rows):
            merged = dict(original_rows[row_idx])
            
        merged["Verification_Status"] = result.get("status")
        merged["Category"] = cat
        merged["Reason"] = result.get("reason")
        merged["MX_Host"] = result.get("mx_host", "")
        merged["SMTP_Code"] = result.get("smtp_code", 0)
        merged["Is_Catch_All"] = "Yes" if result.get("is_catch_all") else "No"
        merged["Is_Disposable"] = "Yes" if result.get("is_disposable") else "No"
        merged["Duration_ms"] = result.get("duration_ms", 0)
        
        item = {
            "index": row_idx,
            "email": result["email"],
            "result": result,
            "merged": merged,
            "stats": {
                "processed": job["processed"],
                "total": job["total"],
                "alive": job["alive"],
                "dead": job["dead"],
                "risky": job["risky"],
                "disposable": job["disposable"],
                "percent": round((job["processed"] / job["total"]) * 100, 1),
                "speed": round(job["processed"] / max(0.1, time.time() - start_time), 1)
            }
        }
        job["results"].append(item)
        asyncio.run_coroutine_threadsafe(queue.put(item), loop)

    # Run multi-threaded executor
    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as executor:
        future_map = {
            executor.submit(
                verifier.verify_single_email,
                email=email,
                check_smtp=check_smtp,
                check_catch_all=check_catch_all,
                timeout=timeout
            ): idx for idx, email in enumerate(emails)
        }
        for future in as_completed(future_map):
            idx = future_map[future]
            try:
                res = future.result()
            except Exception as e:
                res = {
                    "email": emails[idx],
                    "status": "ERROR",
                    "category": "DEAD",
                    "reason": str(e),
                    "duration_ms": 0
                }
            on_verified(res, idx)
            
    job["status"] = "completed"
    asyncio.run_coroutine_threadsafe(queue.put({"type": "COMPLETED"}), loop)

@app.post("/api/start-batch")
async def start_batch(req: StartBatchRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    loop = asyncio.get_running_loop()
    events_queue = asyncio.Queue()
    
    total = len(req.emails)
    JOBS[job_id] = {
        "status": "running",
        "total": total,
        "processed": 0,
        "alive": 0,
        "dead": 0,
        "risky": 0,
        "disposable": 0,
        "results": [],
        "events_queue": events_queue,
        "loop": loop,
        "start_time": time.time(),
        "original_rows": req.original_rows or [],
        "email_col": req.email_column or "email"
    }
    
    background_tasks.add_task(
        process_batch_job,
        job_id=job_id,
        emails=req.emails,
        original_rows=req.original_rows or [],
        email_col=req.email_column or "email",
        concurrency=req.concurrency,
        check_smtp=req.check_smtp,
        check_catch_all=req.check_catch_all,
        timeout=req.timeout
    )
    
    return {"job_id": job_id, "total": total}

@app.get("/api/stream/{job_id}")
async def stream_job_events(job_id: str):
    """Server-Sent Events endpoint streaming live verifications to the client."""
    if job_id not in JOBS:
        raise HTTPException(status_code=404, detail="Job not found")
        
    job = JOBS[job_id]
    queue: asyncio.Queue = job["events_queue"]

    async def event_generator():
        import json
        while True:
            item = await queue.get()
            if isinstance(item, dict) and item.get("type") == "COMPLETED":
                yield f"event: completed\ndata: {json.dumps({'status': 'finished'})}\n\n"
                break
            yield f"data: {json.dumps(item)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

@app.get("/api/export/{job_id}")
async def export_csv(job_id: str, filter: str = "alive"):
    """
    Exports verification results as CSV.
    filter='alive': Only deliverable/alive mailboxes.
    filter='all': All records with verification metadata.
    """
    if job_id not in JOBS:
        raise HTTPException(status_code=404, detail="Job not found")
        
    job = JOBS[job_id]
    results = job.get("results", [])
    
    output = io.StringIO()
    
    # Filter records
    filtered_items = []
    for item in results:
        cat = item.get("result", {}).get("category", "")
        if filter == "alive":
            if cat == "ALIVE":
                filtered_items.append(item["merged"])
        elif filter == "dead":
            if cat == "DEAD":
                filtered_items.append(item["merged"])
        elif filter == "risky":
            if cat in ("RISKY", "DISPOSABLE"):
                filtered_items.append(item["merged"])
        else:
            filtered_items.append(item["merged"])
            
    if not filtered_items:
        output.write("No matching records found\n")
    else:
        # Determine all unique fieldnames preserving order
        fieldnames = []
        for item in filtered_items:
            for k in item.keys():
                if k not in fieldnames:
                    fieldnames.append(k)
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for row in filtered_items:
            writer.writerow(row)
            
    csv_bytes = output.getvalue().encode('utf-8-sig') # UTF-8 BOM for Excel compatibility
    filename = f"verified_emails_{filter}_{job_id[:8]}.csv"
    
    return StreamingResponse(
        io.BytesIO(csv_bytes),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

# Mount static files
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
async def get_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    with open(index_file, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())
