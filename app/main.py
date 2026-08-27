import os
import json
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, Response
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from contextlib import asynccontextmanager

from app.database import get_db, init_db
from app.vault import store_in_vault, read_from_vault, ensure_vault_exists
from app.analysis import analyze_binary

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    ensure_vault_exists()
    yield

app = FastAPI(title="rootBox - Malware Vault", lifespan=lifespan)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
def list_samples(request: Request, message: str = None):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM samples ORDER BY uploaded_at DESC")
    samples = cursor.fetchall()
    conn.close()
    return templates.TemplateResponse(request=request, name="index.html", context={"samples": samples, "message": message})

@app.get("/upload", response_class=HTMLResponse)
def upload_page(request: Request, error: str = None):
    return templates.TemplateResponse(request=request, name="upload.html", context={"error": error})

@app.post("/upload")
async def handle_upload(
    request: Request,
    file: UploadFile = File(...),
    threat_type: str = Form(...),
    file_format: str = Form(...),
    description: str = Form(""),
    analysis_notes: str = Form("")
):
    try:
        content = await file.read()
        if not content:
            return templates.TemplateResponse(request=request, name="upload.html", context={"error": "Uploaded file is empty."})

        vault_filename, sha256, md5, size = store_in_vault(content)

        # Run automated static analysis pipeline
        analysis_res = analyze_binary(content, file.filename, sha256, threat_type)

        conn = get_db()
        cursor = conn.cursor()

        # Check if hash already exists
        cursor.execute("SELECT id FROM samples WHERE sha256 = ?", (sha256,))
        existing = cursor.fetchone()
        if existing:
            conn.close()
            return templates.TemplateResponse(
                request=request,
                name="upload.html",
                context={"error": f"Sample with matching SHA-256 hash already exists in vault (ID #{existing['id']})."}
            )

        cursor.execute("""
            INSERT INTO samples (
                original_filename, vault_filename, file_size, sha256, md5, threat_type, file_format, description, analysis_notes,
                entropy, entropy_level, magic_type, extracted_strings, hex_dump, yara_rule
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            file.filename, vault_filename, size, sha256, md5, threat_type, file_format, description, analysis_notes,
            analysis_res["entropy"], analysis_res["entropy_level"], analysis_res["magic_type"],
            json.dumps(analysis_res["extracted_strings"]), analysis_res["hex_dump"], analysis_res["yara_rule"]
        ))

        conn.commit()
        conn.close()

        return RedirectResponse(url="/?message=Sample+successfully+quarantined+and+analyzed", status_code=303)
    except Exception as e:
        return templates.TemplateResponse(request=request, name="upload.html", context={"error": f"Error uploading sample: {str(e)}"})

@app.get("/sample/{sample_id}", response_class=HTMLResponse)
def sample_detail(request: Request, sample_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM samples WHERE id = ?", (sample_id,))
    sample_row = cursor.fetchone()
    conn.close()

    if not sample_row:
        raise HTTPException(status_code=404, detail="Sample not found")

    sample = dict(sample_row)
    # Parse JSON extracted strings
    try:
        sample["extracted_strings_list"] = json.loads(sample.get("extracted_strings") or "[]")
    except Exception:
        sample["extracted_strings_list"] = []

    return templates.TemplateResponse(request=request, name="detail.html", context={"sample": sample})

@app.get("/download/{sample_id}")
def download_sample(sample_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM samples WHERE id = ?", (sample_id,))
    sample = cursor.fetchone()
    conn.close()

    if not sample:
        raise HTTPException(status_code=404, detail="Sample not found")

    try:
        file_bytes = read_from_vault(sample["vault_filename"])
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Vault file binary missing on disk")

    headers = {
        "Content-Disposition": f'attachment; filename="{sample["original_filename"]}.bin"',
        "X-Content-Type-Options": "nosniff",
        "X-Download-Options": "noopen",
        "Content-Security-Policy": "default-src 'none'",
    }

    return Response(
        content=file_bytes,
        media_type="application/octet-stream",
        headers=headers
    )
