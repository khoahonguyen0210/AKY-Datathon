"""HTTP API for SENTINEL.

Uploads are parsed in memory with a size cap. They are not written to disk
and they are not passed to a shell.
"""

import os
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.grok_bot import investigate
from app.models import CaseInfo, Investigation, SampleSummary
from app.parser import MAX_EVENTS, ParseError, parse_logs
from app.samples import list_samples, load_sample, sample_log_path

MAX_UPLOAD_BYTES = 2_000_000

app = FastAPI(title="SENTINEL", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.get("/api/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "grok_configured": bool(os.environ.get("XAI_API_KEY", "").strip()),
    }


@app.get("/api/samples", response_model=list[SampleSummary])
def samples() -> list[SampleSummary]:
    return list_samples()


@app.get("/api/samples/{sample_id}/investigation", response_model=Investigation)
def sample_investigation(sample_id: str) -> Investigation:
    try:
        case, events = load_sample(sample_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Unknown sample.") from exc
    return investigate(events, case)


@app.get("/api/samples/{sample_id}/logs")
def sample_logs(sample_id: str) -> FileResponse:
    try:
        path = sample_log_path(sample_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Unknown sample.") from exc
    return FileResponse(path, media_type="text/plain", filename=f"{sample_id}.jsonl")


@app.post("/api/investigate", response_model=Investigation)
async def investigate_upload(file: UploadFile = File(...)) -> Investigation:
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds 2 MB.")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="The file must be UTF-8 text.") from exc
    try:
        events = parse_logs(text)
    except ParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if len(events) > MAX_EVENTS:
        raise HTTPException(status_code=400, detail=f"Too many events. The limit is {MAX_EVENTS}.")
    case = CaseInfo(
        id="upload",
        title=Path(file.filename or "uploaded logs").name[:80] or "uploaded logs",
        subtitle="Uploaded log file",
        note="Findings below are limited to events in this file.",
        origin="upload",
    )
    return investigate(events, case)


def mount_static(application: FastAPI) -> None:
    static_dir = os.environ.get("SENTINEL_STATIC", "")
    if not static_dir:
        return
    path = Path(static_dir)
    if path.is_dir():
        application.mount("/", StaticFiles(directory=path, html=True), name="static")


mount_static(app)
