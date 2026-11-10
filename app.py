"""
Website for the Bahrain Scam Link Checker.

Run locally:
    python -m uvicorn app:app --reload
Then open http://127.0.0.1:8000

API:
    POST /api/check   {"text": "<a link or a whole SMS>"}  ->  verdicts for up to 3 links
    POST /api/page-scan  {"link": "..."}  ->  start a sandboxed page scan (Layer 5)
    GET  /api/page-scan/{scan_id}         ->  "pending" until ready, then the updated verdict
    GET  /api/health
    GET  /docs        interactive API documentation (made automatically by FastAPI)
"""

import time
from collections import defaultdict, deque
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import service

HERE = Path(__file__).parent
STATIC = HERE / "static"

RATE_LIMIT = 10           # checks per IP address ...
RATE_WINDOW = 60          # ... per minute - protects the free API quotas
SCAN_LIMIT = 3            # page scans per IP per minute (they use urlscan.io quota)

app = FastAPI(title="Bahrain Scam Link Checker",
              description="Checks links from SMS/WhatsApp messages. The link is never opened.")
app.mount("/static", StaticFiles(directory=STATIC), name="static")

_hits: dict[str, deque] = defaultdict(deque)
_scan_hits: dict[str, deque] = defaultdict(deque)


class CheckRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=service.MAX_TEXT,
                      description="A link, or the whole message that contained it")


def _client_ip(request: Request) -> str:
    # Behind a hosting proxy the real address is in X-Forwarded-For
    fwd = request.headers.get("x-forwarded-for")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "?")


def _rate_limited(ip: str, store=None, limit=RATE_LIMIT) -> bool:
    store = _hits if store is None else store
    now, q = time.time(), store[ip]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= limit:
        return True
    q.append(now)
    return False


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(STATIC / "index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "page_scan": service.page_scan_available()}


@app.post("/api/check")
async def check(body: CheckRequest, request: Request):
    if _rate_limited(_client_ip(request)):
        raise HTTPException(status_code=429, detail="rate_limited")
    result = await run_in_threadpool(service.check_text, body.text)
    if not result["found"]:
        raise HTTPException(status_code=422, detail="no_link")
    return result


class PageScanRequest(BaseModel):
    link: str = Field(..., min_length=3, max_length=service.MAX_TEXT)


@app.post("/api/page-scan")
async def page_scan_start(body: PageScanRequest, request: Request):
    """Layer 5: open the page in urlscan.io's sandbox. Poll /api/page-scan/{scan_id} for the result."""
    if _rate_limited(_client_ip(request), _scan_hits, SCAN_LIMIT):
        raise HTTPException(status_code=429, detail="rate_limited")
    return await run_in_threadpool(service.start_page_scan, body.link)


@app.get("/api/page-scan/{scan_id}")
async def page_scan_poll(scan_id: str):
    if not service.page_scan.UUID_RE.match(scan_id):
        raise HTTPException(status_code=404, detail="unknown")
    return await run_in_threadpool(service.poll_page_scan, scan_id)


@app.get("/api/page-scan/{scan_id}/screenshot", include_in_schema=False)
async def page_scan_screenshot(scan_id: str):
    if not service.page_scan.UUID_RE.match(scan_id):
        raise HTTPException(status_code=404)
    img = await run_in_threadpool(service.page_screenshot, scan_id)
    if not img:
        raise HTTPException(status_code=404)
    return Response(content=img, media_type="image/png", headers={"Cache-Control": "private, max-age=3600"})
