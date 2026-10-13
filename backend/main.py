import os, json, time, hashlib, threading, traceback
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from typing import List, Optional
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from backend.db import run_sql, list_days, valid_day
from backend.query_agent import answer_with_sql
from backend.analysis import analyze
from backend.timeline import build_timeline
from backend.guild_client import start_guild_run
from backend.investigate import investigate, scan_days
from backend.scoring import score_investigation, attack_days

MAX_ROWS = 50
GUILD_WAIT_SECONDS = 5
CACHE_SECONDS = 3600
ERROR_ANSWER = "I couldn't answer that. Try rephrasing the question."
OFF_TOPIC_ANSWER = ("I can only answer questions about the login logs. "
                    "Try asking about accounts, computers, or failed logins.")

WARMUP_QUERIES = [
    "SELECT count() FROM auth_logs",
    "SELECT src_user, uniqExact(dst_comp) AS computers FROM auth_logs "
    "WHERE src_comp != dst_comp GROUP BY src_user ORDER BY computers DESC LIMIT 5",
]

# Protection for a public deployment. Every answer costs model credits, so each
# visitor gets an hourly allowance and the whole service a daily one. An optional
# APP_PASSCODE locks the API to people who have been given the code.
PASSCODE = os.getenv("APP_PASSCODE", "").strip()
PER_VISITOR_PER_HOUR = int(os.getenv("RATE_LIMIT_PER_HOUR", "40"))
ALL_VISITORS_PER_DAY = int(os.getenv("RATE_LIMIT_PER_DAY", "1500"))
COSTLY_PATHS = ("/ask", "/investigate", "/scan")

_cache = {}  # normalized question -> (expires_at, response)
_hits = defaultdict(deque)   # visitor -> times of recent costly requests
_today = {"day": "", "count": 0}
_limit_lock = threading.Lock()

def _over_limit(visitor: str) -> Optional[str]:
    """Record a costly request; return a message if the visitor or the service is over its allowance."""
    now = time.time()
    with _limit_lock:
        day = time.strftime("%Y-%m-%d")
        if _today["day"] != day:
            _today.update(day=day, count=0)
        if _today["count"] >= ALL_VISITORS_PER_DAY:
            return "This demo has reached its limit for today. Please come back tomorrow."
        recent = _hits[visitor]
        while recent and recent[0] < now - 3600:
            recent.popleft()
        if len(recent) >= PER_VISITOR_PER_HOUR:
            return "You have reached the hourly limit for this demo. Please try again later."
        recent.append(now)
        _today["count"] += 1
    return None
_guild_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="guild")

def _start_guild(question: str):
    try:
        return _guild_pool.submit(start_guild_run, question)
    except Exception as e:
        print(f"[guild] could not start: {e!r}", flush=True)
        return None

def _guild_url(future):
    if future is None:
        return None
    try:
        return future.result(timeout=GUILD_WAIT_SECONDS)
    except Exception as e:
        print(f"[guild] no session url: {type(e).__name__}", flush=True)
        return None

def _warm_up():
    for sql in WARMUP_QUERIES:
        try:
            print(f"[warmup] {run_sql(sql)['stats']['query_ms']} ms", flush=True)
        except Exception as e:
            print(f"[warmup] failed: {e!r}", flush=True)

@asynccontextmanager
async def lifespan(app):
    threading.Thread(target=_warm_up, daemon=True).start()
    yield

app = FastAPI(title="LogWhisperer", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def guard(request: Request, call_next):
    """Passcode and allowance checks for the endpoints that cost model credits."""
    if request.method == "POST" and request.url.path in COSTLY_PATHS:
        if PASSCODE and request.headers.get("x-passcode", "") != PASSCODE:
            return JSONResponse({"error": "passcode"}, status_code=401)
        forwarded = request.headers.get("x-forwarded-for", "")
        visitor = forwarded.split(",")[0].strip() or (request.client.host if request.client else "unknown")
        message = _over_limit(visitor)
        if message:
            return JSONResponse({"error": message}, status_code=429)
    return await call_next(request)

class Turn(BaseModel):
    question: str = ""
    sql: str = ""
    answer: str = ""

class AskRequest(BaseModel):
    question: str
    day: Optional[str] = None
    history: List[Turn] = []

class DayRequest(BaseModel):
    day: Optional[str] = None

_days = {"at": 0.0, "days": []}

def _known_days() -> list:
    """Days in the data, refreshed every few minutes."""
    if time.time() - _days["at"] > 300:
        try:
            _days.update(at=time.time(), days=list_days())
        except Exception as e:
            print(f"[days] could not list days: {e!r}", flush=True)
    return _days["days"]

def _day_or_none(day):
    """The requested day if the data has it, else None (meaning: all the data)."""
    return day if valid_day(day) and any(d["day"] == day for d in _known_days()) else None

def _simple(answer: str) -> dict:
    return {
        "answer": answer,
        "risk": "low",
        "next_steps": [],
        "sql": "",
        "rows": [],
        "timeline": [],
        "stats": {"rows_scanned": 0, "query_ms": 0},
        "guild_session_url": None,
    }

def _cache_key(question: str, day=None, history=None) -> str:
    """Same question, same day and same conversation so far -> same cached answer."""
    past = hashlib.sha1(json.dumps([t["sql"] for t in history or []]).encode()).hexdigest()[:10]
    return f"{day or 'all'}|{past}|" + " ".join(question.lower().split())

def _answer(question: str, day=None, history=None) -> dict:
    t0 = time.time()
    guild = _start_guild(question)
    result = answer_with_sql(question, day=day, days=[d["day"] for d in _known_days()], history=history)
    t1 = time.time()

    if result["sql"] is None:
        print(f"[ask] off-topic | query {t1 - t0:.2f}s | total {t1 - t0:.2f}s", flush=True)
        return _simple(OFF_TOPIC_ANSWER)

    rows = result["rows"][:MAX_ROWS]
    out = analyze(question, result["sql"], rows)
    t2 = time.time()
    print(f"[ask] query {t1 - t0:.2f}s | analyze {t2 - t1:.2f}s | total {t2 - t0:.2f}s", flush=True)

    return {
        "answer": out["answer"],
        "risk": out["risk"],
        "next_steps": out["next_steps"],
        "sql": result["sql"],
        "rows": rows,
        "timeline": build_timeline(rows),
        "stats": result["stats"],
        "guild_session_url": _guild_url(guild),
    }

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/days")
def days():
    """The days of data available, so the app can offer a day picker."""
    return {"days": _known_days()}

@app.post("/scan")
def run_scan():
    """Run the outlier test on every day at once. Cached; errors are not."""
    hit = _cache.get("/scan")
    if hit and hit[0] > time.time():
        return hit[1]
    t0 = time.time()
    try:
        found = scan_days()
        try:
            truth = attack_days()   # labels, read only after the scan has finished
        except Exception as e:
            print(f"[scan] labels unavailable: {e!r}", flush=True)
            truth = None
        days_out = []
        for d in _known_days():
            real = (truth or {}).get(d["day"])
            days_out.append({
                "day": d["day"], "logins": d["logins"],
                "suspects": found["suspects_by_day"].get(d["day"], []),
                "red_team": None if truth is None else {
                    "events": real["events"] if real else 0,
                    "computers": real["computers"] if real else []},
            })
        response = {"days": days_out, "sql": found["sql"], "stats": found["stats"]}
    except Exception as e:
        print(f"[scan] ERROR after {time.time() - t0:.2f}s: {e!r}", flush=True)
        traceback.print_exc()
        return {"error": "The scan could not finish. Try again in a moment."}
    print(f"[scan] {sum(bool(d['suspects']) for d in days_out)} day(s) flagged | total {time.time() - t0:.2f}s",
          flush=True)
    _cache["/scan"] = (time.time() + CACHE_SECONDS, response)
    return response

@app.post("/investigate")
def run_investigation(req: DayRequest = DayRequest()):
    """Hunt for a compromised machine with no question. Cached like /ask; errors are not."""
    day = _day_or_none(req.day)
    cache_key = f"/investigate|{day or 'all'}"
    hit = _cache.get(cache_key)
    if hit and hit[0] > time.time():
        print("[investigate] cache hit", flush=True)
        return hit[1]
    t0 = time.time()
    try:
        response = investigate(day)
    except Exception as e:
        print(f"[investigate] ERROR after {time.time() - t0:.2f}s: {e!r}", flush=True)
        traceback.print_exc()
        return {"error": "The investigation could not finish. Try again in a moment."}
    try:
        # Added after the investigation is complete; the labels never influence it.
        response["scorecard"] = score_investigation(response)
    except Exception as e:
        print(f"[investigate] scorecard skipped: {e!r}", flush=True)
        response["scorecard"] = None
    print(f"[investigate] {len(response['suspects'])} suspect(s) | total {time.time() - t0:.2f}s", flush=True)
    _cache[cache_key] = (time.time() + CACHE_SECONDS, response)
    return response

@app.post("/ask")
def ask(req: AskRequest):
    day = _day_or_none(req.day)
    history = [t.dict() for t in req.history[-3:]]
    key = _cache_key(req.question, day, history)
    hit = _cache.get(key)
    if hit and hit[0] > time.time():
        print("[ask] cache hit | total 0.00s", flush=True)
        return hit[1]

    t0 = time.time()
    try:
        response = _answer(req.question, day, history)
    except Exception as e:
        print(f"[ask] ERROR after {time.time() - t0:.2f}s: {e!r}", flush=True)
        traceback.print_exc()
        return _simple(ERROR_ANSWER)

    if response["sql"]:  # off-topic replies have no SQL and are not cached
        _cache[key] = (time.time() + CACHE_SECONDS, response)
    return response
