import time, threading, traceback
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from backend.db import run_sql
from backend.query_agent import answer_with_sql
from backend.analysis import analyze
from backend.timeline import build_timeline
from backend.guild_client import start_guild_run
from backend.investigate import investigate

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

_cache = {}  # normalized question -> (expires_at, response)
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

class AskRequest(BaseModel):
    question: str

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

def _cache_key(question: str) -> str:
    return " ".join(question.lower().split())

def _answer(question: str) -> dict:
    t0 = time.time()
    guild = _start_guild(question)
    result = answer_with_sql(question)
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

@app.post("/investigate")
def run_investigation():
    """Hunt for a compromised machine with no question. Cached like /ask; errors are not."""
    hit = _cache.get("/investigate")
    if hit and hit[0] > time.time():
        print("[investigate] cache hit", flush=True)
        return hit[1]
    t0 = time.time()
    try:
        response = investigate()
    except Exception as e:
        print(f"[investigate] ERROR after {time.time() - t0:.2f}s: {e!r}", flush=True)
        traceback.print_exc()
        return {"error": "The investigation could not finish. Try again in a moment."}
    print(f"[investigate] {len(response['suspects'])} suspect(s) | total {time.time() - t0:.2f}s", flush=True)
    _cache["/investigate"] = (time.time() + CACHE_SECONDS, response)
    return response

@app.post("/ask")
def ask(req: AskRequest):
    key = _cache_key(req.question)
    hit = _cache.get(key)
    if hit and hit[0] > time.time():
        print("[ask] cache hit | total 0.00s", flush=True)
        return hit[1]

    t0 = time.time()
    try:
        response = _answer(req.question)
    except Exception as e:
        print(f"[ask] ERROR after {time.time() - t0:.2f}s: {e!r}", flush=True)
        traceback.print_exc()
        return _simple(ERROR_ANSWER)

    if response["sql"]:  # off-topic replies have no SQL and are not cached
        _cache[key] = (time.time() + CACHE_SECONDS, response)
    return response
