"""Display-only ground-truth labels for the timeline.

Runs after the agents have answered; nothing here is ever sent to a model.
"""
import os, time, datetime, threading
import clickhouse_connect
from dotenv import load_dotenv
from backend.db import TABLE

load_dotenv()

MATCH_COLS = ("src_user", "src_comp", "dst_comp")
RETRY_SECONDS = 60

_attacks = None        # list of {timestamp, src_user, src_comp, dst_comp}
_by_time = {}          # ISO timestamp (to the second) -> attack rows
_failed_at = 0.0
_lock = threading.Lock()

def _iso_second(value) -> str:
    if isinstance(value, datetime.datetime):
        return value.isoformat(timespec="seconds")
    return str(value).replace(" ", "T")[:19]

def _load():
    client = clickhouse_connect.get_client(
        host=os.getenv("CLICKHOUSE_HOST"),
        username=os.getenv("CLICKHOUSE_RO_USER"),
        password=os.getenv("CLICKHOUSE_RO_PASSWORD"),
        secure=True,
        connect_timeout=5,
    )
    result = client.query(
        f"SELECT timestamp, src_user, src_comp, dst_comp FROM {TABLE} WHERE is_attack = 1")
    return [dict(zip(result.column_names, r)) for r in result.result_rows]

def attack_rows() -> list:
    """Load attack rows once; on failure return [] and retry after RETRY_SECONDS."""
    global _attacks, _by_time, _failed_at
    if _attacks is not None:
        return _attacks
    with _lock:
        if _attacks is not None or time.time() - _failed_at < RETRY_SECONDS:
            return _attacks or []
        try:
            rows = _load()
        except Exception as e:
            _failed_at = time.time()
            print(f"[labels] could not load attack rows: {e!r}", flush=True)
            return []
        by_time = {}
        for r in rows:
            by_time.setdefault(_iso_second(r["timestamp"]), []).append(r)
        _by_time, _attacks = by_time, rows
        print(f"[labels] loaded {len(rows)} attack rows", flush=True)
        return _attacks

def _matches(row: dict, attack: dict) -> bool:
    present = [c for c in MATCH_COLS if row.get(c) is not None]
    return bool(present) and all(str(row[c]) == str(attack[c]) for c in present)

def mark_attacks(timeline_rows: list) -> list:
    """Set is_attack = 1 on events whose source row matches an attack row.

    Each event needs a "_row" dict with timestamp and any of src_user, src_comp, dst_comp.
    """
    try:
        attack_rows()
        for event in timeline_rows:
            row = event.get("_row") or {}
            candidates = _by_time.get(_iso_second(row.get("timestamp")), [])
            if any(_matches(row, a) for a in candidates):
                event["is_attack"] = 1
    except Exception as e:
        print(f"[labels] marking skipped: {e!r}", flush=True)
    return timeline_rows
