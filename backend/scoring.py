"""Score investigations against LANL's red-team labels.

Runs only after an investigation has finished. This is the one place in the
backend that reads is_attack, and nothing here is ever sent to a model.
"""
from backend.db import _client, TABLE, valid_day
from backend.investigate import REMOTE_HUMAN, _in_list


def _score(flagged: int, real: int, correct: int) -> dict:
    return {"flagged": flagged, "real": real, "correct": correct,
            "precision": round(correct / flagged, 3) if flagged else None,
            "recall": round(correct / real, 3) if real else None}


def _set(sql: str) -> set:
    return {r[0] for r in _client().query(sql).result_rows}


def score_investigation(result: dict) -> dict:
    """Compare what one investigation flagged with what the red team really did in its scope."""
    day = result.get("day")
    scope = f"toDate(timestamp) = '{day}' AND " if valid_day(day) else ""
    real_computers = _set(f"SELECT DISTINCT src_comp FROM {TABLE} WHERE {scope}is_attack = 1")
    real_accounts = _set(f"SELECT DISTINCT src_user FROM {TABLE} WHERE {scope}is_attack = 1")
    real_events = _client().query(
        f"SELECT count() FROM {TABLE} WHERE {scope}is_attack = 1").result_rows[0][0]

    suspects = {s["computer"] for s in result["suspects"]}
    accounts = {a["account"] for a in result["accounts"]}

    # Events the investigation points at: successful logins from the suspect computers.
    flagged_events = correct_events = 0
    if suspects:
        flagged_events, correct_events = _client().query(
            f"SELECT count(), sum(is_attack) FROM {TABLE} WHERE {scope}src_comp IN ({_in_list(suspects)}) "
            f"AND {REMOTE_HUMAN} AND result = 'Success'").result_rows[0]

    return {
        "computers": _score(len(suspects), len(real_computers), len(suspects & real_computers)),
        "accounts": _score(len(accounts), len(real_accounts), len(accounts & real_accounts)),
        "events": _score(int(flagged_events), int(real_events), int(correct_events)),
    }


def attack_days() -> dict:
    """day -> {"events": n, "computers": [...]} for every day with red-team activity."""
    rows = _client().query(
        f"SELECT toDate(timestamp) AS day, count() AS events, groupUniqArray(src_comp) AS computers "
        f"FROM {TABLE} WHERE is_attack = 1 GROUP BY day ORDER BY day").result_rows
    return {str(day)[:10]: {"events": int(events), "computers": sorted(computers)}
            for day, events, computers in rows}
