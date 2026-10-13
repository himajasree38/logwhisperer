"""Score the one-click investigation against LANL's red-team labels.

    python scripts/score_investigation.py

The investigation itself never reads the labels. This script runs it, then
compares what it flagged with what the red team really did, and writes
eval/investigation.json.
"""
from pathlib import Path
import json, os, sys, time

import clickhouse_connect
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from backend.investigate import investigate, REMOTE_HUMAN, _in_list


def _score(flagged: set, truth: set) -> dict:
    hits = flagged & truth
    return {"flagged": len(flagged), "real": len(truth), "correct": len(hits),
            "precision": round(len(hits) / len(flagged), 3) if flagged else None,
            "recall": round(len(hits) / len(truth), 3) if truth else None}


def main():
    result = investigate()

    client = clickhouse_connect.get_client(
        host=os.getenv("CLICKHOUSE_HOST"), username=os.getenv("CLICKHOUSE_RO_USER"),
        password=os.getenv("CLICKHOUSE_RO_PASSWORD"), secure=True)

    def column(sql):
        return {r[0] for r in client.query(sql).result_rows}

    total_rows = client.query("SELECT count() FROM auth_logs").result_rows[0][0]
    real_computers = column("SELECT DISTINCT src_comp FROM auth_logs WHERE is_attack = 1")
    real_accounts = column("SELECT DISTINCT src_user FROM auth_logs WHERE is_attack = 1")
    real_events = client.query("SELECT count() FROM auth_logs WHERE is_attack = 1").result_rows[0][0]

    suspects = {s["computer"] for s in result["suspects"]}
    accounts = {a["account"] for a in result["accounts"]}

    # Events the investigation points at: successful logins from the suspect computers.
    flagged_events = correct_events = 0
    if suspects:
        flagged_events, correct_events = client.query(
            f"SELECT count(), sum(is_attack) FROM auth_logs WHERE src_comp IN ({_in_list(suspects)}) "
            f"AND {REMOTE_HUMAN} AND result = 'Success'").result_rows[0]

    scores = {
        "computers": _score(suspects, real_computers),
        "accounts": _score(accounts, real_accounts),
        "events": {"flagged": flagged_events, "real": real_events, "correct": int(correct_events),
                   "precision": round(correct_events / flagged_events, 3) if flagged_events else None,
                   "recall": round(correct_events / real_events, 3) if real_events else None},
    }
    out = {"date": time.strftime("%Y-%m-%d"), "logins_in_dataset": total_rows,
           "model": os.getenv("AKASHML_MODEL"), "scores": scores, "stats": result["stats"],
           "report_written_by_model": result["report_written_by_model"],
           "headline": result["headline"], "summary": result["summary"]}
    (ROOT / "eval").mkdir(exist_ok=True)
    (ROOT / "eval" / "investigation.json").write_text(json.dumps(out, indent=2, default=str))

    print(result["headline"], "\n")
    print(f"{'':<11}{'flagged':>9}{'real':>7}{'correct':>9}{'precision':>11}{'recall':>8}")
    for name, s in scores.items():
        print(f"{name:<11}{s['flagged']:>9}{s['real']:>7}{s['correct']:>9}"
              f"{(s['precision'] if s['precision'] is not None else '-'):>11}"
              f"{(s['recall'] if s['recall'] is not None else '-'):>8}")
    st = result["stats"]
    print(f"\n{st['queries']} queries over {total_rows:,} logins, {st['rows_scanned']:,} rows scanned, "
          f"{st['query_ms']} ms in ClickHouse, {st['seconds']} s end to end")
    print("Saved eval/investigation.json")


if __name__ == "__main__":
    main()
