"""Score the one-click investigation against LANL's red-team labels.

    python scripts/score_investigation.py

The investigation itself never reads the labels. This script runs it, then
compares what it flagged with what the red team really did, and writes
eval/investigation.json.
"""
from pathlib import Path
import json, os, sys, time

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from backend.investigate import investigate
from backend.scoring import score_investigation
from backend.db import _client


def main():
    result = investigate()
    scores = score_investigation(result)
    total_rows = _client().query("SELECT count() FROM auth_logs").result_rows[0][0]

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
