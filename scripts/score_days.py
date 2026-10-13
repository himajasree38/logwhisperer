"""Score the scan and the one-click investigation on every day of data.

    python scripts/score_days.py

The detection rule was designed while looking at one day (2026-10-08). Every other
day is a day it had not seen, so this is the honest test of whether it generalises.
Writes eval/days.json. Labels are read only after each result is in.
"""
from pathlib import Path
import json, os, sys, time

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from backend.db import list_days, TABLE
from backend.investigate import investigate, scan_days
from backend.scoring import score_investigation, attack_days

DESIGN_DAY = "2026-10-08"


def main():
    days = list_days()
    scan = scan_days()
    truth = attack_days()
    print(f"{TABLE}: {len(days)} days, {sum(d['logins'] for d in days):,} logins; "
          f"scan took {scan['stats']['seconds']} s ({scan['stats']['rows_scanned']:,} rows)\n")

    rows = []
    print(f"{'day':<12}{'logins':>12}  {'red team':<24}{'scan':<34}{'accounts':>10}{'logins found':>14}")
    for d in days:
        day = d["day"]
        real = truth.get(day, {"events": 0, "computers": []})
        suspects = scan["suspects_by_day"].get(day, [])
        row = {"day": day, "logins": d["logins"], "seen_during_design": day == DESIGN_DAY,
               "red_team_events": real["events"], "red_team_computers": real["computers"],
               "suspects": suspects, "investigation": None}
        if suspects:
            result = investigate(day)
            row["investigation"] = {"scores": score_investigation(result), "stats": result["stats"],
                                    "headline": result["headline"]}
        rows.append(row)

        truth_text = f"{real['events']} from {','.join(real['computers'])}" if real["events"] else "quiet"
        scan_text = (f"{suspects[0]['computer']} ({suspects[0]['targets']} machines, "
                     f"{suspects[0]['times_normal']}x)" if suspects else "nothing unusual")
        inv = row["investigation"]
        acc = f"{inv['scores']['accounts']['correct']}/{inv['scores']['accounts']['real']}" if inv else "-"
        ev = f"{inv['scores']['events']['correct']}/{inv['scores']['events']['real']}" if inv else "-"
        print(f"{day:<12}{d['logins']:>12,}  {truth_text:<24}{scan_text:<34}{acc:>10}{ev:>14}")

    active = [r for r in rows if r["red_team_events"]]
    quiet = [r for r in rows if not r["red_team_events"]]
    caught = [r for r in active if any(s["computer"] in r["red_team_computers"] for s in r["suspects"])]
    false_alarms = [r for r in rows if r["suspects"]
                    and not any(s["computer"] in r["red_team_computers"] for s in r["suspects"])]
    events_total = sum(r["red_team_events"] for r in rows)
    events_on_caught_days = sum(r["investigation"]["scores"]["events"]["correct"] for r in caught)
    summary = {
        "days": len(rows), "logins": sum(r["logins"] for r in rows),
        "days_with_red_team": len(active), "days_caught": len(caught),
        "quiet_days": len(quiet), "days_with_false_alarm": len(false_alarms),
        "red_team_logins": events_total, "red_team_logins_found": events_on_caught_days,
        "unseen_days_caught": len([r for r in caught if not r["seen_during_design"]]),
    }
    (ROOT / "eval").mkdir(exist_ok=True)
    (ROOT / "eval" / "days.json").write_text(json.dumps(
        {"date": time.strftime("%Y-%m-%d"), "table": TABLE, "model": os.getenv("AKASHML_MODEL"),
         "design_day": DESIGN_DAY, "summary": summary, "scan_stats": scan["stats"], "days": rows},
        indent=2, default=str))

    print(f"\nDays with red-team activity caught : {summary['days_caught']}/{summary['days_with_red_team']}")
    print(f"Quiet days                          : {summary['quiet_days']}, "
          f"days with a false alarm: {summary['days_with_false_alarm']}")
    print(f"Red-team logins found               : {events_on_caught_days}/{events_total}")
    print("Saved eval/days.json")


if __name__ == "__main__":
    main()
