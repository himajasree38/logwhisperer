"""Scorecard: how reliable, consistent, fast and accurate is the question pipeline?

Runs a fixed set of questions through the same code /ask uses (no cache, no Guild
run) and scores the results against LANL's red-team labels.

    python scripts/scorecard.py --label baseline
    python scripts/scorecard.py --label after-fix --repeat 2

Writes eval/<label>.json and prints a summary. The labels are read only here,
after the agents have answered; nothing from them is sent to a model.
"""
from pathlib import Path
import argparse, json, os, re, statistics, sys, time
from concurrent.futures import ThreadPoolExecutor

import clickhouse_connect
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from backend.query_agent import answer_with_sql
from backend.analysis import analyze

MAX_ROWS = 50   # same cap as /ask

# (kind, question). "hunt" questions start with no names; "pivot" questions follow
# a named account or computer; "off_topic" questions must be refused.
QUESTIONS = [
    ("hunt", "Which accounts logged into the most different computers yesterday?"),
    ("hunt", "Which source computer used the most different user accounts to log into other computers?"),
    ("hunt", "Which accounts logged into more than 50 different computers yesterday?"),
    ("hunt", "Summarize yesterday's biggest security risks."),
    ("hunt", "Is there any sign of an attacker moving through the network?"),
    ("hunt", "Which accounts had the most failed logins yesterday?"),
    ("hunt", "Which accounts had failed logins on more than five different computers?"),
    ("hunt", "Which computers received the most failed logins yesterday?"),
    ("hunt", "Were there any logins at unusual hours, between midnight and 5 AM?"),
    ("hunt", "Which accounts used NTLM to reach the most computers yesterday?"),
    ("hunt", "Which accounts used remote interactive logins the most yesterday?"),
    ("hunt", "Which accounts logged in from the most different source computers yesterday?"),
    ("hunt", "Which accounts had many failed logins and then a successful login?"),
    ("hunt", "What hour of the day had the most failed logins?"),
    ("pivot", "What did computer C17693 do yesterday, in time order?"),
    ("pivot", "Which accounts logged in from computer C17693 yesterday?"),
    ("pivot", "Which accounts did C17693 use that had successful logins, and which computers did they reach?"),
    ("pivot", "Which computers did C17693 fail to log into?"),
    ("pivot", "How many different computers did C17693 connect to yesterday?"),
    ("pivot", "What did account U66@DOM1 do yesterday, in time order?"),
    ("pivot", "What did account U293@DOM1 do yesterday, in time order?"),
    ("pivot", "Which computers did U66@DOM1 reach, in order?"),
    ("pivot", "Which computers did account U22@DOM1 try to log into?"),
    ("pivot", "What happened between 9 AM and 10 AM on computer C17693?"),
    ("off_topic", "What is the capital of France?"),
    ("off_topic", "Write me a poem about autumn."),
    ("off_topic", "asdf qwerty banana"),
]

ACCOUNT_RE = re.compile(r"^[^@\s]+@\S+$")   # e.g. U66@DOM1, C586$@DOM1, U1718@?
COMPUTER_RE = re.compile(r"^C\d+$")         # e.g. C17693
FALLBACK_MARKERS = ("could not summarize", "Automatic analysis failed")


def ground_truth():
    """Red-team accounts and source computers. Read-only login; labels stay in this script."""
    client = clickhouse_connect.get_client(
        host=os.getenv("CLICKHOUSE_HOST"),
        username=os.getenv("CLICKHOUSE_RO_USER"),
        password=os.getenv("CLICKHOUSE_RO_PASSWORD"),
        secure=True,
    )
    accounts = {r[0] for r in client.query(
        "SELECT DISTINCT src_user FROM auth_logs WHERE is_attack = 1").result_rows}
    computers = {r[0] for r in client.query(
        "SELECT DISTINCT src_comp FROM auth_logs WHERE is_attack = 1").result_rows}
    return accounts, computers


def _values(value):
    if isinstance(value, (list, tuple)):
        for v in value:
            yield from _values(v)
    elif isinstance(value, str):
        yield value


def entities(rows):
    accounts, computers = set(), set()
    for row in rows:
        for value in row.values():
            for v in _values(value):
                if ACCOUNT_RE.match(v):
                    accounts.add(v)
                elif COMPUTER_RE.match(v):
                    computers.add(v)
    return accounts, computers


def run_once(kind, question, bad_accounts, bad_computers):
    """One pass through the pipeline. Never raises; failures are part of the score."""
    record = {"kind": kind, "question": question, "status": "ok", "risk": None,
              "seconds": None, "query_ms": None, "rows_scanned": None, "rows": 0,
              "attacker_accounts": [], "attacker_computers": [], "answer": "", "sql": None}
    start = time.time()
    try:
        result = answer_with_sql(question)
        if result["sql"] is None:
            record["status"] = "refused"
        else:
            rows = result["rows"][:MAX_ROWS]
            out = analyze(question, result["sql"], rows)
            accounts, computers = entities(rows)
            fallback = any(m in out["answer"] or m in " ".join(out["findings"])
                           for m in FALLBACK_MARKERS)
            record.update(
                status="no_explanation" if fallback else "ok",
                risk=out["risk"], answer=out["answer"], sql=result["sql"], rows=len(rows),
                query_ms=result["stats"]["query_ms"],
                rows_scanned=result["stats"]["rows_scanned"],
                attacker_accounts=sorted(accounts & bad_accounts),
                attacker_computers=sorted(computers & bad_computers),
            )
    except Exception as e:
        record["status"] = "error"
        record["answer"] = repr(e)[:200]
    record["seconds"] = round(time.time() - start, 1)
    return record


def summarize(runs, bad_accounts, repeat):
    """Headline numbers. `runs` is a list of passes, each a list of records in question order."""
    flat = [r for one_pass in runs for r in one_pass]
    on_topic = [r for r in flat if r["kind"] != "off_topic"]
    off_topic = [r for r in flat if r["kind"] == "off_topic"]
    answered = [r for r in on_topic if r["status"] == "ok"]
    seconds = sorted(r["seconds"] for r in answered)

    found = set()
    for r in on_topic:
        found.update(r["attacker_accounts"])
    hunt_found = set()
    for r in on_topic:
        if r["kind"] == "hunt":
            hunt_found.update(r["attacker_accounts"])

    consistent = None
    if repeat > 1:
        per_question = list(zip(*runs))
        rated = [q for q in per_question if q[0]["kind"] != "off_topic"
                 and all(r["risk"] for r in q)]
        same = [q for q in rated if len({r["risk"] for r in q}) == 1]
        consistent = {"same_risk_every_run": len(same), "questions_rated_every_run": len(rated)}

    return {
        "on_topic_runs": len(on_topic),
        "answered_with_explanation": len(answered),
        "no_explanation": sum(r["status"] == "no_explanation" for r in on_topic),
        "errors": sum(r["status"] == "error" for r in on_topic),
        "wrongly_refused": sum(r["status"] == "refused" for r in on_topic),
        "off_topic_runs": len(off_topic),
        "off_topic_refused": sum(r["status"] == "refused" for r in off_topic),
        "median_seconds": statistics.median(seconds) if seconds else None,
        "p90_seconds": seconds[int(0.9 * (len(seconds) - 1))] if seconds else None,
        "attacker_accounts_total": len(bad_accounts),
        "attacker_accounts_surfaced": len(found),
        "attacker_accounts_surfaced_by_hunt_questions": len(hunt_found),
        "risk_consistency": consistent,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--label", default="run", help="name for the results file")
    parser.add_argument("--repeat", type=int, default=1, help="passes over the question set")
    parser.add_argument("--workers", type=int, default=3, help="questions run at once")
    args = parser.parse_args()

    bad_accounts, bad_computers = ground_truth()
    print(f"Ground truth: {len(bad_accounts)} attacker accounts, "
          f"{len(bad_computers)} attacker source computer(s)")
    print(f"{len(QUESTIONS)} questions x {args.repeat} pass(es), model {os.getenv('AKASHML_MODEL')}\n")

    runs = []
    for n in range(args.repeat):
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            one_pass = list(pool.map(
                lambda item: run_once(item[0], item[1], bad_accounts, bad_computers), QUESTIONS))
        runs.append(one_pass)
        for r in one_pass:
            print(f"  [{n + 1}] {r['status']:<15}{(r['risk'] or '-'):<8}{r['seconds']:>5}s  "
                  f"attackers={len(r['attacker_accounts']):<3} {r['question'][:70]}")
        print()

    summary = summarize(runs, bad_accounts, args.repeat)
    out_dir = ROOT / "eval"
    out_dir.mkdir(exist_ok=True)
    out_file = out_dir / f"{args.label}.json"
    out_file.write_text(json.dumps(
        {"label": args.label, "model": os.getenv("AKASHML_MODEL"),
         "date": time.strftime("%Y-%m-%d"), "summary": summary, "runs": runs}, indent=2))

    s = summary
    print("=" * 72)
    print(f"Answered with an explanation : {s['answered_with_explanation']}/{s['on_topic_runs']}")
    print(f"  no explanation             : {s['no_explanation']}")
    print(f"  errors                     : {s['errors']}")
    print(f"  wrongly refused            : {s['wrongly_refused']}")
    print(f"Off-topic correctly refused  : {s['off_topic_refused']}/{s['off_topic_runs']}")
    print(f"Answer time                  : median {s['median_seconds']}s, p90 {s['p90_seconds']}s")
    print(f"Attacker accounts surfaced   : {s['attacker_accounts_surfaced']}/{s['attacker_accounts_total']} "
          f"({s['attacker_accounts_surfaced_by_hunt_questions']} from hunt questions alone)")
    if s["risk_consistency"]:
        c = s["risk_consistency"]
        print(f"Same risk on every pass      : {c['same_risk_every_run']}/{c['questions_rated_every_run']}")
    print(f"\nSaved {out_file.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
