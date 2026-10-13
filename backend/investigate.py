"""One-click investigation: hunt for a compromised machine with no question and no hints.

A fixed playbook of read-only queries, each a step an analyst would take by hand:

  1. Learn what is normal: how many machines does a shared computer usually reach?
  2. Find sources far outside that norm, using many accounts to reach many machines.
  3. Profile each suspect: accounts used, successes, failures, when it was active.
  4. List the accounts that logged in successfully from it (likely stolen credentials).
  5. Check whether those accounts normally work from other machines.
  6. Map where the suspect got in.

The model writes the report from these findings; it does not decide them, so the
result is the same on every run. The red-team labels are never read here.
"""
import json, time
from backend.db import run_sql, valid_day
from backend.llm import ask_json

# A "shared" source is one used by several people's accounts to reach other machines.
MIN_ACCOUNTS = 5
# A suspect reaches this many times more machines than the 99th percentile of shared sources.
OUTLIER_FACTOR = 3
MAX_SUSPECTS = 3
MAX_EDGES = 400

# Remote logins by people's accounts: the traffic lateral movement shows up in.
_REMOTE_HUMAN = "src_comp != dst_comp AND src_user LIKE 'U%'"
REMOTE_HUMAN = _REMOTE_HUMAN   # unscoped form, used by the scorer

REPORT_SYSTEM = """You are a security analyst writing an incident summary for a small team with no security specialist.
You get the findings of an automated investigation of one day of Windows login logs. Use only those findings.

Return ONLY JSON:
- "headline": one sentence, under 25 words, stating what was found.
- "summary": 3 or 4 short plain-English sentences: what happened, how we know, how far it spread. No jargon.
  Keep attempted and successful logins apart: "accounts" and "targets" on a suspect count every attempt,
  while "accounts_that_got_in" and "machines_reached" count only successes.
  "accounts_whose_usual_computer_is_elsewhere" means those accounts normally work from other machines,
  which suggests their passwords were stolen; it does not mean the attack moved to other machines.
  Write dates in words, for example "8 October".
  "top_accounts" are accounts that got in. Name them only when talking about accounts that got in.
  Give the counts as they are. Do not write "most", "nearly all" or "few" unless the numbers support it.
  "times_normal" compares the suspect with other shared computers on the network, not with its own past.
- "actions": up to 4 concrete actions in priority order, naming the specific computer and how many accounts.

{"headline": "...", "summary": "...", "actions": ["..."]}"""


def _in_list(values) -> str:
    """Quote values for a SQL IN (...) list. Values come from our own query results."""
    return ", ".join("'" + str(v).replace("\\", "\\\\").replace("'", "\\'") + "'" for v in values)


class _Steps:
    """Runs queries and keeps a record of each one for the report."""

    def __init__(self):
        self.steps, self.rows_scanned, self.query_ms = [], 0, 0

    def run(self, title: str, sql: str) -> list:
        out = run_sql(" ".join(sql.split()))
        self.rows_scanned += out["stats"]["rows_scanned"]
        self.query_ms += out["stats"]["query_ms"]
        self.steps.append({"title": title, "finding": "", "sql": out["sql"], "stats": out["stats"]})
        return out["rows"]

    def note(self, finding: str):
        self.steps[-1]["finding"] = finding


def _template_report(suspects: list, accounts: list, targets: int) -> dict:
    """A plain report for when the model is unavailable, so an investigation never fails."""
    if not suspects:
        return {"headline": "No computer stood out as a source of lateral movement.",
                "summary": "No shared computer reached far more machines than normal for this network.",
                "actions": []}
    s = suspects[0]
    return {
        "headline": f"Computer {s['computer']} used {s['accounts']} accounts to reach {s['targets']} machines.",
        "summary": (f"{s['computer']} logged into {s['targets']} other computers using {s['accounts']} different "
                    f"accounts, about {s['times_normal']} times more machines than is normal for a shared computer. "
                    f"{len(accounts)} accounts logged in successfully from it, reaching {targets} machines."),
        "actions": [f"Isolate computer {s['computer']} from the network",
                    f"Reset the passwords of the {len(accounts)} accounts that logged in from it",
                    f"Check the {targets} machines it reached for signs of compromise"],
    }


def investigate(day: str = None) -> dict:
    """Investigate one day (YYYY-MM-DD), or everything loaded when no day is given."""
    started = time.time()
    steps = _Steps()
    if day is not None and not valid_day(day):
        raise ValueError("day must look like 2026-10-08")
    # Every query below is limited to the day being investigated.
    remote = f"toDate(timestamp) = '{day}' AND {_REMOTE_HUMAN}" if day else _REMOTE_HUMAN
    in_scope = f"toDate(timestamp) = '{day}' AND " if day else ""

    # 1. What is normal for a shared computer?
    rows = steps.run("Learn what is normal", f"""
        SELECT count() AS shared_sources, quantile(0.5)(targets) AS typical, quantile(0.99)(targets) AS p99
        FROM (SELECT src_comp, uniqExact(src_user) AS accounts, uniqExact(dst_comp) AS targets
              FROM auth_logs WHERE {remote} GROUP BY src_comp HAVING accounts >= {MIN_ACCOUNTS})
        LIMIT 1""")
    norm = rows[0] if rows else {"shared_sources": 0, "typical": 0, "p99": 0}
    typical, p99 = float(norm["typical"] or 0), float(norm["p99"] or 0)
    threshold = max(1.0, p99 * OUTLIER_FACTOR)
    steps.note(f"{norm['shared_sources']} computers are used by {MIN_ACCOUNTS} or more accounts to reach other "
               f"machines. A typical one reaches {typical:.0f}; 99% reach {p99:.0f} or fewer.")

    # 2. Which sources are far outside that?
    rows = steps.run("Find computers far outside normal", f"""
        SELECT src_comp AS computer, uniqExact(src_user) AS accounts, uniqExact(dst_comp) AS targets,
               count() AS logins, countIf(result = 'Fail') AS failed,
               min(timestamp) AS first_seen, max(timestamp) AS last_seen
        FROM auth_logs WHERE {remote}
        GROUP BY src_comp HAVING accounts >= {MIN_ACCOUNTS} AND targets > {threshold:.0f}
        ORDER BY targets DESC LIMIT {MAX_SUSPECTS}""")
    suspects = [dict(r, times_normal=round(r["targets"] / p99, 1) if p99 else None) for r in rows]
    if suspects:
        steps.note("; ".join(f"{s['computer']} used {s['accounts']} accounts to reach {s['targets']} machines "
                             f"({s['times_normal']}x the 99th percentile)" for s in suspects))
    else:
        steps.note(f"No shared computer reached more than {threshold:.0f} machines.")

    accounts, edges, activity, homes, targets_reached, elsewhere = [], [], [], [], 0, 0
    if suspects:
        names = _in_list(s["computer"] for s in suspects)

        # 3. How did each suspect log in, and did it work?
        rows = steps.run("Profile the suspect", f"""
            SELECT src_comp AS computer, auth_type, logon_type, result, count() AS logins,
                   uniqExact(src_user) AS accounts, uniqExact(dst_comp) AS targets
            FROM auth_logs WHERE src_comp IN ({names}) AND {remote}
            GROUP BY computer, auth_type, logon_type, result ORDER BY logins DESC LIMIT 20""")
        steps.note("; ".join(f"{r['logins']} {r['result'].lower()} {r['auth_type']} {r['logon_type']} logins "
                             f"with {r['accounts']} accounts to {r['targets']} machines" for r in rows[:4]))
        profile = rows

        # 4. Accounts that got in: the likely stolen credentials.
        accounts = steps.run("List accounts that got in", f"""
            SELECT src_user AS account, uniqExact(dst_comp) AS targets, count() AS logins,
                   min(timestamp) AS first_seen, max(timestamp) AS last_seen
            FROM auth_logs WHERE src_comp IN ({names}) AND {remote} AND result = 'Success'
            GROUP BY src_user ORDER BY targets DESC, logins DESC LIMIT 200""")
        steps.note(f"{len(accounts)} accounts logged in successfully from the suspect.")

        if accounts:
            # 5. Where do these accounts normally work? The computer each one logs in from
            #    most, other than the suspect, is taken as its usual machine.
            homes = steps.run("Find where those accounts normally work", f"""
                SELECT account, home, logins FROM (
                    SELECT src_user AS account, src_comp AS home, count() AS logins FROM auth_logs
                    WHERE {in_scope}src_user IN ({_in_list(a['account'] for a in accounts)})
                      AND src_comp NOT IN ({names})
                    GROUP BY account, home ORDER BY logins DESC LIMIT 1 BY account)
                ORDER BY logins DESC LIMIT 500""")
            usual = {h["account"]: h["home"] for h in homes}
            for account in accounts:
                account["usual_computer"] = usual.get(account["account"])
            elsewhere = len(usual)
            steps.note(f"{elsewhere} of the {len(accounts)} accounts normally log in from another computer "
                       f"({len(set(usual.values()))} different ones), so the suspect is not their usual machine.")

        # 6. Where did it get in, and when?
        edges = steps.run("Map the machines it reached", f"""
            SELECT src_comp AS source, dst_comp AS target, uniqExact(src_user) AS accounts,
                   count() AS logins, min(timestamp) AS first_seen
            FROM auth_logs WHERE src_comp IN ({names}) AND {remote} AND result = 'Success'
            GROUP BY source, target ORDER BY first_seen LIMIT {MAX_EDGES}""")
        targets_reached = len({e["target"] for e in edges})
        steps.note(f"It logged into {targets_reached} machines successfully.")

        activity = steps.run("Chart its activity through the day", f"""
            SELECT toStartOfInterval(timestamp, INTERVAL 30 MINUTE) AS slot,
                   countIf(result = 'Success') AS succeeded, countIf(result = 'Fail') AS failed
            FROM auth_logs WHERE src_comp IN ({names}) AND {remote}
            GROUP BY slot ORDER BY slot LIMIT 100""")
        busiest = max(activity, key=lambda r: r["succeeded"] + r["failed"]) if activity else None
        if busiest:
            steps.note(f"Busiest half hour started {str(busiest['slot'])[11:16]}, with "
                       f"{busiest['succeeded'] + busiest['failed']} logins.")
    else:
        profile = []

    findings = {
        "normal": {"shared_sources": norm["shared_sources"], "typical_targets": typical, "p99_targets": p99},
        "suspects": suspects,
        "login_profile": profile[:6],
        "accounts_that_got_in": len(accounts),
        # These accounts' owners normally work from other machines, so their use from
        # the suspect points to stolen credentials. It does not mean the attack spread.
        "accounts_whose_usual_computer_is_elsewhere": elsewhere,
        "top_accounts": accounts[:8],
        "machines_reached": targets_reached,
    }
    report = None
    if suspects:
        report = ask_json([{"role": "system", "content": REPORT_SYSTEM},
                           {"role": "user", "content": json.dumps(findings, default=str)}],
                          tag="investigate", required=("headline", "summary", "actions"))
    written_by_model = report is not None
    report = report or _template_report(suspects, accounts, targets_reached)

    return {
        "day": day,
        "risk": "high" if suspects else "low",
        "headline": str(report["headline"]),
        "summary": str(report["summary"]),
        "actions": [str(a) for a in report.get("actions", [])][:4],
        "report_written_by_model": written_by_model,
        "suspects": suspects,
        "accounts": accounts,
        "homes": homes,
        "edges": edges,
        "activity": activity,
        "steps": steps.steps,
        "stats": {"queries": len(steps.steps), "rows_scanned": steps.rows_scanned,
                  "query_ms": steps.query_ms, "seconds": round(time.time() - started, 1)},
    }


def scan_days() -> dict:
    """Apply the same outlier test to every day at once: which days have a suspect?"""
    started = time.time()
    out = run_sql(" ".join(f"""
        SELECT day, src_comp AS computer, accounts, targets, p99
        FROM (SELECT day, src_comp, accounts, targets, quantileExact(0.99)(targets) OVER (PARTITION BY day) AS p99
              FROM (SELECT toDate(timestamp) AS day, src_comp, uniqExact(src_user) AS accounts,
                           uniqExact(dst_comp) AS targets
                    FROM auth_logs WHERE {_REMOTE_HUMAN}
                    GROUP BY day, src_comp HAVING accounts >= {MIN_ACCOUNTS}))
        WHERE targets > greatest(1, p99 * {OUTLIER_FACTOR})
        ORDER BY day, targets DESC LIMIT 500""".split()))
    by_day = {}
    for r in out["rows"]:
        day = str(r["day"])[:10]
        p99 = float(r["p99"] or 0)
        by_day.setdefault(day, []).append({
            "computer": r["computer"], "accounts": r["accounts"], "targets": r["targets"],
            "times_normal": round(r["targets"] / p99, 1) if p99 else None})
    return {"suspects_by_day": {d: s[:MAX_SUSPECTS] for d, s in by_day.items()},
            "sql": out["sql"],
            "stats": dict(out["stats"], seconds=round(time.time() - started, 1))}


if __name__ == "__main__":
    import sys
    out = investigate(sys.argv[1] if len(sys.argv) > 1 else None)
    print(out["headline"], "\n")
    print(out["summary"], "\n")
    for a in out["actions"]:
        print("  -", a)
    print()
    for i, step in enumerate(out["steps"], 1):
        print(f"{i}. {step['title']}: {step['finding']}")
    print("\nstats:", out["stats"], "| accounts:", len(out["accounts"]), "| edges:", len(out["edges"]))
