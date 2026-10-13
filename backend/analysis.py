import json
from backend.llm import ask_json

MAX_ROWS = 30
RISKS = ("low", "medium", "high")

ANALYZE_SYSTEM = """You are a security investigator reviewing Windows authentication logs from a company network.
You get a user's question, the SQL that was run, and the result rows. Investigate, then explain to a non-expert.

Look for:
- Lateral movement: one account reaching many different computers.
- One source computer using many different accounts.
- Logins at unusual hours (for example midnight to 5 AM).
- Bursts of failed logins.

Accounts with a "?" domain (e.g. U1718@?) and accounts that are busy every hour of the day are likely automated or system activity.
Rate them lower risk unless other signs appear. Accounts ending in $ are computer accounts.
Only describe what the rows show.

Fields, in this order:
- "answer": read aloud to a non-expert. Plain English, at most 3 short sentences, under 60 words. No jargon, no SQL.
- "risk": "low", "medium", or "high".
- "next_steps": up to 3 concrete actions, e.g. "Lock account U66@DOM1" or "Check computers C1823 and C2867".
- "findings": up to 4 technical findings, each under 20 words, naming specific accounts, computers, counts, and times.

Keep your reasoning brief. Return ONLY JSON: {"answer": "...", "risk": "...", "next_steps": ["..."], "findings": ["..."]}"""


def _str_list(value, limit: int) -> list:
    if not isinstance(value, list):
        return []
    return [str(v).strip() for v in value if str(v).strip()][:limit]

def analyze(question: str, sql: str, rows: list) -> dict:
    payload = {"question": question, "sql": sql, "rows": rows[:MAX_ROWS]}
    data = ask_json([{"role": "system", "content": ANALYZE_SYSTEM},
                     {"role": "user", "content": json.dumps(payload, default=str)}],
                    tag="analyze", required=("answer", "risk")) or {}

    risk = str(data.get("risk", "")).strip().lower()
    findings = _str_list(data.get("findings"), 10)
    if risk not in RISKS:
        # unknown risk is never reported as "low"
        risk = "medium"
        findings = findings or ["Automatic analysis failed. Review the results manually."]

    answer = data.get("answer")
    if not isinstance(answer, str) or not answer.strip():
        answer = f"I found results with {risk} risk, but could not summarize them. Please review the findings."

    return {"risk": risk, "findings": findings, "answer": answer.strip(),
            "next_steps": _str_list(data.get("next_steps"), 3)}

if __name__ == "__main__":
    from backend.query_agent import answer_with_sql

    q = "Which accounts logged into the most different computers yesterday?"
    result = answer_with_sql(q)
    print("SQL:", result["sql"])

    out = analyze(q, result["sql"], result["rows"])
    print("Risk:", out["risk"])
    print("Findings:")
    for f in out["findings"]:
        print("  -", f)
    print("Answer:", out["answer"])
    print("Next steps:")
    for s in out["next_steps"]:
        print("  -", s)
