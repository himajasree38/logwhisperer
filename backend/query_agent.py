import json
from pathlib import Path
from backend.db import run_sql
from backend.llm import ask_json

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = (ROOT / "prompts" / "schema_notes.md").read_text()

OFF_TOPIC = {"sql": None, "columns": [], "rows": [], "stats": {"rows_scanned": 0, "query_ms": 0}}

SYSTEM = f"""You are a security analyst who writes ClickHouse SQL.
Turn the user's question into ONE ClickHouse SELECT query on table auth_logs.

{SCHEMA}

Rules:
- Return ONLY JSON: {{"sql": "<one SELECT query>"}}
- If the question is not about logins, accounts, computers, or security in these logs, return {{"sql": null}}.
- Never use the is_attack column.
- Always include ORDER BY and LIMIT (max 100).
- Prefer returning user, computers, counts, and timestamps so results can be explained.
- When listing events (individual logins rather than counts), always select timestamp, src_user, src_comp, and dst_comp.

Examples:
Q: Which accounts logged into the most different computers yesterday?
{{"sql": "SELECT src_user, uniqExact(dst_comp) AS computers, count() AS logins FROM auth_logs WHERE src_user LIKE 'U%' AND src_comp != dst_comp GROUP BY src_user ORDER BY computers DESC LIMIT 10"}}

Q: Which computers did U66@DOM1 reach, in order?
{{"sql": "SELECT timestamp, src_user, src_comp, dst_comp, logon_type, result FROM auth_logs WHERE src_user = 'U66@DOM1' AND src_comp != dst_comp ORDER BY timestamp LIMIT 100"}}

Q: Who had the most failed logins?
{{"sql": "SELECT src_user, count() AS failed FROM auth_logs WHERE result = 'Fail' AND src_user LIKE 'U%' GROUP BY src_user ORDER BY failed DESC LIMIT 10"}}

Q: What's a good recipe for pancakes?
{{"sql": null}}
"""

def _ask_model(messages):
    """Return the SQL string, or None if the model said the question is off-topic."""
    data = ask_json(messages, tag="query", required=("sql",))
    if data is None:
        raise ValueError("Model did not return a query.")
    return data["sql"]

def _run(sql):
    return dict(OFF_TOPIC) if sql is None else run_sql(sql)

def answer_with_sql(question: str) -> dict:
    """Run the question as SQL. result["sql"] is None when the question is off-topic."""
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": question}]
    sql = _ask_model(messages)
    try:
        return _run(sql)
    except Exception as e:
        # one retry: show the model its error
        messages += [{"role": "assistant", "content": json.dumps({"sql": sql})},
                     {"role": "user", "content": f"That query failed with: {e}. Fix it and return only JSON."}]
        return _run(_ask_model(messages))

if __name__ == "__main__":
    for q in ["Which accounts logged into the most different computers yesterday?",
              "Which computers did U66@DOM1 reach, in order?",
              "Were there logins at unusual hours, like between midnight and 5 AM?"]:
        print("\nQ:", q)
        out = answer_with_sql(q)
        print("SQL:", out["sql"])
        print("Stats:", out["stats"])
        for row in out["rows"][:5]:
            print("  ", row)
